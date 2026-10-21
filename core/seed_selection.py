"""Deterministic offline seed selection for the background-adjusted search objective.

Pure, side-effect-free functions only: they consume flat candidate dicts
(produced upstream from the candidate stream) and return the next-round seed
set.  Everything is transport-stratified and order-independent -- the output
depends only on the *set* of input candidates, never on their order.

Selection semantics (per transport, budgets are independent):
  1. rank: higher ``target_stability``, higher ``adjusted_breadth``, more
     selective extra clusters, shorter packet, then ``packet_hash`` ascending;
  2. force an injective target-to-payload assignment for mandatory
     ``low_reach_target`` values (one distinct payload per target whenever a
     feasible assignment exists);
  3. deduplicate the remaining pool by ``(transport, packet_hash)`` keeping
     the best-ranked representative;
  4. fill the remaining slots greedily by marginal coverage of
     ``(mutation_target, selective_extra_cluster)`` pairs, tie-breaking with
     the same deterministic rank;
  5. ``verified_services`` = ``payload_or_legacy_triggered_clusters`` minus
     the explicitly supplied passive clusters for that transport.

Output provenance is always ``legacy_unknown`` (current selection reads legacy
candidate streams whose response phase is unknown), and
``mutation_target`` / ``packet_hex`` / ``packet_hash`` are preserved verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

PROVENANCE_LEGACY_UNKNOWN = "legacy_unknown"

DEFAULT_TRANSPORT_BUDGETS: Dict[str, int] = {"tcp": 16, "udp": 8}

_REQUIRED_KEYS = (
    "transport",
    "mutation_target",
    "packet_hex",
    "packet_hash",
    "adjusted_breadth",
    "selective_extra_clusters",
    "payload_or_legacy_triggered_clusters",
    "target_stability",
    "target_reached",
)

# ---------------------------------------------------------------------------
# Accessors
# ---------------------------------------------------------------------------

def _validate_candidate(candidate: Mapping[str, object]) -> None:
    missing = [key for key in _REQUIRED_KEYS if candidate.get(key) is None]
    if missing:
        raise ValueError("candidate missing required keys: " + repr(missing))

def packet_length(candidate: Mapping[str, object]) -> int:
    """Packet size in bytes, derived from ``packet_hex``."""
    return len(str(candidate.get("packet_hex", ""))) // 2

def _string_set(candidate: Mapping[str, object], key: str) -> FrozenSet[str]:
    return frozenset(str(item) for item in (candidate.get(key) or ()))

def verified_services(
    candidate: Mapping[str, object],
    passive_clusters: Optional[Iterable[str]] = None,
) -> Tuple[str, ...]:
    """Triggered clusters minus explicitly supplied passive clusters."""
    triggered = _string_set(candidate, "payload_or_legacy_triggered_clusters")
    return tuple(sorted(triggered - frozenset(passive_clusters or ())))

def coverage_pairs(candidate: Mapping[str, object]) -> FrozenSet[Tuple[str, str]]:
    """``(mutation_target, selective_extra_cluster)`` pairs covered by a packet."""
    target = str(candidate.get("mutation_target", ""))
    return frozenset(
        (target, cluster)
        for cluster in _string_set(candidate, "selective_extra_clusters")
    )

def rank_key(candidate: Mapping[str, object]) -> Tuple[float, float, int, int, str]:
    """Deterministic sort key; smaller is better.

    Order: higher ``target_stability``, higher ``adjusted_breadth``, more
    selective extra clusters, shorter packet, then ``packet_hash`` ascending
    as the final stable tie-breaker.
    """
    return (
        -float(candidate.get("target_stability") or 0.0),
        -float(candidate.get("adjusted_breadth") or 0.0),
        -len(_string_set(candidate, "selective_extra_clusters")),
        packet_length(candidate),
        str(candidate.get("packet_hash", "")),
    )

# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_candidates(
    candidates: Iterable[Mapping[str, object]],
) -> List[Mapping[str, object]]:
    """Keep one best-ranked representative per ``(transport, packet_hash)``.

    Returns the survivors sorted by rank (best first), so downstream stages
    are independent of input order.
    """
    best: Dict[Tuple[str, str], Mapping[str, object]] = {}
    for candidate in candidates:
        _validate_candidate(candidate)
        key = (str(candidate.get("transport", "")), str(candidate.get("packet_hash", "")))
        current = best.get(key)
        if current is None or rank_key(candidate) < rank_key(current):
            best[key] = candidate
    return sorted(best.values(), key=rank_key)

def _mandatory_assignment(
    pool: Sequence[Mapping[str, object]],
    targets: Sequence[str],
) -> Dict[str, Mapping[str, object]]:
    """Find a deterministic injective target→payload assignment.

    A global payload dedup performed before this step can erase the only
    representative for a strict target when the same bytes were also emitted
    under another mutation target.  This is a small bipartite matching
    problem: targets are left vertices, packet hashes are right vertices, and
    rank-ordered reachable candidates are edges.  The augmenting-path solver
    guarantees a full assignment whenever one exists.
    """
    options: Dict[str, List[Mapping[str, object]]] = {}
    for target in targets:
        best_by_hash: Dict[str, Mapping[str, object]] = {}
        for candidate in pool:
            if str(candidate.get("mutation_target", "")) != target:
                continue
            digest = str(candidate.get("packet_hash", ""))
            current = best_by_hash.get(digest)
            if current is None or rank_key(candidate) < rank_key(current):
                best_by_hash[digest] = candidate
        options[target] = sorted(best_by_hash.values(), key=rank_key)
        if not options[target]:
            raise ValueError(
                "no target-reachable candidate for mandatory target " + repr(target)
            )

    owner_by_hash: Dict[str, str] = {}
    candidate_by_target: Dict[str, Mapping[str, object]] = {}

    def augment(target: str, seen_hashes: set[str]) -> bool:
        for candidate in options[target]:
            digest = str(candidate.get("packet_hash", ""))
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            owner = owner_by_hash.get(digest)
            if owner is None or augment(owner, seen_hashes):
                owner_by_hash[digest] = target
                candidate_by_target[target] = candidate
                return True
        return False

    # Most-constrained targets first reduces displacement work; the matching
    # remains deterministic through target and rank tie-breakers.
    order = sorted(targets, key=lambda target: (len(options[target]), target))
    for target in order:
        if not augment(target, set()):
            raise ValueError(
                "mandatory low-reach targets have no distinct-payload assignment"
            )
    return candidate_by_target

# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SeedSelection:
    """Selected next-round seeds plus per-transport accounting."""

    selected: List[Dict[str, object]] = field(default_factory=list)
    per_transport: Dict[str, int] = field(default_factory=dict)
    covered_pairs: Dict[str, FrozenSet[Tuple[str, str]]] = field(default_factory=dict)
    skipped_transports: Tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.selected)

def _output_record(
    candidate: Mapping[str, object],
    passive_clusters_for_transport: FrozenSet[str],
    reason: str,
) -> Dict[str, object]:
    """Public seed record: preserved identifiers + verified clusters."""
    return {
        "transport": str(candidate.get("transport", "")),
        "mutation_target": str(candidate.get("mutation_target", "")),
        "packet_hex": str(candidate.get("packet_hex", "")),
        "packet_hash": str(candidate.get("packet_hash", "")),
        "selective_extra_clusters": sorted(
            _string_set(candidate, "selective_extra_clusters")
        ),
        "verified_services": verified_services(
            candidate, passive_clusters_for_transport
        ),
        "adjusted_breadth": float(candidate.get("adjusted_breadth") or 0.0),
        "target_stability": float(candidate.get("target_stability") or 0.0),
        "target_reached": bool(candidate.get("target_reached")),
        "selection_reason": reason,
        "provenance": PROVENANCE_LEGACY_UNKNOWN,
    }

def select_seeds(
    candidates: Iterable[Mapping[str, object]],
    *,
    transport_budgets: Mapping[str, int] = DEFAULT_TRANSPORT_BUDGETS,
    low_reach_targets: Optional[Mapping[str, Sequence[str]]] = None,
    passive_clusters: Optional[Mapping[str, Sequence[str]]] = None,
) -> SeedSelection:
    """Select the deterministic next-round seed set.

    - ``transport_budgets``: independent per-transport limits (tcp=16/udp=8 by
      default); candidates on transports without a budget are skipped.
    - ``low_reach_targets``: per-transport mandatory targets; one best
      target-reachable candidate is forced for each.  Raises ``ValueError``
      when the mandatory targets exceed the transport budget, or when a
      mandatory target has no reachable candidate at all.
    - ``passive_clusters``: per-transport clusters removed from
      ``payload_or_legacy_triggered_clusters`` when computing
      ``verified_services``.
    """
    budgets = {str(t): int(n) for t, n in transport_budgets.items() if int(n) >= 0}
    targets_by_transport: Dict[str, FrozenSet[str]] = {
        str(transport): frozenset(str(t) for t in targets)
        for transport, targets in (low_reach_targets or {}).items()
    }
    passive_by_transport: Dict[str, FrozenSet[str]] = {
        str(transport): frozenset(str(c) for c in clusters)
        for transport, clusters in (passive_clusters or {}).items()
    }

    validated = []
    for candidate in candidates:
        _validate_candidate(candidate)
        validated.append(candidate)
    by_transport: Dict[str, List[Mapping[str, object]]] = {}
    skipped: Dict[str, int] = {}
    for candidate in validated:
        transport = str(candidate.get("transport", ""))
        if transport not in budgets:
            skipped[transport] = skipped.get(transport, 0) + 1
            continue
        # A seed must retain target reachability.  Diagnostic-only legacy
        # payloads are useful for background estimation, never for seed fill.
        if not bool(candidate.get("target_reached")):
            continue
        by_transport.setdefault(transport, []).append(candidate)

    selected: List[Dict[str, object]] = []
    counts: Dict[str, int] = {}
    covered: Dict[str, FrozenSet[Tuple[str, str]]] = {}
    for transport in sorted(budgets):
        budget = budgets[transport]
        pool = by_transport.get(transport, [])
        passive = passive_by_transport.get(transport, frozenset())
        mandatory = tuple(sorted(targets_by_transport.get(transport, frozenset())))
        if len(mandatory) > budget:
            raise ValueError(
                "transport " + repr(transport) + ": " + str(len(mandatory))
                + " mandatory low-reach targets exceed the budget of "
                + str(budget)
            )

        chosen: List[Tuple[Mapping[str, object], str]] = []
        used_keys = set()
        covered_pairs: FrozenSet[Tuple[str, str]] = frozenset()

        # Phase 1 -- distinct target-reachable representative per mandatory
        # target.  Matching precedes global payload dedup so a cross-target
        # duplicate cannot erase a strict target's only viable seed.
        try:
            mandatory_by_target = _mandatory_assignment(pool, mandatory)
        except ValueError as exc:
            raise ValueError("transport " + repr(transport) + ": " + str(exc)) from exc
        for target in mandatory:
            best = mandatory_by_target[target]
            key = (str(best.get("transport", "")), str(best.get("packet_hash", "")))
            used_keys.add(key)
            chosen.append((best, "mandatory_target"))
            covered_pairs |= coverage_pairs(best)

        # Phase 2 -- greedy marginal pair coverage for the remaining slots.
        greedy_pool = deduplicate_candidates(pool)
        remaining = budget - len(used_keys)
        while remaining > 0:
            best: Optional[Mapping[str, object]] = None
            best_key: Optional[Tuple[str, str]] = None
            best_marginal = -1
            for candidate in greedy_pool:
                key = (str(candidate.get("transport", "")),
                       str(candidate.get("packet_hash", "")))
                if key in used_keys:
                    continue
                marginal = len(coverage_pairs(candidate) - covered_pairs)
                if (
                    best is None
                    or marginal > best_marginal
                    or (marginal == best_marginal
                        and rank_key(candidate) < rank_key(best))
                ):
                    best, best_key, best_marginal = candidate, key, marginal
            if best is None or best_key is None or best_marginal <= 0:
                break
            used_keys.add(best_key)
            chosen.append((best, "greedy_coverage"))
            covered_pairs |= coverage_pairs(best)
            remaining -= 1

        for candidate, reason in chosen:
            selected.append(_output_record(candidate, passive, reason))
        counts[transport] = len(chosen)
        covered[transport] = covered_pairs

    return SeedSelection(
        selected=selected,
        per_transport=counts,
        covered_pairs=covered,
        skipped_transports=tuple(sorted(skipped)),
    )
