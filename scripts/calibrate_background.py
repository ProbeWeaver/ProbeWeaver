#!/usr/bin/env python3
"""Fit a background-response profile from control and reward JSONL.

This command is deliberately offline: it never opens sockets.  Control probes
must be collected separately and supplied as JSONL.  Reward logs are streamed
from gzip JSONL files and globally deduplicated on disk.
"""

from __future__ import annotations

import argparse
import gzip
import json
import sqlite3
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional, Sequence, Union

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from core.background_model import (  # noqa: E402
    BackgroundEntry,
    BackgroundProfile,
    BannerEntry,
    adjusted_breadth,
    adjusted_cluster_weights,
    quantile,
    select_gamma,
    service_topology_hash,
)
from core.service_weights import compute_cluster_weights, weight_config_hash  # noqa: E402

def _transport_members() -> Dict[str, list[str]]:
    result = {"tcp": [], "udp": []}
    for member, info in config.SERVICES.items():
        transport = info.get("protocol", "tcp")
        if transport in ("tcp", "both"):
            result["tcp"].append(member)
        if transport in ("udp", "both"):
            result["udp"].append(member)
    return result

def _transport_clusters() -> Dict[str, set[str]]:
    return {
        transport: {config.cluster_of(member) for member in members}
        for transport, members in _transport_members().items()
    }

RewardRoots = Union[Path, Sequence[Path]]

def _reward_event_paths(roots: RewardRoots) -> list[Path]:
    selected = [roots] if isinstance(roots, Path) else list(roots)
    if not selected:
        raise ValueError("at least one reward root is required")
    paths = []
    for root in selected:
        paths.extend([root] if root.is_file()
                     else sorted(root.rglob("*.jsonl.gz")))
    # Resolve duplicate roots/files before reading; deterministic order keeps
    # the SQLite aggregation and provenance independent of CLI order.
    return sorted({path.resolve() for path in paths})

def iter_reward_events(root: RewardRoots) -> Iterator[dict]:
    paths = _reward_event_paths(root)
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid reward JSON {path}:{line_number}: {exc}") from exc
                if isinstance(item, dict):
                    yield item

def deduplicated_reward_events(root: RewardRoots) -> Iterator[dict]:
    """Yield one conservative observation per unique payload.

    Repeated sends are collapsed with set union, represented as compact bit
    masks in SQLite.  Union is intentional here: the background model asks
    whether a payload *can* elicit a service, so a single observed hit is
    sufficient and frequent repeats cannot increase the sample weight.  The
    set of mutation targets and the hits observed under a *different* target
    are retained separately.  This prevents a hit seen only while mutating
    service ``c`` from being attributed to the same payload's observation
    under another target.

    ``payload_triggered_clusters`` is authoritative whenever the key exists,
    including when its value is an empty list.  The legacy
    ``triggered_clusters`` fallback is used only for V1 logs that predate the
    response-phase schema.
    """
    cluster_names = sorted({
        config.cluster_of(member) for member in config.SERVICES
    })
    cluster_index = {cluster: idx for idx, cluster in enumerate(cluster_names)}

    def bit(cluster: str) -> int:
        idx = cluster_index.get(cluster)
        return 0 if idx is None else 1 << idx

    def decode(mask: int) -> list[str]:
        return [
            cluster for idx, cluster in enumerate(cluster_names)
            if mask & (1 << idx)
        ]

    with tempfile.TemporaryDirectory(prefix="background_reward_") as temp_dir:
        db = sqlite3.connect(str(Path(temp_dir) / "events.sqlite3"))
        try:
            db.execute(
                "CREATE TABLE events (transport TEXT, packet_hash TEXT, "
                "target_mask INTEGER NOT NULL, hit_mask INTEGER NOT NULL, "
                "non_target_hit_mask INTEGER NOT NULL, "
                "PRIMARY KEY (transport, packet_hash)) WITHOUT ROWID"
            )
            for event in iter_reward_events(root):
                if event.get("event_type") == "dedup_skip":
                    continue
                transport = str(event.get("transport") or "").lower()
                packet_hash = str(event.get("packet_hash") or "")
                if transport not in ("tcp", "udp") or not packet_hash:
                    continue
                target = config.cluster_of(str(event.get("mutation_target") or ""))
                if "payload_triggered_clusters" in event:
                    triggered = set(event.get("payload_triggered_clusters") or ())
                else:
                    triggered = set(event.get("triggered_clusters") or ())
                target_mask = bit(target)
                hit_mask = 0
                non_target_hit_mask = 0
                for cluster in triggered:
                    normalized = config.cluster_of(str(cluster))
                    hit_mask |= bit(normalized)
                    if normalized != target:
                        non_target_hit_mask |= bit(normalized)
                db.execute(
                    """INSERT INTO events VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(transport, packet_hash) DO UPDATE SET
                         target_mask=(events.target_mask | excluded.target_mask),
                         hit_mask=(events.hit_mask | excluded.hit_mask),
                         non_target_hit_mask=(events.non_target_hit_mask |
                                              excluded.non_target_hit_mask)""",
                    (transport, packet_hash, target_mask, hit_mask,
                     non_target_hit_mask),
                )
            db.commit()
            cursor = db.execute(
                "SELECT transport, packet_hash, target_mask, hit_mask, "
                "non_target_hit_mask "
                "FROM events ORDER BY transport, packet_hash"
            )
            for (transport, packet_hash, target_mask, hit_mask,
                 non_target_hit_mask) in cursor:
                yield {
                    "transport": transport,
                    "packet_hash": packet_hash,
                    "mutation_targets": decode(int(target_mask)),
                    "triggered_clusters": decode(int(hit_mask)),
                    "non_target_triggered_clusters": decode(
                        int(non_target_hit_mask)),
                }
        finally:
            db.close()

def read_controls(path: Path) -> list[dict]:
    controls = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid control JSON {path}:{line_number}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"control record must be an object: {path}:{line_number}")
            controls.append(item)
    if not controls:
        raise ValueError("control input is empty")
    return controls

def fit_profile(
    controls: Sequence[dict],
    reward_root: RewardRoots,
    *,
    objective_version: str,
    eta: float,
    high_rate: float,
    high_mass_max: float,
    gamma_candidates: Sequence[float],
    null_q: float,
    banner_wilson_min: float,
) -> BackgroundProfile:
    members_by_transport = _transport_members()
    clusters_by_transport = _transport_clusters()
    control_hits = defaultdict(lambda: defaultdict(int))
    control_totals = defaultdict(lambda: defaultdict(int))
    banner_hits = defaultdict(lambda: defaultdict(int))
    banner_totals = defaultdict(lambda: defaultdict(int))
    control_payload_sets: Dict[str, list[set[str]]] = defaultdict(list)

    for item in controls:
        transport = str(item.get("transport") or "").lower()
        kind = str(item.get("probe_kind") or "")
        if transport not in clusters_by_transport:
            raise ValueError(f"invalid control transport {transport!r}")
        responses = item.get("responses") or []
        if kind == "connect_only":
            banner_members = {
                str(response.get("service") or "")
                for response in responses
                if response.get("banner_hex")
                or response.get("response_phase") == "pre_payload_banner"
            }
            for member in members_by_transport[transport]:
                banner_totals[transport][member] += 1
                banner_hits[transport][member] += int(member in banner_members)
            continue
        if kind not in ("random", "shuffled", "zero_length"):
            raise ValueError(f"invalid control probe_kind {kind!r}")
        triggered = {
            str(response.get("cluster") or config.cluster_of(
                str(response.get("service") or "")))
            for response in responses
            if response.get("response_phase", "post_payload") == "post_payload"
            and response.get("response_hex")
        }
        control_payload_sets[transport].append(triggered)
        for cluster in clusters_by_transport[transport]:
            control_totals[transport][cluster] += 1
            control_hits[transport][cluster] += int(cluster in triggered)

    round_hits = defaultdict(lambda: defaultdict(int))
    round_totals = defaultdict(lambda: defaultdict(int))
    unique_rewards = 0
    for event in deduplicated_reward_events(reward_root):
        unique_rewards += 1
        transport = str(event.get("transport") or "").lower()
        targets = set(event.get("mutation_targets") or ())
        triggered = set(event.get("non_target_triggered_clusters") or ())
        for cluster in clusters_by_transport.get(transport, set()):
            # A deduplicated payload may have been sent under several targets.
            # It is eligible for c whenever at least one observation was not a
            # c-targeted mutation.  If all observations targeted c, exclude it.
            if targets and targets <= {cluster}:
                continue
            round_totals[transport][cluster] += 1
            round_hits[transport][cluster] += int(cluster in triggered)

    entries: Dict[str, Dict[str, BackgroundEntry]] = {}
    banner_entries: Dict[str, Dict[str, BannerEntry]] = {}
    passive_clusters: Dict[str, list[str]] = {}
    gamma_by_transport: Dict[str, float] = {}
    gamma_met: Dict[str, bool] = {}
    null_thresholds: Dict[str, Dict[str, float]] = {}

    for transport, clusters in clusters_by_transport.items():
        entries[transport] = {
            cluster: BackgroundEntry.build(
                control_hits=control_hits[transport][cluster],
                control_total=control_totals[transport][cluster],
                round1_hits=round_hits[transport][cluster],
                round1_total=round_totals[transport][cluster],
                eta=eta,
            )
            for cluster in sorted(clusters)
        }
        banner_entries[transport] = {
            member: BannerEntry.build(
                banner_hits[transport][member],
                banner_totals[transport][member],
                banner_wilson_min,
            )
            for member in sorted(members_by_transport[transport])
        }
        cluster_members = defaultdict(list)
        for member in members_by_transport[transport]:
            cluster_members[config.cluster_of(member)].append(member)
        passive_clusters[transport] = sorted(
            cluster for cluster, members in cluster_members.items()
            if members and all(banner_entries[transport][m].stable for m in members)
        )
        base = compute_cluster_weights(
            set(clusters),
            prevalence_alpha=float(getattr(
                config, "SERVICE_WEIGHT_PREVALENCE_ALPHA", 0.7)),
        )
        rates = {cluster: entry.mixed_rate for cluster, entry in entries[transport].items()}
        gamma, met = select_gamma(
            base, rates, gamma_candidates, high_rate, high_mass_max)
        gamma_by_transport[transport] = gamma
        gamma_met[transport] = met
        adjusted = adjusted_cluster_weights(base, rates, gamma)
        null_thresholds[transport] = {}
        for target in sorted(clusters):
            values = [
                adjusted_breadth(triggered, target, adjusted)
                for triggered in control_payload_sets.get(transport, ())
            ]
            null_thresholds[transport][target] = quantile(values, null_q)

    reward_roots = ([reward_root] if isinstance(reward_root, Path)
                    else list(reward_root))
    resolved_roots = [str(path.resolve()) for path in reward_roots]
    return BackgroundProfile(
        objective_version=objective_version,
        service_topology_hash=service_topology_hash(config.SERVICES),
        weight_config_hash=weight_config_hash(
            prevalence_alpha=float(config.SERVICE_WEIGHT_PREVALENCE_ALPHA)),
        eta=eta,
        high_rate=high_rate,
        high_mass_max=high_mass_max,
        gamma=gamma_by_transport,
        gamma_target_met=gamma_met,
        null_quantile=null_q,
        entries=entries,
        banner_members=banner_entries,
        passive_clusters=passive_clusters,
        null_thresholds=null_thresholds,
        source_metadata={
            "control_records": len(controls),
            "unique_reward_payloads": unique_rewards,
            "repeat_aggregation": "set_union_per_transport_packet_hash",
            "reward_root": (resolved_roots[0]
                            if len(resolved_roots) == 1 else None),
            "reward_roots": resolved_roots,
        },
    )

def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fit = sub.add_parser("fit")
    fit.add_argument("--controls", required=True, type=Path)
    fit.add_argument(
        "--reward-root", required=True, type=Path, action="append",
        help="reward JSONL file/directory (repeat for TCP and UDP roots)",
    )
    fit.add_argument("--output", "-o", required=True, type=Path)
    fit.add_argument("--objective-version", default="background_adjusted_breadth")
    fit.add_argument("--eta", type=float, default=config.BACKGROUND_MIX_ETA)
    fit.add_argument("--high-rate", type=float, default=config.BACKGROUND_HIGH_RATE)
    fit.add_argument("--high-mass-max", type=float, default=config.BACKGROUND_HIGH_MASS_MAX)
    fit.add_argument("--null-quantile", type=float, default=config.BACKGROUND_NULL_QUANTILE)
    fit.add_argument("--banner-wilson-min", type=float,
                     default=config.PASSIVE_BANNER_WILSON_MIN)
    return parser.parse_args(argv)

def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "fit":
        universe = None
        profile = fit_profile(
            read_controls(args.controls),
            args.reward_root,
            objective_version=args.objective_version,
            eta=args.eta,
            high_rate=args.high_rate,
            high_mass_max=args.high_mass_max,
            gamma_candidates=config.BACKGROUND_GAMMA_CANDIDATES,
            null_q=args.null_quantile,
            banner_wilson_min=args.banner_wilson_min,
        )
        profile.save(str(args.output))
        print(json.dumps({
            "output": str(args.output.resolve()),
            "artifact_hash": profile.artifact_hash,
            "gamma": profile.gamma,
            "passive_clusters": profile.passive_clusters,
            "e1_training_universe_hash": (
                universe["artifact_hash"] if universe else None),
        }, ensure_ascii=False))
        return 0
    raise AssertionError(args.command)

if __name__ == "__main__":
    raise SystemExit(main())
