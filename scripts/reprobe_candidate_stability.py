"""Re-probe stored multi-probe candidates exactly 3 times for network stability.

Collect network stability facts (no
``validated_exploratory`` claim is made or implied by this tool).

Inputs are one or more public JSON arrays (nested fingerprint schema) and/or
authoritative gzip JSONL candidate streams (flat candidate-stream schema).
Only ``multi_probe`` and ``exploratory_multi_probe`` candidates are selected;
every other candidate type is skipped and reported.  Exact duplicate
candidate identities are deduplicated and reported (same probe).  A selected
record that is legacy phase-unknown (strict mode) or structurally invalid
(any mode, including ``--allow-legacy``) makes the run fail fast with
``CandidateStabilityError`` **before** any ServiceTester is built or any
output is written — partial artifacts are never silently produced.  Each
selected candidate is re-probed **exactly three times** against the current
SERVICES fleet, routed by the record's own transport: members with protocol
``both`` are explicitly rewritten to the record transport in both directions
(tcp → "tcp", udp → "udp"), never passed through as "both".  The resulting
network-stability artifact is written atomically (``.tmp`` + ``os.replace``).

No multiprocessing is used: correctness and bounded memory matter more here
than raw throughput.  ``ServiceTester`` is instantiated only in this CLI
execution path (lazily, one per transport); all evaluation logic lives in
``core/candidate_stability.py`` and stays pure/injectable for tests.

Example:
  mamba run -n protocol_fuzzer python scripts/reprobe_candidate_stability.py \\
      --input candidates.json stream_dir/task_tcp.jsonl.gz \\
      --output outputs/stability.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Tuple

# Limit glibc malloc arena for this CLI process (consistent with other tools)
os.environ.setdefault("MALLOC_ARENA_MAX", "8")

# Make repo root importable when invoked as `python scripts/reprobe_...py`
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config  # noqa: E402
from config import SERVICES  # noqa: E402
from core.background_model import service_topology_hash  # noqa: E402
from core.candidate_stability import (  # noqa: E402
    STABILITY_REPETITIONS,
    SUPPORTED_CANDIDATE_TYPES,
    CandidateStabilityError,
    LegacyPhaseUnknownError,
    build_stability_artifact,
    candidate_identity_digest,
    load_stability_artifact,
    parse_candidate_record,
    write_stability_artifact,
)
from core.candidate_stream import iter_candidate_stream  # noqa: E402
from core.service_tester import ServiceTester  # noqa: E402

logger = logging.getLogger("reprobe_candidate_stability")

# JSON arrays above this size are streamed with ijson when available; smaller
# files (and any environment without ijson) use the plain json fallback.
_IJSON_SIZE_THRESHOLD = 8 * 1024 * 1024

try:  # optional streaming dependency
    import ijson  # type: ignore
except ImportError:  # pragma: no cover - environment dependent
    ijson = None


# ---------------------------------------------------------------------------
# Input loading (streaming where practical)
# ---------------------------------------------------------------------------

def iter_input_records(paths: Sequence[str]) -> Iterator[dict]:
    """Yield candidate records from JSON arrays and/or ``.jsonl.gz`` streams.

    ``.jsonl.gz`` / ``.gz`` paths are treated as authoritative candidate
    streams (streamed line by line).  Everything else must be a public JSON
    array: large files stream via ijson when installed, small files use the
    plain json fallback (which tests also exercise).
    """
    for path in paths:
        suffix = Path(path).suffix.lower()
        if suffix in (".gz",):
            n = 0
            for record in iter_candidate_stream(path):
                yield record
                n += 1
            logger.info("loaded %d records from candidate stream %s", n, path)
            continue
        size = os.path.getsize(path)
        if ijson is not None and size > _IJSON_SIZE_THRESHOLD:
            n = 0
            with open(path, "rb") as handle:
                for record in ijson.items(handle, "item"):
                    yield record
                    n += 1
            logger.info("streamed %d records (ijson) from %s", n, path)
            continue
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            raise CandidateStabilityError(
                f"input {path} is not a JSON array of candidate records")
        for record in data:
            yield record
        logger.info("loaded %d records (json fallback) from %s",
                    len(data), path)


# ---------------------------------------------------------------------------
# Service routing (transport of the record decides the fleet subset)
# ---------------------------------------------------------------------------

def load_services_for_transport(transport: str) -> Dict[str, Tuple]:
    """SERVICES subset for one transport, reprobe_fingerprints semantics.

    tcp → members with protocol in {tcp, both}; udp → members with protocol
    in {udp, both}.  A ``both`` member is **explicitly rewritten** to the
    current record transport in BOTH directions (tcp → "tcp", udp → "udp"):
    routing must never rely on ServiceTester's fallback of dispatching every
    unknown/non-udp transport to TCP.
    """
    if transport not in ("tcp", "udp"):
        raise ValueError(f"transport must be tcp/udp, got {transport!r}")
    out: Dict[str, Tuple] = {}
    for name, info in SERVICES.items():
        member_transport = info.get("protocol", "tcp")
        if member_transport == "both":
            member_transport = transport
        elif member_transport != transport:
            continue
        out[name] = (info["host"], info["port"], member_transport)
    return out


def build_probe_fn(
    timeout: float,
    banner_timeout: float,
) -> Tuple[Callable[[dict, int], object], Dict[str, ServiceTester]]:
    """Lazily instantiate one ServiceTester per transport and return a
    ``probe_fn(record, repetition_index)`` routing each record by its own
    transport.  ServiceTester instances are created only here (CLI path)."""
    testers: Dict[str, ServiceTester] = {}

    def tester_for(transport: str) -> ServiceTester:
        if transport not in testers:
            services = load_services_for_transport(transport)
            if not services:
                raise CandidateStabilityError(
                    f"no SERVICES available for transport {transport!r}")
            testers[transport] = ServiceTester(
                services, timeout=timeout, banner_timeout=banner_timeout)
            logger.info("ServiceTester[%s]: %d members (timeout=%.3fs, "
                        "banner=%.3fs)", transport, len(services),
                        timeout, banner_timeout)
        return testers[transport]

    def probe_fn(record: dict, repetition_index: int):
        packet = bytes.fromhex(record["packet_hex"])
        return tester_for(str(record.get("transport", ""))).test_packet(packet)

    return probe_fn, testers


# ---------------------------------------------------------------------------
# Candidate selection / filtering
# ---------------------------------------------------------------------------

class SelectionReport:
    """Explicit accounting of what was kept, skipped, or rejected and why."""

    def __init__(self) -> None:
        self.selected = 0
        self.skipped_types: Counter = Counter()
        self.duplicate_identity = 0
        self.rejected_legacy_phase = 0
        self.rejected_invalid: List[str] = []

    def summary(self) -> str:
        skipped = " ".join(
            f"{ctype}={count}"
            for ctype, count in sorted(self.skipped_types.items())
        ) or "none"
        return (
            f"selected={self.selected} "
            f"skipped_candidate_types[{skipped}] "
            f"duplicate_identity={self.duplicate_identity} "
            f"rejected_legacy_phase={self.rejected_legacy_phase} "
            f"rejected_invalid={len(self.rejected_invalid)}"
        )


def select_candidates(
    records: Iterator[dict],
    *,
    strict_phase_aware: bool,
    allow_unobserved_challenge: bool = False,
    limit: int = 0,
    report: Optional[SelectionReport] = None,
) -> List[dict]:
    """Filter to multi_probe/exploratory_multi_probe, dedupe identity.

    Intentionally skipped and reported:
      - unsupported candidate types (out of stability scope);
      - exact duplicate candidate identities (same probe — each unique
        candidate must be probed exactly 3 times, not 6).

    Selected records that are legacy phase-unknown (strict mode only) or
    structurally invalid (any mode, including ``--allow-legacy``) are **not**
    skipped: silently dropping them would produce a partial artifact that
    under-reports stability facts.  Selection therefore fails fast with
    :class:`LegacyPhaseUnknownError` / :class:`CandidateStabilityError`
    carrying the selection report, before any network tester is built or any
    output is written (the call site runs selection first).
    """
    report = report or SelectionReport()
    selected: List[dict] = []
    seen: set = set()
    for record in records:
        if not isinstance(record, dict):
            report.rejected_invalid.append(f"non-dict record: {type(record)}")
            continue
        candidate_type = str(
            record.get("candidate_type") or "multi_probe")
        if candidate_type not in SUPPORTED_CANDIDATE_TYPES:
            report.skipped_types[candidate_type] += 1
            continue
        try:
            parse_candidate_record(
                record, strict_phase_aware=strict_phase_aware,
                allow_unobserved_challenge=allow_unobserved_challenge)
        except LegacyPhaseUnknownError as exc:
            report.rejected_legacy_phase += 1
            logger.debug("legacy phase-unknown selected record: %s", exc)
            continue  # collected; raised below, before any probing
        except CandidateStabilityError as exc:
            report.rejected_invalid.append(str(exc))
            logger.debug("invalid selected record: %s", exc)
            continue  # collected; raised below, before any probing
        digest = candidate_identity_digest(record)
        if digest in seen:
            report.duplicate_identity += 1
            continue
        seen.add(digest)
        selected.append(record)
        if limit > 0 and len(selected) >= limit:
            break
    report.selected = len(selected)
    if report.rejected_invalid:
        reasons = "; ".join(report.rejected_invalid[:3])
        extra = len(report.rejected_invalid) - 3
        suffix = f" (+{extra} more)" if extra > 0 else ""
        raise CandidateStabilityError(
            f"structurally invalid selected candidate records must not yield "
            f"a partial artifact: {reasons}{suffix}; selection report: "
            f"{report.summary()}")
    if report.rejected_legacy_phase and strict_phase_aware:
        raise LegacyPhaseUnknownError(
            f"{report.rejected_legacy_phase} legacy phase-unknown selected "
            f"record(s) rejected in strict phase-aware mode; a partial "
            f"artifact is not permitted — rerun with --allow-legacy to admit "
            f"them explicitly; selection report: {report.summary()}")
    return selected


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    report = SelectionReport()
    records = iter_input_records(args.input)
    # Selection runs first and fails fast (CandidateStabilityError /
    # LegacyPhaseUnknownError carrying the selection report) on legacy or
    # structurally invalid selected records, so a partial artifact can never
    # be produced and no ServiceTester is ever built for such inputs.
    selected = select_candidates(
        records,
        strict_phase_aware=not args.allow_legacy,
        allow_unobserved_challenge=getattr(
            args, "allow_unobserved_challenge", False),
        limit=args.limit,
        report=report,
    )
    logger.info("candidate selection: %s", report.summary())
    if report.skipped_types:
        logger.info("skipped candidate types (out of stability scope): %s",
                    dict(report.skipped_types))
    if report.duplicate_identity:
        logger.info(
            "deduplicated %d exact duplicate candidate identities (same "
            "probe, probed once)", report.duplicate_identity)
    if not selected:
        logger.error("no selectable candidates; nothing to probe")
        return 1

    probe_fn, testers = build_probe_fn(args.timeout, args.banner_timeout)
    artifact = build_stability_artifact(
        selected,
        probe_fn,
        service_topology_hash=service_topology_hash(SERVICES),
        response_phase_schema_version=int(getattr(
            config, "RESPONSE_PHASE_SCHEMA_VERSION", 2)),
        strict_phase_aware=not args.allow_legacy,
        allow_unobserved_challenge=getattr(
            args, "allow_unobserved_challenge", False),
        repetitions=STABILITY_REPETITIONS,
    )

    output = write_stability_artifact(artifact, args.output)
    logger.info(
        "wrote stability artifact: %s (schema=%d repetitions=%d "
        "candidates=%d artifact_hash=%s)",
        output, artifact["schema_version"], artifact["repetitions"],
        len(artifact["candidate_results"]), artifact["artifact_hash"])
    # Immediate round-trip validation: fail loudly rather than ship a
    # self-inconsistent artifact.
    load_stability_artifact(output)
    stable = sum(
        1 for result in artifact["candidate_results"]
        if result["network_stable"])
    logger.info(
        "network_stable candidates: %d/%d (target stable: %d/%d)",
        stable, len(artifact["candidate_results"]),
        sum(1 for r in artifact["candidate_results"] if r["target_stable"]),
        len(artifact["candidate_results"]))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Re-probe stored multi_probe / exploratory_multi_probe "
                    "candidates exactly 3 times and record network stability "
                    "facts (no validated claim).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  mamba run -n protocol_fuzzer python scripts/reprobe_candidate_stability.py \\
      --input candidates.json task_tcp.jsonl.gz \\
      --output stability/candidate_stability.json
""",
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True,
        help="One or more nested JSON arrays or authoritative compressed candidate streams")
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output artifact path; atomically replaced after writing")
    parser.add_argument(
        "--timeout", type=float, default=0.1,
        help="Per-service timeout in seconds (default: 0.1)")
    parser.add_argument(
        "--banner-timeout", type=float, default=0.03,
        help="TCP banner timeout in seconds (default: 0.03)")
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Process the first N eligible candidates (0 = all)")
    parser.add_argument(
        "--allow-legacy", action="store_true",
        help="Explicitly admit legacy candidates with unknown phases; strict "
             "phase-aware mode rejects observations without response_phase")
    parser.add_argument(
        "--allow-unobserved-challenge", action="store_true",
        help="For fresh validation: admit qualification_status=fresh_rule_validation_challenge, "
             "responses=[] and complete parent lineage; ordinary candidate gates are unchanged")
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return run(args)
    except CandidateStabilityError as exc:
        logger.error("candidate stability failed: %s", exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
