#!/usr/bin/env python3
"""Stream transport-specific co-response statistics, fit shrinkage calibration and evaluate frozen priors. Do not interpret conditional co-response as causal mutation direction."""

from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.util
import json
import logging
import math
import os
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

try:
    import ijson
except ImportError:  
    sys.stderr.write(
        "error: ijson is required for streaming calibration (input files can be "
        "8GB+; whole-file json.load fallback is forbidden by design).\n"
        "Install it with: mamba install -n protocol_fuzzer ijson  "
        "(also declared in environment.yaml)\n"
    )
    raise SystemExit(2)

import config  # noqa: E402
from core.compatibility_calibration import (  # noqa: E402
    DEFAULT_PRIOR_STRENGTH,
    DEFAULT_SMOOTHING,
    FACTS_EMPTY,
    FACTS_OK,
    FACTS_SKIP_SCHEMA,
    FACTS_SKIP_TRANSPORT,
    NEUTRAL_Q,
    PairCoResponseStats,
    HeuristicCompatScores,
    atomic_write_json,
    build_calibration_artifact,
    extract_packet_facts,
    observational_conditional,
    shrinkage_posterior,
)
from protocol.field import UnifiedProtocolSpec  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("calibrate_compatibility")

# ============================================================================

# ============================================================================

def stream_facts(paths: List[str]):
    """Stream packet facts and maintain per-input accounting."""
    for path in paths:
        per_file = {
            "path": os.path.abspath(path),
            "records": 0,
            "used": 0,
            "empty_trigger": 0,
            FACTS_SKIP_TRANSPORT: 0,
            FACTS_SKIP_SCHEMA: 0,
            "nested_records": 0,
            "flat_records": 0,
        }
        try:
            st = os.stat(path)
            per_file["size_bytes"] = st.st_size
            per_file["mtime"] = datetime.fromtimestamp(
                st.st_mtime, timezone.utc).isoformat()
        except OSError:
            pass   
        t0 = time.time()
        with open(path, "rb") as fh:
            for record in ijson.items(fh, "item"):
                per_file["records"] += 1
                if not isinstance(record, dict):
                    per_file[FACTS_SKIP_SCHEMA] += 1
                    continue
                facts = extract_packet_facts(record)
                if facts.status == FACTS_SKIP_TRANSPORT:
                    per_file[FACTS_SKIP_TRANSPORT] += 1
                elif facts.status == FACTS_SKIP_SCHEMA:
                    per_file[FACTS_SKIP_SCHEMA] += 1
                else:
                    if facts.status == FACTS_EMPTY:
                        per_file["empty_trigger"] += 1
                    per_file["used"] += 1

                    responses = record.get("responses") or []
                    if responses and isinstance(responses[0], dict) \
                            and "responses" in responses[0]:
                        per_file["nested_records"] += 1
                    elif responses:
                        per_file["flat_records"] += 1
                yield facts, per_file
        per_file["elapsed_s"] = round(time.time() - t0, 1)
        logger.info("[fit] scanned %s: %s", path, json.dumps(per_file))

def accumulate_stats(paths: List[str]) -> Tuple[Dict[str, PairCoResponseStats], Dict]:
    """Accumulate transport statistics in one bounded-memory pass."""
    stats: Dict[str, PairCoResponseStats] = defaultdict(PairCoResponseStats)
    files_meta: List[Dict] = []
    current: Optional[Dict] = None
    for facts, per_file in stream_facts(paths):
        if current is None or current["path"] != per_file["path"]:
            if current is not None:
                files_meta.append(current)
            current = per_file
        if facts.status in (FACTS_OK, FACTS_EMPTY):
            stats[facts.transport].observe(facts.clusters)
    if current is not None:
        files_meta.append(current)
    totals = {
        "files": len(paths),
        "records": sum(f["records"] for f in files_meta),
        "used": sum(f["used"] for f in files_meta),
        "empty_trigger": sum(f["empty_trigger"] for f in files_meta),
        FACTS_SKIP_TRANSPORT: sum(f[FACTS_SKIP_TRANSPORT] for f in files_meta),
        FACTS_SKIP_SCHEMA: sum(f[FACTS_SKIP_SCHEMA] for f in files_meta),
    }
    metadata = {"files": files_meta, "totals": totals}
    return dict(stats), metadata

# ============================================================================

# ============================================================================

def load_specs(specs_dir: str) -> Dict[str, UnifiedProtocolSpec]:
    specs: Dict[str, UnifiedProtocolSpec] = {}
    for spec_file in sorted(glob.glob(os.path.join(specs_dir, "*.py"))):
        basename = os.path.basename(spec_file)
        if basename == "__init__.py":
            continue
        module_name = basename[:-3]
        try:
            loader_spec = importlib.util.spec_from_file_location(
                f"calib_specs_{module_name}", spec_file)
            if loader_spec is None or loader_spec.loader is None:
                continue
            module = importlib.util.module_from_spec(loader_spec)
            loader_spec.loader.exec_module(module)
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type)
                        and issubclass(attr, UnifiedProtocolSpec)
                        and attr is not UnifiedProtocolSpec):
                    spec = attr()
                    specs[spec.name] = spec
                    break
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to load spec %s: %s", spec_file, exc)
    return specs

# ============================================================================

# ============================================================================

def _validate_common_args(args: argparse.Namespace) -> Optional[str]:
    """Validate shared fitting/evaluation arguments."""
    if not args.prior_strength > 0:
        return f"--prior-strength must be > 0, got {args.prior_strength!r}"
    if not 0.0 <= args.neutral_q <= 1.0:
        return f"--neutral-q must be in [0,1], got {args.neutral_q!r}"
    a, b = args.smoothing_a, args.smoothing_b
    if a < 0 or b < 0 or a + b <= 0:
        return (f"--smoothing-a/-b must satisfy a>=0, b>=0, a+b>0, "
                f"got ({a!r}, {b!r})")
    return None

def _validate_evaluate_args(args: argparse.Namespace) -> Optional[str]:
    err = _validate_common_args(args)
    if err:
        return err
    if not 0.0 < args.test_ratio < 1.0:
        return (f"--test-ratio must be in (0,1) exclusive, "
                f"got {args.test_ratio!r}")
    return None

# ============================================================================
# fit
# ============================================================================

def cmd_fit(args: argparse.Namespace) -> int:
    err = _validate_common_args(args)
    if err:
        logger.error("[fit] %s", err)
        return 2
    specs = load_specs(args.specs_dir)
    logger.info("[fit] loaded %d specs from %s", len(specs), args.specs_dir)

    stats, metadata = accumulate_stats(args.inputs)
    if not stats:
        logger.error("[fit] no usable records (all skipped?) — refusing to "
                     "write an empty artifact")
        return 2
    transports = sorted(t for t in stats if t in ("tcp", "udp"))
    other = sorted(t for t in stats if t not in ("tcp", "udp"))
    if other:
        logger.warning("[fit] unexpected transport keys ignored: %s", other)
    selected = {t: stats[t] for t in transports}
    if not selected:
        logger.error("[fit] no tcp/udp-stratified records found — refusing to "
                     "write an unstratified artifact")
        return 2

    artifact = build_calibration_artifact(
        selected,
        specs,
        prior_strength=args.prior_strength,
        smoothing=(args.smoothing_a, args.smoothing_b),
        neutral_q=args.neutral_q,
        source_metadata={
            "generator": "scripts/calibrate_compatibility.py fit",
            **metadata,
        },
        include_aggregate=True,
        objective_version=args.objective_version,
    )
    atomic_write_json(args.output, artifact)
    universe = artifact["cluster_universe"]
    logger.info(
        "[fit] artifact written: %s (universe=%d clusters, transports=%s, "
        "prior_strength=%.1f, smoothing=(%s,%s), heuristic specs=%d, "
        "objective_version=%s)",
        args.output, len(universe), transports,
        args.prior_strength, args.smoothing_a, args.smoothing_b, len(specs),
        artifact.get("objective_version"),
    )
    logger.info("[fit] totals: %s", json.dumps(metadata["totals"]))
    return 0

# ============================================================================

# ============================================================================

def _packet_bucket(packet_hex: str) -> int:
    return int(hashlib.sha256(packet_hex.encode("utf-8")).hexdigest()[:8], 16) % 10_000

def _iter_usable_records(path: str) -> Iterator[Tuple[str, frozenset, str]]:
    """Yield valid transport, service-set and packet-hex triples."""
    with open(path, "rb") as fh:
        for record in ijson.items(fh, "item"):
            if not isinstance(record, dict):
                continue
            packet_hex = record.get("packet_hex")
            if not packet_hex:
                continue
            facts = extract_packet_facts(record)
            if facts.status in (FACTS_OK, FACTS_EMPTY):
                yield facts.transport, facts.clusters, packet_hex

def cmd_evaluate(args: argparse.Namespace) -> int:
    err = _validate_evaluate_args(args)
    if err:
        logger.error("[evaluate] %s", err)
        return 2
    specs = load_specs(args.specs_dir)
    scorer = HeuristicCompatScores(specs, neutral_q=args.neutral_q)
    smoothing = (args.smoothing_a, args.smoothing_b)
    threshold = int(args.test_ratio * 10_000)

    train_stats: Dict[str, PairCoResponseStats] = defaultdict(PairCoResponseStats)
    n_train_by_transport: Counter = Counter()
    n_test_by_transport: Counter = Counter()
    n_usable = 0
    for transport, clusters, packet_hex in _iter_usable_records(args.input):
        n_usable += 1
        if _packet_bucket(packet_hex) < threshold:
            n_test_by_transport[transport] += 1
        else:
            n_train_by_transport[transport] += 1
            train_stats[transport].observe(clusters)
    if n_usable == 0:
        logger.error("[evaluate] no usable records in %s", args.input)
        return 2
    n_train = sum(n_train_by_transport.values())
    n_test = sum(n_test_by_transport.values())
    logger.info("[evaluate] split by sha256(packet_hex)[:8] %% 10000 < %d: "
                "train=%d test=%d", threshold, n_train, n_test)
    if n_train == 0 or n_test == 0:
        logger.error("[evaluate] empty split (train=%d, test=%d) — need both "
                     "non-empty; adjust --test-ratio or add data", n_train, n_test)
        return 2

    train_universes = {t: set(s.universe) for t, s in train_stats.items()}
    metrics = {
        t: {"n_instances": 0, "sum_brier_cal": 0.0, "sum_brier_heu": 0.0,
            "sum_ll_cal": 0.0, "sum_ll_heu": 0.0,
            "bins": [{"low": i / 10, "high": (i + 1) / 10, "n": 0,
                      "sum_pred": 0.0, "sum_y": 0.0} for i in range(10)]}
        for t in train_stats
    }

    for transport, clusters, packet_hex in _iter_usable_records(args.input):
        if _packet_bucket(packet_hex) >= threshold:
            continue
        m = metrics.get(transport)
        if m is None:      
            continue
        stats = train_stats[transport]
        universe = train_universes[transport]
        for i in sorted(clusters):
            if i not in universe:
                continue
            for j in sorted(universe):
                if j == i:
                    continue
                y = 1.0 if j in clusters else 0.0
                h = scorer.score(i, j)
                alpha, beta, mean, _std = shrinkage_posterior(
                    h, args.prior_strength,
                    stats.pair_n.get((i, j), 0), stats.cluster_n[i])
                p_cal = min(max(mean, 1e-6), 1 - 1e-6)
                p_heu = min(max(h, 1e-6), 1 - 1e-6)
                m["n_instances"] += 1
                m["sum_brier_cal"] += (p_cal - y) ** 2
                m["sum_brier_heu"] += (p_heu - y) ** 2
                m["sum_ll_cal"] += -(y * math.log(p_cal)
                                     + (1 - y) * math.log(1 - p_cal))
                m["sum_ll_heu"] += -(y * math.log(p_heu)
                                     + (1 - y) * math.log(1 - p_heu))
                b = m["bins"][min(int(p_cal * 10), 9)]
                b["n"] += 1
                b["sum_pred"] += p_cal
                b["sum_y"] += y

    totals = {"n_instances": 0, "sum_brier_cal": 0.0, "sum_brier_heu": 0.0,
              "sum_ll_cal": 0.0, "sum_ll_heu": 0.0}
    per_transport = {}
    for transport in sorted(train_stats):
        m = metrics[transport]
        n_instances = m["n_instances"]
        if n_instances == 0:
            continue
        calibration_table = [
            {
                "low": b["low"], "high": b["high"], "n": b["n"],
                "mean_predicted": (b["sum_pred"] / b["n"]) if b["n"] else None,
                "observed_rate": (b["sum_y"] / b["n"]) if b["n"] else None,
            }
            for b in m["bins"]
        ]
        per_transport[transport] = {
            "n_train_packets": train_stats[transport].n_packets,
            "n_test_packets": n_test_by_transport[transport],
            "n_pairs_evaluated": n_instances,
            "brier_calibrated": m["sum_brier_cal"] / n_instances,
            "logloss_calibrated": m["sum_ll_cal"] / n_instances,
            "brier_heuristic": m["sum_brier_heu"] / n_instances,
            "logloss_heuristic": m["sum_ll_heu"] / n_instances,
            "calibration_table": calibration_table,
        }
        totals["n_instances"] += n_instances
        totals["sum_brier_cal"] += m["sum_brier_cal"]
        totals["sum_brier_heu"] += m["sum_brier_heu"]
        totals["sum_ll_cal"] += m["sum_ll_cal"]
        totals["sum_ll_heu"] += m["sum_ll_heu"]

    if totals["n_instances"] == 0:
        logger.error("[evaluate] no evaluable (i,j) instances — test packets' "
                     "clusters not covered by train universe?")
        return 2

    n = totals["n_instances"]
    report = {
        "schema_version": 1,
        "type": "compat_calibration_evaluation",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "input": os.path.abspath(args.input),
        "split": {
            "method": "sha256(packet_hex)[:8] as uint32 mod 10000 < threshold",
            "test_ratio": args.test_ratio,
            "n_train": n_train,
            "n_test": n_test,
        },
        "prior_strength": args.prior_strength,
        "smoothing": list(smoothing),
        "neutral_q": args.neutral_q,
        "n_specs": len(specs),
        "per_transport": per_transport,
        "totals": {
            "n_instances": n,
            "brier_calibrated": totals["sum_brier_cal"] / n,
            "logloss_calibrated": totals["sum_ll_cal"] / n,
            "brier_heuristic": totals["sum_brier_heu"] / n,
            "logloss_heuristic": totals["sum_ll_heu"] / n,
        },
        "semantics": {
            "instance": "One ordered (test packet, i, j) pair: the packet reaches i;"
                        "label=1 exactly when it also reaches j",
            "prediction": "calibrated=shrinkage q(i,j), fitted only on training data;"
                          "heuristic=structural baseline h(i,j)",
            "observational_note": "P(j|i) is observational co-response frequency,"
                                  "not the causal direction of a mutation",
        },
    }
    atomic_write_json(args.output, report)
    t = report["totals"]
    logger.info(
        "[evaluate] report: %s | instances=%d | "
        "Brier cal=%.4f vs heu=%.4f | logloss cal=%.4f vs heu=%.4f",
        args.output, n, t["brier_calibrated"], t["brier_heuristic"],
        t["logloss_calibrated"], t["logloss_heuristic"],
    )
    return 0

# ============================================================================
# argparse
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Compatibility calibration (P1-6): stream fingerprints, "
                    "calibrate structural scores against real co-responses.")
    sub = parser.add_subparsers(dest="command", required=True)

    fit = sub.add_parser("fit", help="stream input JSON(s) → calibration artifact")
    fit.add_argument("inputs", nargs="+", help="input fingerprint JSON file(s)")
    fit.add_argument("-o", "--output", required=True, help="artifact output path")
    fit.add_argument("--specs-dir", default=config.PROTOCOL_SPECS_DIR,
                     help="protocol specs dir for heuristic prior means")
    fit.add_argument("--prior-strength", type=float,
                     default=getattr(config, "COMPATIBILITY_PRIOR_STRENGTH",
                                     DEFAULT_PRIOR_STRENGTH),
                     help="shrinkage pseudo-count s (default from config)")
    fit.add_argument("--smoothing-a", type=float, default=DEFAULT_SMOOTHING[0])
    fit.add_argument("--smoothing-b", type=float, default=DEFAULT_SMOOTHING[1])
    fit.add_argument("--neutral-q", type=float,
                     default=getattr(config, "COMPATIBILITY_NEUTRAL_Q", NEUTRAL_Q))
    fit.add_argument("--objective-version",
                     default=getattr(config, "OBJECTIVE_VERSION", None),
                     help="objective version stamped into the artifact (default: "
                          "current config.OBJECTIVE_VERSION; runtime strict-"
                          "validates artifact against it)")
    fit.set_defaults(func=cmd_fit)

    ev = sub.add_parser("evaluate", help="stable-hash train/test split evaluation")
    ev.add_argument("input", help="input fingerprint JSON file")
    ev.add_argument("-o", "--output", required=True, help="report output path")
    ev.add_argument("--test-ratio", type=float, default=0.3,
                    help="fraction of packets held out for test (hash split)")
    ev.add_argument("--specs-dir", default=config.PROTOCOL_SPECS_DIR)
    ev.add_argument("--prior-strength", type=float,
                    default=getattr(config, "COMPATIBILITY_PRIOR_STRENGTH",
                                    DEFAULT_PRIOR_STRENGTH))
    ev.add_argument("--smoothing-a", type=float, default=DEFAULT_SMOOTHING[0])
    ev.add_argument("--smoothing-b", type=float, default=DEFAULT_SMOOTHING[1])
    ev.add_argument("--neutral-q", type=float,
                    default=getattr(config, "COMPATIBILITY_NEUTRAL_Q", NEUTRAL_Q))
    ev.set_defaults(func=cmd_evaluate)
    return parser

def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())
