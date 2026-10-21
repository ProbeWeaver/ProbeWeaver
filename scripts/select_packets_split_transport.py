#!/usr/bin/env python3
"""Select independent TCP and UDP probe sequences using shared weighted greedy coverage. Packet transport defines the observation universe."""
import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_HERE) not in sys.path:  
    sys.path.insert(0, str(_HERE))

os.environ.setdefault("MALLOC_ARENA_MAX", "8")

from services_config import SERVICES  # noqa: E402
from select_packets import (  # noqa: E402
    PacketSelector,
    compute_cluster_weights,
    load_censys_counts,
    load_nested_packets,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger("split_select")

WANT = {
    "tcp": {"tcp", "both"},
    "udp": {"udp", "both"},
}

def member_transport(member: str) -> str:
    return SERVICES.get(member, {}).get("protocol", "tcp")

def build_universe(packets, transport, split_by="packet"):
    """Select packets belonging to one transport universe."""
    want = WANT[transport]
    out = []
    for p in packets:
        if split_by == "packet" and p.get("transport", "") != transport:
            continue
        pairs = {(c, m) for (c, m) in p["pairs"] if member_transport(m) in want}
        if pairs:
            q = dict(p)
            q["pairs"] = pairs
            out.append(q)
    return out

def select_for(universe_packets, counts, k, alpha, min_new, label,
               objective="weighted", quota=1):
    ubc = {}
    for p in universe_packets:
        for (c, _m) in p["pairs"]:
            ubc.setdefault(c, set()).add(_m)
    n_per = {c: len(ms) for c, ms in ubc.items()}
    weights = compute_cluster_weights(set(ubc), prevalence_alpha=alpha, counts=counts)
    sel = PacketSelector(universe_packets, weights, n_per, gamma=1.0,
                          objective=objective, quota=quota)
    chosen = sel.select(k=k, min_new_coverage=min_new)
    report = sel.coverage_report(chosen)
    return chosen, report, weights

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--input", nargs="+",
                    default=["outputs/fingerprints.json"])
    ap.add_argument("--tcp-out", default="outputs/selected_tcp.json")
    ap.add_argument("--udp-out", default="outputs/selected_udp.json")
    ap.add_argument("--k", type=int, default=7)
    ap.add_argument("--alpha", type=float, default=0.7)
    ap.add_argument("--min-new", type=float, default=0.005, dest="min_new")
    ap.add_argument("--objective", choices=["weighted", "lexicographic", "quota"], default="weighted",
                    help="Selection objective: weighted (default), lexicographic, or quota")
    ap.add_argument("--quota", type=int, default=1, help="Per-service implementation quota (default: 1)")
    ap.add_argument("--split-by", choices=["packet", "member"], default="packet",
                    help="Universe partition: packet transport (default);"
                         "member transport is a legacy fallback for untagged data")
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    counts = load_censys_counts()

    t0 = time.time()
    packets = load_nested_packets(args.input)
    if args.limit > 0:
        packets = packets[: args.limit]
    log.info("Loaded %d unique packets in %.0fs", len(packets), time.time() - t0)

    summary = {}
    for tr in ("tcp", "udp"):
        uni = build_universe(packets, tr, split_by=args.split_by)
        t1 = time.time()
        chosen, report, weights = select_for(
            uni, counts, args.k, args.alpha, args.min_new, tr,
            objective=args.objective, quota=args.quota,
        )
        log.info("[%s] Universe: %d packets / %d services / %d pairs; selected %d | service coverage %.1f%% (%d/%d) |"
                 "weighted implementation coverage %.1f%% (%.0fs)",
                 tr, len(uni), report["universe"]["n_clusters"],
                 report["universe"]["n_pairs"], len(chosen),
                 100.0 * report["cluster_coverage"], report["n_clusters_covered"],
                 report["universe"]["n_clusters"],
                 100.0 * report["weighted_coverage"], time.time() - t1)

        out_path = Path(args.tcp_out if tr == "tcp" else args.udp_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "transport": tr,
            "selected_packets": chosen,
            "coverage": report,
            "cluster_weights": weights,
            "parameters": {"k": args.k, "alpha": args.alpha,
                           "objective": args.objective, "quota": args.quota,
                           "min_new_coverage": args.min_new},
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        log.info("[%s] Wrote %s", tr, out_path)

        for s in chosen:
            cum = report["cumulative"][s["rank"] - 1]["weighted_coverage"]
            log.info("  [%s] rank %d  target=%-9s marg=%.4f  cum=%.1f%%  newpairs=%d",
                     tr, s["rank"], s.get("mutation_target", "?"), s["marginal_benefit"],
                     100.0 * cum, len(s["covered_pairs_newly"]))

        summary[tr] = {
            "universe_packets": len(uni),
            "n_clusters": report["universe"]["n_clusters"],
            "n_pairs": report["universe"]["n_pairs"],
            "selected": len(chosen),
            "weighted_coverage": report["weighted_coverage"],
            "first_5_cov": report["cumulative"][min(4, len(chosen) - 1)]["weighted_coverage"]
            if chosen else 0.0,
        }

    log.info("Summary: %s", json.dumps(summary, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    sys.exit(main())
