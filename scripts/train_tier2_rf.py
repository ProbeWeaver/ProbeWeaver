#!/usr/bin/env python3
"""Train the Tier-2 RF on every response in a frozen rule corpus."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config  # noqa: E402
from fingerprint.tier2_rf import Tier2TrainingError, train_tier2_rf  # noqa: E402

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Train/refit the Tier-2 RandomForest from the full "
                    "phase-aware rule corpus")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--corpus-provenance")
    parser.add_argument("--output", required=True)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=20)
    parser.add_argument("--min-samples-leaf", type=int, default=2)
    parser.add_argument("--group-test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--n-jobs", type=int, default=-1)
    parser.add_argument(
        "--deployment-threshold", type=float,
        default=float(getattr(config, "FINGERPRINT_CONFIDENCE_THRESHOLD", 0.7)))
    return parser

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = train_tier2_rf(
            corpus_path=args.corpus,
            provenance_path=args.corpus_provenance,
            output_dir=args.output,
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            min_samples_leaf=args.min_samples_leaf,
            group_test_size=args.group_test_size,
            random_state=args.random_state,
            n_jobs=args.n_jobs,
            deployment_threshold=args.deployment_threshold,
        )
    except (OSError, ValueError, Tier2TrainingError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "artifact_hash": result["artifact_hash"],
        "samples": result["data"]["n_samples"],
        "classes": result["data"]["n_classes"],
        "in_sample_accuracy": result["final_fit"]["in_sample_accuracy"],
        "group_diagnostic": result["diagnostic"].get("status"),
        "output": str(Path(args.output).resolve()),
    }, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
