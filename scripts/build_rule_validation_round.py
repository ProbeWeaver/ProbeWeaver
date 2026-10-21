#!/usr/bin/env python3
"""Bind a fresh, lineage-disjoint stability reprobe round to a rule bundle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.candidate_stability import load_stability_artifact  # noqa: E402
from core.rule_corpus import load_rule_corpus  # noqa: E402
from core.rule_validation import (  # noqa: E402
    build_rule_validation_round,
    write_rule_validation_round,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create the probe-family-disjoint validation binding "
                    "required for formal rule-confirmed evaluation.")
    parser.add_argument("--rule-bundle", required=True)
    parser.add_argument("--rule-corpus", required=True)
    parser.add_argument("--rule-corpus-provenance", default=None)
    parser.add_argument("--stability-artifact", required=True)
    parser.add_argument("--transport", choices=("tcp", "udp"), required=True)
    parser.add_argument("--output", required=True)
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    with open(args.rule_bundle, encoding="utf-8") as handle:
        bundle = json.load(handle)
    atoms, provenance = load_rule_corpus(
        args.rule_corpus, args.rule_corpus_provenance)
    stability = load_stability_artifact(args.stability_artifact)
    artifact = build_rule_validation_round(
        rule_bundle=bundle,
        corpus_atoms=atoms,
        corpus_provenance=provenance,
        stability_artifact=stability,
        transport=args.transport,
    )
    write_rule_validation_round(artifact, args.output)
    print(
        f"validation={artifact['artifact_hash']} transport={args.transport} "
        f"challenge={artifact['challenge']['candidate_count']} "
        "packet_overlap=0 family_overlap=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
