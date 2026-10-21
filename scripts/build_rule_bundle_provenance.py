#!/usr/bin/env python3
"""Build and immediately verify strict background-adjusted search rule-bundle provenance."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.rule_bundle_provenance import (  # noqa: E402
    RuleBundleProvenanceError,
    build_rule_bundle_provenance,
    load_rule_bundle_provenance,
    write_rule_bundle_provenance,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bind strict corpus, Agent states, rules and Go runtime")
    parser.add_argument("--cluster-rules")
    parser.add_argument("--member-rules")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--corpus-provenance")
    parser.add_argument("--agent-state", action="append", required=True)
    parser.add_argument("--zgrab-dir", required=True)
    parser.add_argument("--output", required=True)
    return parser


def run(args: argparse.Namespace) -> int:
    inputs = dict(
        cluster_rules_path=args.cluster_rules,
        member_rules_path=args.member_rules,
        corpus_path=args.corpus,
        corpus_provenance_path=args.corpus_provenance,
        agent_state_paths=args.agent_state,
        zgrab_dir=args.zgrab_dir,
    )
    manifest = build_rule_bundle_provenance(**inputs)
    write_rule_bundle_provenance(manifest, args.output)
    load_rule_bundle_provenance(
        args.output, **inputs,
        expected_manifest_hash=manifest["artifact_hash"])
    logging.getLogger(__name__).info(
        "wrote %s (artifact=%s corpus=%s rules=%s runtime=%s)",
        args.output, manifest["artifact_hash"],
        manifest["corpus"]["corpus_digest"],
        manifest["rules"]["digest"], manifest["runtime"]["digest"])
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    try:
        return run(args)
    except RuleBundleProvenanceError as exc:
        logging.getLogger(__name__).error("rule-bundle build failed: %s", exc)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
