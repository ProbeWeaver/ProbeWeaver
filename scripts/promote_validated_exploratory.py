#!/usr/bin/env python
"""Promote stable, held-out-rule-confirmed exploratory candidates offline."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.validated_exploratory import (  # noqa: E402
    ValidatedExploratoryError,
    build_validated_exploratory_artifact,
    load_promotion_inputs,
    write_validated_exploratory_artifact,
)

logger = logging.getLogger("promote_validated_exploratory")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Promote exploratory candidates using bound stability and "
                    "hidden-eval rule facts.")
    parser.add_argument("--stability-artifact", required=True)
    parser.add_argument("--distinguishability-artifact", required=True)
    parser.add_argument("--rule-bundle-provenance", required=True)
    parser.add_argument("--output", required=True)
    return parser

def run(args: argparse.Namespace) -> int:
    stability, index, bundle = load_promotion_inputs(
        args.stability_artifact,
        args.distinguishability_artifact,
        args.rule_bundle_provenance,
    )
    artifact = build_validated_exploratory_artifact(
        stability, index.manifest, bundle, index)
    output = write_validated_exploratory_artifact(artifact, args.output)
    summary = artifact["summary"]
    print(
        f"validated={summary['n_validated']} "
        f"rejected={summary['n_rejected']} "
        f"skipped={summary['n_skipped']} "
        f"exploratory={summary['n_exploratory']} output={output}")
    return 0

def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        return run(build_parser().parse_args(argv))
    except (ValidatedExploratoryError, ValueError, OSError) as exc:
        logger.error("promotion rejected: %s", exc)
        return 2

if __name__ == "__main__":
    sys.exit(main())
