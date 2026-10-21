#!/usr/bin/env python3
"""Build the lineage-complete construction view required by E0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.rule_corpus import (  # noqa: E402
    RuleCorpusError,
    derive_lineage_complete_rule_corpus,
)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Derive a strict rule corpus that contains only real "
                    "parent-lineage probe families")
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--corpus-provenance")
    parser.add_argument("--output", required=True)
    parser.add_argument("--provenance-output")
    parser.add_argument("--summary-output")
    return parser

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = derive_lineage_complete_rule_corpus(
            args.corpus,
            args.output,
            provenance_path=args.corpus_provenance,
            provenance_output=args.provenance_output,
        )
    except (OSError, RuleCorpusError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    summary = {
        "source_atom_count": result["source_atom_count"],
        "retained_atom_count": result["retained_atom_count"],
        "dropped_atom_count": result["dropped_atom_count"],
        "corpus_path": result["corpus"]["output_path"],
        "corpus_digest": result["corpus"]["corpus_digest"],
        "corpus_file_sha256": result["corpus"]["file_sha256"],
        "provenance_path": result["provenance_path"],
        "construction": result["provenance"]["construction"],
    }
    if args.summary_output:
        target = Path(args.summary_output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(summary, indent=2, ensure_ascii=False)
                          + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
