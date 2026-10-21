"""Build the atomic, multi-probe-first, phase-aware rule-training corpus.

Prepare the identification corpus. Inputs are one or more public
JSON arrays (nested fingerprint schema) and/or authoritative gzip JSONL
candidate streams (flat candidate-stream schema); large JSON arrays stream
with ijson when installed.  All logic lives in ``core/rule_corpus.py`` — this
CLI only wires inputs, defaults and atomic output.

Selection semantics (see ``core/rule_corpus.py`` for the full contract):
  - ``multi_probe`` / ``exploratory_multi_probe`` → primary channel
    (responses from ALL responding services);
  - ``target_reachability`` → support channel (per-(cluster, member)
    supplementation only);
  - ``diagnostic_only`` and unknown types are skipped and reported;
  - exact duplicate candidate identities are deduplicated; conflicting
    duplicates fail fast;
  - selected records that are legacy phase-unknown (strict mode, the
    default) or malformed (any mode) fail fast **before** any output file is
    written;
  - partition quotas/salts/ratios are recorded in the provenance sidecar,
    which is written atomically **after** the corpus and binds its file
    SHA256 + canonical corpus digest.

No network, no Agent: this tool is pure offline data preparation.

Example:
  mamba run -n protocol_fuzzer python scripts/build_rule_training_corpus.py \\
      --input candidates.json stream_dir/task_tcp.jsonl.gz \\
      --output rules/corpus.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Iterator, Optional, Sequence

# Limit glibc malloc arena for this CLI process (consistent with other tools)
os.environ.setdefault("MALLOC_ARENA_MAX", "8")

# Make repo root importable when invoked as `python scripts/build_...py`
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import config  # noqa: E402
from core.candidate_stream import iter_candidate_stream  # noqa: E402
from core.rule_corpus import (  # noqa: E402
    DEFAULT_BANNER_SUPPORT_CAP,
    RULE_CORPUS_SCHEMA_VERSION,
    RuleCorpusError,
    build_and_write_rule_corpus,
    load_rule_corpus,
)

logger = logging.getLogger("build_rule_training_corpus")

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

def iter_input_records(paths: Sequence[str], *, distinct_source_observations=False) -> Iterator[dict]:
    """Yield candidate records from JSON arrays and/or ``.jsonl.gz`` streams."""
    if distinct_source_observations:
        for path in paths:
            with open(path, 'rb') as handle:
                source_sha = hashlib.file_digest(handle, 'sha256').hexdigest()
            for index, record in enumerate(iter_input_records([path])):
                if 'candidate_occurrence_id' in record:
                    raise RuleCorpusError('source already carries an occurrence identity')
                occurrence = hashlib.sha256(
                    f'source-observation-v1:{source_sha}:{index}'.encode()).hexdigest()
                yield {**record, 'candidate_occurrence_id': occurrence}
        return
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
                # Match json.load's numeric types: Decimal breaks canonical
                # JSON hashing of real candidate latencies/reward values.
                for record in ijson.items(handle, "item", use_float=True):
                    yield record
                    n += 1
            logger.info("streamed %d records (ijson) from %s", n, path)
            continue
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            raise RuleCorpusError(
                f"input {path} is not a JSON array of candidate records")
        for record in data:
            yield record
        logger.info("loaded %d records (json fallback) from %s",
                    len(data), path)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(args: argparse.Namespace) -> int:
    result = build_and_write_rule_corpus(
        iter_input_records(args.input, distinct_source_observations=getattr(
            args, 'distinct_source_observations', False)),
        args.output,
        provenance_output=args.provenance_output,
        allow_legacy=args.allow_legacy,
        primary_cap=args.primary_cap,
        min_samples=args.min_samples,
        banner_support_cap=args.banner_support_cap,
        limit=args.limit,
    )
    report = result["build"].report
    corpus = result["corpus"]
    provenance = result["provenance"]
    logger.info("corpus build: %s", report.summary())
    if report.skipped_candidate_types:
        logger.info(
            "skipped candidate types (never enter the corpus): %s",
            dict(report.skipped_candidate_types))
    if report.duplicate_identity_deduped:
        logger.info(
            "deduplicated %d exact duplicate candidate identities",
            report.duplicate_identity_deduped)
    logger.info(
        "wrote corpus: %s (schema=%d construction=%s atoms=%d "
        "file_sha256=%s corpus_digest=%s)",
        corpus["output_path"], RULE_CORPUS_SCHEMA_VERSION,
        provenance["construction"]["method"], corpus["atom_count"],
        corpus["file_sha256"], corpus["corpus_digest"])
    logger.info(
        "wrote provenance sidecar: %s (mode=%s construction_view=%s "
        "packet_universe_size=%s merge=%s)",
        result["provenance_path"], provenance["phase_awareness_mode"],
        provenance["construction"]["view"],
        provenance["construction"]["packet_universe_size"],
        provenance["construction"]["identification_cluster_merge"])
    # Immediate round-trip validation: fail loudly rather than ship a
    # self-inconsistent corpus/provenance pair.
    load_rule_corpus(
        corpus["output_path"], result["provenance_path"],
        expected_corpus_digest=corpus["corpus_digest"],
        expected_file_sha256=corpus["file_sha256"])
    counts = provenance["counts"]["atoms"]
    by_id_cluster: dict = {}
    for pair_key, pair in provenance["counts"]["pairs"].items():
        id_cluster = pair_key.split("/", 1)[0]
        by_id_cluster[id_cluster] = by_id_cluster.get(id_cluster, 0) + pair["atoms"]
    logger.info(
        "atoms by id_cluster (%d clusters): %s (unique response identities: %d)",
        len(by_id_cluster), dict(sorted(by_id_cluster.items())),
        counts["unique_response_identities"])
    return 0

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the atomic, multi-probe-first, phase-aware "
                    "rule-training corpus from candidate streams / public "
                    "nested arrays.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  mamba run -n protocol_fuzzer python scripts/build_rule_training_corpus.py \\
      --input candidates.json task_tcp.jsonl.gz \\
      --output rules/corpus.json
""",
    )
    parser.add_argument(
        "--input", "-i", nargs="+", required=True,
        help="One or more nested JSON arrays or authoritative .jsonl.gz candidate streams")
    parser.add_argument(
        "--output", "-o", required=True,
        help="Output corpus path; stream JSON and replace the temporary file atomically")
    parser.add_argument(
        "--provenance-output", default=None,
        help="Provenance sidecar (default: <output>.provenance.json); written"
             "atomically only after the corpus has been saved successfully")
    parser.add_argument(
        "--allow-legacy", action="store_true",
        help="Explicitly admit legacy records with unknown phases, marked"
             "legacy_unknown and non-phase-aware in provenance")
    parser.add_argument(
        "--primary-cap", type=int,
        default=int(getattr(config, "RULE_GEN_SAMPLE_PER_CLUSTER", 400)),
        help="Maximum primary observations per (service, implementation)"
             "(default: config.RULE_GEN_SAMPLE_PER_CLUSTER)")
    parser.add_argument(
        "--min-samples", type=int,
        default=int(getattr(config, "RULE_GEN_MIN_SAMPLES", 20)),
        help="Fill sparse primary observations with target-reachability samples up to this per-pair count"
             "(default: config.RULE_GEN_MIN_SAMPLES)")
    parser.add_argument(
        "--banner-support-cap", type=int,
        default=DEFAULT_BANNER_SUPPORT_CAP,
        help=f"Maximum supplementary banner observations per pair when primary data lacks banners"
             f"(default:{DEFAULT_BANNER_SUPPORT_CAP}）")
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Process only the first N eligible candidates (0 = all; introduces order dependence,"
             "for debugging only)")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument('--distinct-source-observations', action='store_true',
                        help='Retain repeated campaign observations using source file SHA256 + zero-based record index; does not change packet/family identities')
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
    except RuleCorpusError as exc:
        logger.error("rule corpus build failed: %s", exc)
        return 2

if __name__ == "__main__":
    sys.exit(main())
