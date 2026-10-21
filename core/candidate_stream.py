"""Memory-bounded candidate persistence for long fuzzing campaigns.

Each worker owns one gzip JSONL stream.  A stream becomes authoritative only
after the worker closes it successfully and the parent records its manifest
entry in a completed-round checkpoint.  Truncated files from killed workers
therefore remain harmless orphans.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
from pathlib import Path
from typing import Dict, Iterable, Iterator, Optional, Sequence

from core.clustering import cluster_of

SCHEMA_VERSION = 2

def _safe_component(value: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in value)

def candidate_dict_to_disk_record(
    candidate: dict,
    *,
    transport: str,
    objective_version: str = "",
    weight_config_hash: str = "",
) -> dict:
    """Convert the compact worker dict to the durable flat JSONL schema."""
    observations = candidate.get("response_observations")
    if observations is not None:
        disk_responses = [
            {
                "service": item.get("service", ""),
                "response_hex": bytes(item.get("response_bytes") or b"").hex(),
                "banner_hex": bytes(item.get("banner_bytes") or b"").hex(),
                "response_phase": item.get("response_phase", "post_payload"),
                "latency_ms": float(item.get("latency_ms", 0.0)),
                "banner_latency_ms": float(item.get("banner_latency_ms", 0.0)),
                "payload_latency_ms": float(item.get("payload_latency_ms", 0.0)),
            }
            for item in observations
            if item.get("response_bytes") or item.get("banner_bytes")
        ]
    else:
        disk_responses = [
            {
                "service": member,
                "response_hex": bytes(response).hex(),
                "banner_hex": "",
                "response_phase": "legacy_unknown",
                "latency_ms": float(latency),
                "banner_latency_ms": 0.0,
                "payload_latency_ms": 0.0,
            }
            for member, response, latency in candidate.get("responses", ())
            if response
        ]

    record = {
        "schema_version": SCHEMA_VERSION,
        "packet_hex": bytes(candidate.get("packet") or b"").hex(),
        "mutation_target": candidate.get("mutation_target", ""),
        "candidate_type": candidate.get("candidate_type", "multi_probe"),
        "iteration": int(candidate.get("iteration", 0)),
        "transport": transport,
        "triggered_clusters": sorted(candidate.get("triggered_clusters") or ()),
        "responses": disk_responses,
    }
    if objective_version:
        record["objective_version"] = objective_version
    if weight_config_hash:
        record["weight_config_hash"] = weight_config_hash
    for key in ("parent_seed_id", "parent_packet_hash"):
        if candidate.get(key):
            record[key] = candidate[key]
    for key in (
        "observed_clusters", "passive_clusters", "payload_triggered_clusters",
        "selective_payload_clusters",
    ):
        if key in candidate:
            record[key] = sorted(candidate.get(key) or ())
    for key in (
        "raw_payload_breadth", "background_adjusted_breadth", "null_threshold",
    ):
        if key in candidate:
            record[key] = float(candidate.get(key) or 0.0)
    for key in ("qualifies_multi_probe", "passive_target"):
        if key in candidate:
            record[key] = bool(candidate.get(key))
    if candidate.get("background_artifact_hash"):
        record["background_artifact_hash"] = candidate["background_artifact_hash"]

    if candidate.get("qualification_status"):
        record["qualification_status"] = candidate["qualification_status"]
    return record

class CandidateStreamWriter:
    """Worker-owned gzip JSONL writer; failures are isolated and observable."""

    def __init__(
        self,
        *,
        enabled: bool,
        stream_dir: str,
        run_id: str,
        task_id: str,
        transport: str,
        objective_version: str = "",
        weight_config_hash: str = "",
    ) -> None:
        self.enabled = bool(enabled)
        self.transport = transport
        self.objective_version = objective_version
        self.weight_config_hash = weight_config_hash
        self.records = 0
        self.errors = 0
        self.path = ""
        self._fh = None
        if not self.enabled:
            return
        try:
            out_dir = Path(stream_dir) / _safe_component(run_id)
            out_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{_safe_component(task_id)}_pid{os.getpid()}.jsonl.gz"
            self.path = str(out_dir / filename)
            self._fh = gzip.open(self.path, "wt", encoding="utf-8", newline="\n")
        except Exception:
            self.errors += 1
            self.enabled = False
            self.path = ""
            self._fh = None

    def write(self, candidate: dict) -> bool:
        if not self.enabled or self._fh is None:
            return False
        try:
            record = candidate_dict_to_disk_record(
                candidate,
                transport=self.transport,
                objective_version=self.objective_version,
                weight_config_hash=self.weight_config_hash,
            )
            self._fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            self._fh.write("\n")
            self.records += 1
            return True
        except Exception:
            self.errors += 1
            return False

    def close(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.close()
        except Exception:
            self.errors += 1
        finally:
            self._fh = None

    def manifest_entry(self) -> dict:
        return {
            "path": self.path,
            "records": self.records,
            "errors": self.errors,
        }

def iter_candidate_stream(path: str) -> Iterator[dict]:
    """Yield complete records from one authoritative gzip JSONL stream."""
    with gzip.open(path, "rt", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                schema = int(record.get("schema_version", 1))
                if schema not in (1, SCHEMA_VERSION):
                    raise ValueError(
                        f"unsupported candidate stream schema {schema} at "
                        f"{path}:{line_number}")
                yield record
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid candidate stream {path}:{line_number}: {exc}") from exc

def disk_record_pattern_digest(record: dict) -> str:
    """Exact cluster/response pattern digest for a flat candidate record."""
    pairs = {
        (cluster_of(item.get("service", "")), item.get("response_hex", ""))
        for item in record.get("responses", ())
        if item.get("response_hex")
    }
    h = hashlib.blake2b(digest_size=20, person=b"pf-cluster-v1")
    for cluster, response_hex in sorted(pairs):
        cluster_bytes = cluster.encode("utf-8", errors="surrogatepass")
        response = bytes.fromhex(response_hex)
        h.update(len(cluster_bytes).to_bytes(4, "big"))
        h.update(cluster_bytes)
        h.update(len(response).to_bytes(8, "big"))
        h.update(response)
    return h.hexdigest()

def disk_record_to_nested(record: dict) -> dict:
    """Convert the flat stream schema to the public nested fingerprint schema."""
    grouped: Dict[str, list] = {}
    for item in record.get("responses", ()):
        if not item.get("response_hex"):
            continue
        member = item.get("service", "")
        grouped.setdefault(cluster_of(member), []).append({
            "service": member,
            "response_hex": item["response_hex"],
            "latency_ms": item.get("latency_ms", 0.0),
            **({"banner_hex": item.get("banner_hex", "")}
               if "banner_hex" in item else {}),
            **({"response_phase": item.get("response_phase", "legacy_unknown")}
               if "response_phase" in item else {}),
            **({"banner_latency_ms": item.get("banner_latency_ms", 0.0)}
               if "banner_latency_ms" in item else {}),
            **({"payload_latency_ms": item.get("payload_latency_ms", 0.0)}
               if "payload_latency_ms" in item else {}),
        })
    nested = {
        "packet_hex": record.get("packet_hex", ""),
        "mutation_target": record.get("mutation_target", ""),
        "candidate_type": record.get("candidate_type", "multi_probe"),
        "iteration": int(record.get("iteration", 0)),
        "transport": record.get("transport", ""),
        "responses": [
            {
                "service": cluster,
                "responses": sorted(members, key=lambda item: item["service"]),
            }
            for cluster, members in sorted(grouped.items())
        ],
    }
    for key in (
        "objective_version", "weight_config_hash",
        "parent_seed_id", "parent_packet_hash", "background_artifact_hash",
        "observed_clusters", "passive_clusters", "payload_triggered_clusters",
        "selective_payload_clusters", "raw_payload_breadth",
        "background_adjusted_breadth", "null_threshold",
        "qualifies_multi_probe", "passive_target", "qualification_status",
    ):
        if key in record:
            nested[key] = record[key]
    return nested

def export_candidate_streams(
    entries: Sequence[dict],
    output_path: str,
    *,
    max_per_pattern: int = 1,
) -> dict:
    """Stream authoritative task files to one atomic nested JSON array.

    Memory is bounded by compact digest counters; packet and response bytes are
    never accumulated.  Entries with errors or missing paths are rejected.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temp = output.with_suffix(output.suffix + ".tmp")
    pattern_counts: Dict[str, int] = {}
    read_records = written_records = 0
    source_files = 0
    first = True
    try:
        with open(temp, "w", encoding="utf-8") as out:
            out.write("[\n")
            for entry in sorted(entries, key=lambda item: item.get("path", "")):
                path = entry.get("path", "")
                if not path or int(entry.get("errors", 0)):
                    continue
                source_files += 1
                for record in iter_candidate_stream(path):
                    read_records += 1
                    digest = disk_record_pattern_digest(record)
                    count = pattern_counts.get(digest, 0)
                    is_semantic = (
                        record.get("objective_version")
                        == "background_adjusted_breadth"
                    )
                    # Background-adjusted candidates were already compressed by the semantic
                    # key inside each worker.  Reapplying the legacy exact-
                    # response cap here would silently collapse its top-K.
                    if not is_semantic and count >= max_per_pattern:
                        continue
                    pattern_counts[digest] = count + 1
                    if not first:
                        out.write(",\n")
                    json.dump(
                        disk_record_to_nested(record), out,
                        ensure_ascii=False, separators=(",", ":"),
                    )
                    first = False
                    written_records += 1
            out.write("\n]\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, output)
    except BaseException:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
        raise
    return {
        "output_path": str(output),
        "source_files": source_files,
        "read_records": read_records,
        "written_records": written_records,
        "unique_patterns": len(pattern_counts),
    }
