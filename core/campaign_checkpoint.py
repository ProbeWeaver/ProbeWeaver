"""Atomic round-boundary checkpoints for resumable fuzzing campaigns.

The pickle is trusted local state (SeedRecord/Bandit/controller objects).  A
small JSON companion is deliberately inspectable without importing project
code.  Checkpoints are committed only after an entire iteration finishes.
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
from pathlib import Path
from typing import Any, Dict, Optional

CHECKPOINT_SCHEMA_VERSION = 1

def build_campaign_signature(
    *,
    transport: str,
    protocols: list,
    services: list,
    objective_version: str,
    weight_config_hash: str,
    fingerprint_threshold: int,
    seed_threshold: int,
    spec_digests: Optional[dict] = None,
    state_identity: Optional[dict] = None,
) -> dict:
    """Build the compatibility signature.  max_iterations is intentionally absent.

    This allows a validated one-round run to resume later with a larger round
    ceiling while rejecting a different transport/universe/objective.
    """
    signature = {
        "transport": transport,
        "protocols": sorted(protocols),
        "services": sorted(services),
        "objective_version": objective_version,
        "weight_config_hash": weight_config_hash,
        "fingerprint_threshold": int(fingerprint_threshold),
        "seed_threshold": int(seed_threshold),
    }
    # A checkpoint embeds bandits too; guarding only the external JSON state
    # cannot prevent a restored pickle from reintroducing old field arms.
    # Omit optional keys for historical/legacy callers, preserving their paths.
    if spec_digests is not None:
        signature["spec_digests"] = dict(spec_digests)
    if state_identity is not None:
        signature["state_identity"] = dict(state_identity)
    return signature

def signature_digest(signature: dict) -> str:
    payload = json.dumps(
        signature, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

class CampaignCheckpoint:
    def __init__(self, root_dir: str, signature: dict) -> None:
        self.signature = signature
        self.signature_hash = signature_digest(signature)
        transport = signature.get("transport") or "unknown"
        self.directory = Path(root_dir) / f"{transport}_{self.signature_hash[:12]}"
        self.state_path = self.directory / "checkpoint.pkl"
        self.manifest_path = self.directory / "checkpoint.json"
        self.seeds_path = self.directory / "next_round_seeds.jsonl"

    def exists(self) -> bool:
        return self.state_path.is_file() and self.manifest_path.is_file()

    def load(self) -> Optional[dict]:
        if not self.exists():
            return None
        with open(self.state_path, "rb") as fh:
            payload = pickle.load(fh)
        if payload.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported checkpoint schema: {payload.get('schema_version')}"
            )
        if payload.get("signature") != self.signature:
            raise ValueError(
                "checkpoint signature mismatch; refusing to mix campaign universes"
            )
        return payload

    def save(self, state: Dict[str, Any], *, status: str = "round_complete") -> dict:
        self.directory.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "signature": self.signature,
            **state,
        }
        self._atomic_pickle(self.state_path, payload)
        self._write_seed_snapshot(payload.get("seeds_by_response_group", {}))

        entries = payload.get("candidate_stream_entries", [])
        manifest = {
            "schema_version": CHECKPOINT_SCHEMA_VERSION,
            "status": status,
            "signature": self.signature,
            "signature_hash": self.signature_hash,
            "run_id": payload.get("run_id", ""),
            "next_iteration": int(payload.get("next_iteration", 0)),
            "response_groups": len(payload.get("seeds_by_response_group", {})),
            "next_seed_count": sum(
                len(items)
                for items in payload.get("seeds_by_response_group", {}).values()
            ),
            "candidate_stream_files": len(entries),
            "candidate_stream_records": sum(
                int(entry.get("records", 0)) for entry in entries
            ),
            "reward_log_files": len(payload.get("reward_log_entries", [])),
            "state_path": str(self.state_path),
            "seed_snapshot_path": str(self.seeds_path),
        }
        self._atomic_json(self.manifest_path, manifest)
        return manifest

    @staticmethod
    def _atomic_pickle(path: Path, payload: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as fh:
            pickle.dump(payload, fh, protocol=pickle.HIGHEST_PROTOCOL)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    @staticmethod
    def _atomic_json(path: Path, payload: dict) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _write_seed_snapshot(self, groups: dict) -> None:
        tmp = self.seeds_path.with_suffix(self.seeds_path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as fh:
            for group, seeds in sorted(
                groups.items(), key=lambda item: sorted(item[0])
            ):
                for seed in seeds:
                    record = {
                        "response_group": sorted(group),
                        "packet_hex": seed.packet.hex(),
                        "verified_services": sorted(seed.verified_services),
                        "fuzzed_protocols": sorted(seed.fuzzed_protocols),
                        "seed_reason": seed.seed_reason,
                        "strict_seed_target": seed.strict_seed_target,
                    }
                    fh.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
                    fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.seeds_path)
