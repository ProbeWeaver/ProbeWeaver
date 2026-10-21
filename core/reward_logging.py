"""Per-worker compressed JSONL logging for multi-objective reward events.

Each worker owns a unique file, so multiprocessing never appends to the same
stream. Logging is best-effort: I/O failure disables that worker's logger but
never aborts a fuzzing campaign.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

def _safe_component(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))
    return value.strip("._") or "unknown"

class RewardEventLogger:
    """Stream reward events to one gzip-compressed JSONL file."""

    def __init__(
        self,
        *,
        enabled: bool,
        log_dir: str,
        run_id: str,
        task_id: str,
        mutation_target: str,
        iteration: int,
    ) -> None:
        self.enabled = bool(enabled)
        self.path: Optional[str] = None
        self.events = 0
        self.errors = 0
        self._fh = None
        if not self.enabled:
            return
        try:
            run_dir = Path(log_dir) / _safe_component(run_id)
            run_dir.mkdir(parents=True, exist_ok=True)
            filename = (
                f"iter{int(iteration):02d}_{_safe_component(mutation_target)}_"
                f"{_safe_component(task_id)}_pid{os.getpid()}.jsonl.gz"
            )
            path = run_dir / filename
            self._fh = gzip.open(path, mode="wt", encoding="utf-8")
            self.path = str(path)
        except Exception as exc:
            self.errors += 1
            self.enabled = False
            logger.warning("[REWARD-LOG] failed to open worker log: %s", exc)

    def write(self, event: Dict[str, Any]) -> None:
        if not self.enabled or self._fh is None:
            return
        try:
            self._fh.write(json.dumps(event, sort_keys=True, ensure_ascii=False))
            self._fh.write("\n")
            self.events += 1
        except Exception as exc:
            self.errors += 1
            logger.warning("[REWARD-LOG] disabling failed worker log %s: %s", self.path, exc)
            self.close()
            self.enabled = False

    def close(self) -> None:
        if self._fh is None:
            return
        try:
            self._fh.close()
        except Exception as exc:
            self.errors += 1
            logger.warning("[REWARD-LOG] failed to close %s: %s", self.path, exc)
        finally:
            self._fh = None

    def manifest_entry(self) -> Dict[str, Any]:
        return {"path": self.path or "", "events": self.events, "errors": self.errors}

