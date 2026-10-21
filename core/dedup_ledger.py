"""Crash-tolerant, process-shared send deduplication for background-adjusted search."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence

SCHEMA_VERSION = 1

def packet_digest(packet: bytes) -> str:
    return hashlib.sha256(packet).hexdigest()

@dataclass(frozen=True)
class ClaimResult:
    packet_hash: str
    claimed: bool
    reason: str

class DedupLedger:
    """SQLite-WAL claim ledger keyed by epoch/transport/target/payload.

    ``pending`` rows are leases.  A worker marks them ``completed`` only after
    the response and all local artifacts have been processed.  If a worker
    dies, a later claimant can recover the row after ``lease_seconds``.
    """

    def __init__(
        self,
        path: str,
        *,
        lease_seconds: float = 900.0,
        owner: Optional[str] = None,
        busy_timeout_ms: int = 30_000,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be > 0")
        self.path = path
        self.lease_seconds = float(lease_seconds)
        self.owner = owner or f"pid{os.getpid()}-{uuid.uuid4().hex}"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._conn = sqlite3.connect(
            path, timeout=max(1.0, busy_timeout_ms / 1000.0),
            isolation_level=None, check_same_thread=False,
        )
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        init_deadline = time.monotonic() + max(1.0, busy_timeout_ms / 1000.0)

        def init_execute(statement: str, parameters=()):
            while True:
                try:
                    return self._conn.execute(statement, parameters)
                except sqlite3.OperationalError as exc:
                    if "locked" not in str(exc).lower() or time.monotonic() >= init_deadline:
                        raise
                    time.sleep(0.02)

        init_execute("PRAGMA journal_mode=WAL")
        init_execute("PRAGMA synchronous=NORMAL")
        init_execute("""
            CREATE TABLE IF NOT EXISTS send_claims (
                attempt_epoch TEXT NOT NULL,
                transport TEXT NOT NULL,
                mutation_target TEXT NOT NULL,
                packet_hash TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending', 'completed')),
                owner TEXT NOT NULL,
                claimed_at REAL NOT NULL,
                completed_at REAL,
                PRIMARY KEY(attempt_epoch, transport, mutation_target, packet_hash)
            )
        """)
        init_execute("""
            CREATE TABLE IF NOT EXISTS ledger_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)
        init_execute("""
            CREATE INDEX IF NOT EXISTS idx_send_claims_owner_pending
            ON send_claims(attempt_epoch, transport, mutation_target, owner, status)
        """)
        existing = self._conn.execute(
            "SELECT value FROM ledger_meta WHERE key='schema_version'"
        ).fetchone()
        if existing is None:
            init_execute(
                "INSERT OR IGNORE INTO ledger_meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        elif existing[0] != str(SCHEMA_VERSION):
            raise ValueError(
                f"dedup ledger schema mismatch: {existing[0]!r} != {SCHEMA_VERSION}"
            )

    def claim_hashes(
        self,
        hashes: Sequence[str],
        *,
        attempt_epoch: str,
        transport: str,
        mutation_target: str,
        now: Optional[float] = None,
    ) -> List[ClaimResult]:
        if not attempt_epoch or transport not in ("tcp", "udp") or not mutation_target:
            raise ValueError("attempt_epoch, tcp/udp transport and mutation_target are required")
        timestamp = time.time() if now is None else float(now)
        expires_before = timestamp - self.lease_seconds
        results: List[ClaimResult] = []
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            for digest in hashes:
                key = (attempt_epoch, transport, mutation_target, digest)
                row = self._conn.execute(
                    """SELECT status, owner, claimed_at FROM send_claims
                       WHERE attempt_epoch=? AND transport=?
                         AND mutation_target=? AND packet_hash=?""",
                    key,
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        """INSERT INTO send_claims
                           (attempt_epoch, transport, mutation_target, packet_hash,
                            status, owner, claimed_at, completed_at)
                           VALUES (?, ?, ?, ?, 'pending', ?, ?, NULL)""",
                        (*key, self.owner, timestamp),
                    )
                    results.append(ClaimResult(digest, True, "new_claim"))
                elif row[0] == "completed":
                    results.append(ClaimResult(digest, False, "completed"))
                elif float(row[2]) <= expires_before:
                    self._conn.execute(
                        """UPDATE send_claims SET owner=?, claimed_at=?, completed_at=NULL
                           WHERE attempt_epoch=? AND transport=?
                             AND mutation_target=? AND packet_hash=?""",
                        (self.owner, timestamp, *key),
                    )
                    results.append(ClaimResult(digest, True, "lease_recovered"))
                else:
                    results.append(ClaimResult(digest, False, "pending"))
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise
        return results

    def claim_packets(self, packets: Sequence[bytes], **kwargs) -> List[ClaimResult]:
        return self.claim_hashes([packet_digest(p) for p in packets], **kwargs)

    def complete_hashes(
        self,
        hashes: Iterable[str],
        *,
        attempt_epoch: str,
        transport: str,
        mutation_target: str,
        now: Optional[float] = None,
    ) -> int:
        timestamp = time.time() if now is None else float(now)
        rows = [
            (timestamp, attempt_epoch, transport, mutation_target, digest, self.owner)
            for digest in hashes
        ]
        if not rows:
            return 0
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            before = self._conn.total_changes
            self._conn.executemany(
                """UPDATE send_claims SET status='completed', completed_at=?
                   WHERE attempt_epoch=? AND transport=? AND mutation_target=?
                     AND packet_hash=? AND owner=? AND status='pending'""",
                rows,
            )
            changed = self._conn.total_changes - before
            self._conn.execute("COMMIT")
            return int(changed)
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def renew_pending(
        self,
        *,
        attempt_epoch: str,
        transport: str,
        mutation_target: str,
        now: Optional[float] = None,
    ) -> int:
        """Refresh every pending lease owned by this worker in one statement."""
        timestamp = time.time() if now is None else float(now)
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            before = self._conn.total_changes
            self._conn.execute(
                """UPDATE send_claims SET claimed_at=?
                   WHERE attempt_epoch=? AND transport=? AND mutation_target=?
                     AND owner=? AND status='pending'""",
                (timestamp, attempt_epoch, transport, mutation_target, self.owner),
            )
            changed = self._conn.total_changes - before
            self._conn.execute("COMMIT")
            return int(changed)
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "DedupLedger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
