"""Hash-chained, tamper-evident JSONL audit log.

Each entry stores the SHA-256 of the previous entry (``prev_hash``) and its
own hash over a canonical JSON encoding of every other field. Editing,
deleting, or reordering any line breaks the chain from that point forward,
which ``verify_chain()`` detects.

This is tamper-*evident*, not tamper-*proof*: someone who can rewrite the
whole file can recompute every hash. Production would anchor the head hash
somewhere the writer can't touch (WORM bucket, a separate signing service).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _entry_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None, reset: bool = True):
        """``path=None`` keeps the log in memory only (used by tests)."""
        self.path = Path(path) if path else None
        self.entries: list[dict[str, Any]] = []
        if self.path is not None and reset:
            self.path.write_text("", encoding="utf-8")

    @property
    def head_hash(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS_HASH

    def record(self, actor: str, action: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        # Round-trip the payload through JSON now so what we hash is exactly
        # what a later reload from disk will see (enums, tuples, etc.).
        normalized = json.loads(json.dumps(payload or {}, default=str))
        body = {
            "seq": len(self.entries),
            "ts": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "action": action,
            "payload": normalized,
            "prev_hash": self.head_hash,
        }
        entry = {**body, "hash": _entry_hash(body)}
        self.entries.append(entry)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(entry) + "\n")
        return entry

    def verify_chain(self) -> bool:
        return self.first_broken_seq() is None

    def first_broken_seq(self) -> int | None:
        """Index of the first entry that fails verification, or None if intact."""
        prev = GENESIS_HASH
        for index, entry in enumerate(self.entries):
            body = {k: v for k, v in entry.items() if k != "hash"}
            if (
                entry.get("seq") != index
                or entry.get("prev_hash") != prev
                or entry.get("hash") != _entry_hash(body)
            ):
                return index
            prev = entry["hash"]
        return None

    def filter(self, action: str | None = None, actor: str | None = None) -> list[dict[str, Any]]:
        return [
            e
            for e in self.entries
            if (action is None or e["action"] == action) and (actor is None or e["actor"] == actor)
        ]

    @classmethod
    def load(cls, path: str | Path) -> "AuditLog":
        """Read an existing log from disk (read-only; nothing is truncated)."""
        log = cls(path=None)
        log.path = Path(path)
        for line in log.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                log.entries.append(json.loads(line))
        return log
