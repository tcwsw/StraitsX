"""Hash-chained append-only audit log.

Tamper-evident without a blockchain: every entry commits to the hash of the one before it.
The on-chain settlement tx is what anchors the chain to something the team cannot forge.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Any, Iterator

from .models import now_iso

_LOCK = threading.Lock()
GENESIS = "0" * 64


def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


class Ledger:
    def __init__(self, path: str = "audit/ledger.jsonl") -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _last_hash(self) -> str:
        prev = GENESIS
        for entry in self.read():
            prev = entry["hash"]
        return prev

    def append(self, kind: str, actor: str, data: dict[str, Any]) -> dict:
        with _LOCK:
            prev = self._last_hash()
            body = {
                "seq": sum(1 for _ in self.read()),
                "ts": now_iso(),
                "kind": kind,
                "actor": actor,
                "data": data,
                "prev": prev,
            }
            body["hash"] = _hash(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str))
            with open(self.path, "a") as fh:
                fh.write(json.dumps(body, default=str) + "\n")
            return body

    def read(self) -> Iterator[dict]:
        if not os.path.exists(self.path):
            return iter(())
        with open(self.path) as fh:
            return iter([json.loads(line) for line in fh if line.strip()])

    def verify(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message) — this is the thing you run on stage."""
        prev = GENESIS
        for entry in self.read():
            body = {k: v for k, v in entry.items() if k != "hash"}
            if body["prev"] != prev:
                return False, f"broken link at seq {body['seq']}"
            recomputed = _hash(json.dumps(body, sort_keys=True, separators=(",", ":"), default=str))
            if recomputed != entry["hash"]:
                return False, f"tampered entry at seq {body['seq']}"
            prev = entry["hash"]
        return True, "chain intact"
