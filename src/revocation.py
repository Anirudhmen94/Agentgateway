"""Durable agent revocation list. File-backed JSON under out/ by default."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "out" / "revocations.json"

_store: "RevocationStore | None" = None
_store_lock = threading.Lock()


def store_path() -> Path:
    raw = os.getenv("REVOCATION_STORE_PATH")
    return Path(raw) if raw else DEFAULT_PATH


class RevocationStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or store_path()
        self._lock = threading.Lock()

    def _load_unlocked(self) -> set[str]:
        if not self.path.exists():
            return set()
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"revocation store unreadable: {self.path}") from exc
        if isinstance(raw, dict):
            ids = raw.get("revoked") or []
        elif isinstance(raw, list):
            ids = raw
        else:
            raise RuntimeError(f"revocation store has unexpected shape: {self.path}")
        if not isinstance(ids, list) or not all(isinstance(x, str) for x in ids):
            raise RuntimeError(f"revocation store has unexpected shape: {self.path}")
        return set(ids)

    def _write_unlocked(self, ids: set[str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"revoked": sorted(ids)}, indent=2) + "\n"
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(self.path)

    def all(self) -> set[str]:
        with self._lock:
            return self._load_unlocked()

    def contains(self, agent_id: str) -> bool:
        return agent_id in self.all()

    def add(self, agent_id: str) -> None:
        with self._lock:
            ids = self._load_unlocked()
            ids.add(agent_id)
            self._write_unlocked(ids)

    def discard(self, agent_id: str) -> None:
        with self._lock:
            ids = self._load_unlocked()
            ids.discard(agent_id)
            self._write_unlocked(ids)

    def clear(self) -> None:
        with self._lock:
            self._write_unlocked(set())


def get_store() -> RevocationStore:
    global _store
    path = store_path()
    with _store_lock:
        if _store is None or _store.path != path:
            _store = RevocationStore(path)
        return _store


def reset_store_for_tests() -> None:
    global _store
    with _store_lock:
        _store = None
