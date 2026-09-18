"""Durable per-agent session quotas. File-backed JSON under out/ by default."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PATH = ROOT / "out" / "quotas.json"
DEFAULT_WINDOW_SECONDS = 3600

_store: "QuotaStore | None" = None
_store_lock = threading.Lock()


def store_path() -> Path:
    raw = os.getenv("QUOTA_STORE_PATH")
    return Path(raw) if raw else DEFAULT_PATH


def default_window_seconds() -> int:
    raw = os.getenv("QUOTA_WINDOW_SECONDS", str(DEFAULT_WINDOW_SECONDS)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = DEFAULT_WINDOW_SECONDS
    return max(1, value)


def default_limit() -> int:
    raw = os.getenv("QUOTA_DEFAULT_LIMIT", "0").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def limit_for_agent(agent: dict[str, Any] | None) -> int:
    if not agent:
        return 0
    if agent.get("quota_limit") is not None:
        try:
            return max(0, int(agent.get("quota_limit")))
        except (TypeError, ValueError):
            return 0
    return default_limit()


def window_for_agent(agent: dict[str, Any] | None) -> int:
    if agent and agent.get("quota_window_seconds") is not None:
        try:
            return max(1, int(agent.get("quota_window_seconds")))
        except (TypeError, ValueError):
            return default_window_seconds()
    return default_window_seconds()


@dataclass(frozen=True)
class QuotaSnapshot:
    allowed: bool
    limit: int
    remaining: int
    window_seconds: int
    used: int


class QuotaStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or store_path()
        self._lock = threading.Lock()

    def _load_unlocked(self) -> dict[str, list[float]]:
        if not self.path.exists():
            return {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"quota store unreadable: {self.path}") from exc
        if isinstance(raw, dict) and isinstance(raw.get("hits"), dict):
            hits_raw = raw["hits"]
        elif isinstance(raw, dict) and all(isinstance(v, list) for v in raw.values()):
            hits_raw = raw
        else:
            raise RuntimeError(f"quota store has unexpected shape: {self.path}")
        hits: dict[str, list[float]] = {}
        for agent_id, stamps in hits_raw.items():
            if not isinstance(agent_id, str) or not isinstance(stamps, list):
                raise RuntimeError(f"quota store has unexpected shape: {self.path}")
            cleaned: list[float] = []
            for item in stamps:
                if not isinstance(item, (int, float)):
                    raise RuntimeError(f"quota store has unexpected shape: {self.path}")
                cleaned.append(float(item))
            hits[agent_id] = cleaned
        return hits

    def _write_unlocked(self, hits: dict[str, list[float]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"hits": hits}, indent=2) + "\n"
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        tmp.replace(self.path)

    def _prune(self, stamps: list[float], now: float, window_seconds: int) -> list[float]:
        cutoff = now - window_seconds
        return [ts for ts in stamps if ts > cutoff]

    def all(self) -> dict[str, list[float]]:
        with self._lock:
            return self._load_unlocked()

    def consume(self, agent_id: str, limit: int, window_seconds: int, *, now: float | None = None) -> QuotaSnapshot:
        if limit <= 0:
            return QuotaSnapshot(
                allowed=True,
                limit=0,
                remaining=0,
                window_seconds=window_seconds,
                used=0,
            )
        stamp = time_now(now)
        with self._lock:
            hits = self._load_unlocked()
            window = self._prune(hits.get(agent_id) or [], stamp, window_seconds)
            if len(window) >= limit:
                hits[agent_id] = window
                self._write_unlocked(hits)
                return QuotaSnapshot(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    window_seconds=window_seconds,
                    used=len(window),
                )
            window.append(stamp)
            hits[agent_id] = window
            self._write_unlocked(hits)
            used = len(window)
            return QuotaSnapshot(
                allowed=True,
                limit=limit,
                remaining=max(0, limit - used),
                window_seconds=window_seconds,
                used=used,
            )

    def remaining(self, agent_id: str, limit: int, window_seconds: int, *, now: float | None = None) -> int:
        if limit <= 0:
            return 0
        stamp = time_now(now)
        with self._lock:
            window = self._prune(self._load_unlocked().get(agent_id) or [], stamp, window_seconds)
            return max(0, limit - len(window))

    def clear(self) -> None:
        with self._lock:
            self._write_unlocked({})


def time_now(now: float | None) -> float:
    import time

    return float(now) if now is not None else time.time()


def get_store() -> QuotaStore:
    global _store
    path = store_path()
    with _store_lock:
        if _store is None or _store.path != path:
            _store = QuotaStore(path)
        return _store


def reset_store_for_tests() -> None:
    global _store
    with _store_lock:
        _store = None
