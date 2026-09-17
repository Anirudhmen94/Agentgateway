"""Gateway: revoke → policy → classifier, with JSONL audit."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.classifier import classify
from src.models import Decision, ToolRequest
from src.policy import PolicyEngine, get_engine

OUT_DIR = Path(__file__).resolve().parent.parent / "out"
AUDIT_PATH = OUT_DIR / "audit.jsonl"

_revoked: set[str] = set()
_lock = threading.Lock()
_subscribers: list[Callable[[dict[str, Any]], None]] = []


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def subscribe_audit(callback: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
    with _lock:
        _subscribers.append(callback)

    def _unsub() -> None:
        with _lock:
            if callback in _subscribers:
                _subscribers.remove(callback)

    return _unsub


def revoked_agents() -> set[str]:
    with _lock:
        return set(_revoked)


def revoke(agent_id: str) -> None:
    with _lock:
        _revoked.add(agent_id)


def unrevoke(agent_id: str) -> None:
    with _lock:
        _revoked.discard(agent_id)


def clear_revocations() -> None:
    with _lock:
        _revoked.clear()


def _append_audit(record: dict[str, Any]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        with AUDIT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
        listeners = list(_subscribers)
    for cb in listeners:
        try:
            cb(record)
        except Exception:
            pass


def handle(
    request: ToolRequest | dict[str, Any],
    *,
    use_cache: bool = True,
    classify_fn: Callable[..., Any] | None = None,
    policy: PolicyEngine | None = None,
    audit: bool = True,
) -> Decision:
    started = time.perf_counter()
    if not isinstance(request, ToolRequest):
        request = ToolRequest.from_dict(request)
    if not request.id:
        request.id = f"req-{int(time.time() * 1000)}"

    with _lock:
        is_revoked = request.agent_id in _revoked

    if is_revoked:
        decision = Decision(
            request_id=request.id,
            agent_id=request.agent_id,
            tool=request.tool,
            verdict="deny",
            deciding_layer="policy",
            rule_id="agent_revoked",
            category="scope_creep",
            reason="Agent is revoked.",
            confidence=1.0,
            reasoning="Revocation list is checked before policy and before the model.",
            latency_ms=(time.perf_counter() - started) * 1000,
            model=None,
            temperature=None,
            timestamp_utc=_utc_now(),
        )
        if audit:
            _append_audit(decision.to_audit_dict())
        return decision

    engine = policy or get_engine()
    policy_decision = engine.evaluate(request)
    if policy_decision.verdict != "undecided":
        decision = Decision(
            request_id=request.id,
            agent_id=request.agent_id,
            tool=request.tool,
            verdict=policy_decision.verdict,
            deciding_layer="policy",
            rule_id=policy_decision.rule_id,
            category=policy_decision.category,
            reason=policy_decision.reason,
            confidence=1.0,
            reasoning=policy_decision.reason,
            latency_ms=(time.perf_counter() - started) * 1000,
            model=None,
            temperature=None,
            timestamp_utc=_utc_now(),
        )
        if audit:
            _append_audit(decision.to_audit_dict())
        return decision

    fn = classify_fn or classify
    result = fn(request, use_cache=use_cache)
    decision = Decision(
        request_id=request.id,
        agent_id=request.agent_id,
        tool=request.tool,
        verdict=result.verdict,
        deciding_layer="model",
        rule_id=policy_decision.rule_id,
        category=result.category,
        reason=policy_decision.reason,
        confidence=result.confidence,
        reasoning=result.reasoning,
        latency_ms=(time.perf_counter() - started) * 1000,
        model=result.model,
        temperature=result.temperature,
        timestamp_utc=result.timestamp_utc,
        cached=bool(result.cached),
    )
    if audit:
        _append_audit(decision.to_audit_dict())
    return decision


def main() -> None:
    import sys

    raw = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {
        "id": "cli-gw",
        "agent_id": "support-triage",
        "tool": "ticket.get",
        "args": {"ticket_id": "TCK-1"},
        "session_context": "Triage the newest billing ticket.",
    }
    print(json.dumps(handle(raw).__dict__, indent=2, default=str))


if __name__ == "__main__":
    main()
