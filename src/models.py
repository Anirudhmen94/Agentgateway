"""Shared request/decision types for the gateway."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


CATEGORIES = (
    "benign",
    "prompt_injection",
    "scope_creep",
    "data_exfiltration",
    "credential_misuse",
)

VERDICTS = ("allow", "deny", "approve", "undecided")


def execution_allowed(verdict: str) -> bool:
    """True only for allow. approve is a hard pending gate, never a proceed signal."""
    return verdict == "allow"


def execution_state(verdict: str) -> str:
    if verdict == "allow":
        return "allowed"
    if verdict == "approve":
        return "pending_approval"
    return "denied"


def is_pending(verdict: str) -> bool:
    """Approve/escalate is a hard pending gate. Never equivalent to allow."""
    return verdict == "approve"


@dataclass
class ToolRequest:
    id: str
    agent_id: str
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    session_context: str = ""
    session_id: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolRequest":
        args = data.get("args") or {}
        if not isinstance(args, dict):
            args = {"_raw": args}
        return cls(
            id=str(data.get("id") or data.get("request_id") or ""),
            agent_id=str(data.get("agent_id") or ""),
            tool=str(data.get("tool") or ""),
            args=args,
            session_context=str(data.get("session_context") or ""),
            session_id=str(data.get("session_id") or ""),
        )


@dataclass
class PolicyDecision:
    verdict: str
    rule_id: str
    reason: str
    category: str | None = None
    quota_limit: int | None = None
    quota_remaining: int | None = None
    quota_window_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ClassifierResult:
    verdict: str
    category: str
    confidence: float
    reasoning: str
    model: str
    temperature: float
    timestamp_utc: str
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Decision:
    request_id: str
    agent_id: str
    tool: str
    verdict: str
    deciding_layer: str
    rule_id: str | None
    category: str | None
    reason: str
    confidence: float | None
    reasoning: str | None
    latency_ms: float
    model: str | None
    temperature: float | None
    timestamp_utc: str
    cached: bool = False
    quota_limit: int | None = None
    quota_remaining: int | None = None
    quota_window_seconds: int | None = None

    @property
    def execution_allowed(self) -> bool:
        return execution_allowed(self.verdict)

    @property
    def state(self) -> str:
        return execution_state(self.verdict)

    @property
    def pending(self) -> bool:
        return is_pending(self.verdict)

    @property
    def backend(self) -> str:
        from src.metrics import decision_backend

        return decision_backend(self.model, self.deciding_layer)

    def _reason_for_audit(self) -> str | None:
        text = (self.reasoning or self.reason or "").strip()
        return text or None

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "verdict": self.verdict,
            "state": self.state,
            "pending": self.pending,
            "execution_allowed": self.execution_allowed,
            "category": self.category,
            "confidence": self.confidence,
            "reason": self._reason_for_audit(),
            "reasoning": self.reasoning,
            "deciding_layer": self.deciding_layer,
            "backend": self.backend,
            "rule_id": self.rule_id,
            "latency_ms": self.latency_ms,
            "model": self.model,
            "temperature": self.temperature,
            "timestamp_utc": self.timestamp_utc,
            "cached": self.cached,
            **self._quota_fields(),
        }

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "verdict": self.verdict,
            "state": self.state,
            "pending": self.pending,
            "execution_allowed": self.execution_allowed,
            "deciding_layer": self.deciding_layer,
            "backend": self.backend,
            "rule_id": self.rule_id,
            "category": self.category,
            "reason": self._reason_for_audit(),
            "confidence": self.confidence,
            "latency_ms": round(self.latency_ms, 3),
            "model": self.model,
            "cached": self.cached,
            **self._quota_fields(),
        }

    def _quota_fields(self) -> dict[str, Any]:
        if self.quota_limit is None and self.quota_remaining is None:
            return {}
        return {
            "quota_limit": self.quota_limit,
            "quota_remaining": self.quota_remaining,
            "quota_window_seconds": self.quota_window_seconds,
            "quota_hit": self.rule_id == "quota_exceeded",
        }
