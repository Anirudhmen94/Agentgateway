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

    def to_audit_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "tool": self.tool,
            "verdict": self.verdict,
            "deciding_layer": self.deciding_layer,
            "rule_id": self.rule_id,
            "category": self.category,
            "latency_ms": round(self.latency_ms, 3),
            "model": self.model,
            "cached": self.cached,
        }
