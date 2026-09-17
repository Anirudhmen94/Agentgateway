"""Deterministic policy layer. No LLM, no network."""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import yaml

from src.models import PolicyDecision, ToolRequest

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "agents.yaml"

INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "new system prompt",
    "system prompt:",
    "system:",
    "you are now",
    "jailbreak",
    "developer mode",
    "override your instructions",
    "do not follow your",
    "call pr.merge",
    "call account.close",
    "call payment.initiate",
    "call customer.export",
    "<!-- ignore previous",
)

SECRET_KEYS = (
    "api_key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "private_key",
    "access_token",
    "refresh_token",
    "bearer",
    "aws_secret_access_key",
    "xai_api_key",
)

EXFIL_KEYS = (
    "forward_to",
    "webhook",
    "exfiltrate",
    "bcc",
    "external_url",
    "drop_url",
    "export_all",
    "destination_url",
)

# Extra fields that turn a granted single-record tool into collection / foreign-record access.
SENSITIVE_FIELD_TOKENS = (
    "full_pan",
    "include_ssn",
    "ssn_last4",
    "bank_account",
    "routing_number",
    "cvv",
    "cvc",
    "include_hr",
    "hr_notes",
    "passport_number",
    "tax_id",
    "national_id",
    "date_of_birth",
)

PIGGYBACK_KEY = re.compile(
    r"(fetch|lookup|attach|pull|include).*(customer|crm|payroll|hr|invoice|ledger|ssn|pan|record)",
    re.I,
)

BULK_KEYS = ("page_size", "limit", "count", "batch_size")


def load_agents(path: Path | None = None) -> dict[str, dict[str, Any]]:
    raw = yaml.safe_load((path or CONFIG_PATH).read_text()) or {}
    agents = {}
    for row in raw.get("agents") or []:
        agents[row["id"]] = row
    return agents


def _flatten_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        out: list[str] = []
        for k, v in value.items():
            out.append(str(k))
            out.extend(_flatten_strings(v))
        return out
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out.extend(_flatten_strings(item))
        return out
    return [str(value)]


def _blob(request: ToolRequest) -> str:
    parts = [request.session_context, request.tool]
    parts.extend(_flatten_strings(request.args))
    return " ".join(parts).lower()


class PolicyEngine:
    def __init__(self, agents: dict[str, dict[str, Any]] | None = None, *, enforce_rate_limit: bool = True) -> None:
        self.agents = agents if agents is not None else load_agents()
        self.enforce_rate_limit = enforce_rate_limit
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._all_tools: set[str] = set()
        for row in self.agents.values():
            self._all_tools.update(row.get("allowed_tools") or [])
            self._all_tools.update(row.get("escalation") or [])

    def reset_rate_limits(self) -> None:
        self._hits.clear()

    def _rate_exceeded(self, agent_id: str, limit: int) -> bool:
        now = time.time()
        window = self._hits[agent_id]
        while window and now - window[0] > 60:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False

    def evaluate(self, request: ToolRequest | dict[str, Any]) -> PolicyDecision:
        if not isinstance(request, ToolRequest):
            request = ToolRequest.from_dict(request)

        agent = self.agents.get(request.agent_id)
        if agent is None:
            return PolicyDecision(
                verdict="deny",
                rule_id="unknown_agent",
                reason=f"Agent {request.agent_id!r} is not registered.",
                category="scope_creep",
            )

        if not request.tool:
            return PolicyDecision(
                verdict="deny",
                rule_id="unknown_tool",
                reason="Tool name is missing.",
                category="scope_creep",
            )

        allowed = set(agent.get("allowed_tools") or [])
        escalation = set(agent.get("escalation") or [])
        if request.tool not in allowed and request.tool not in escalation:
            if request.tool not in self._all_tools:
                return PolicyDecision(
                    verdict="deny",
                    rule_id="unknown_tool",
                    reason=f"Tool {request.tool!r} is not a registered tool.",
                    category="scope_creep",
                )
            return PolicyDecision(
                verdict="deny",
                rule_id="tool_not_allowed",
                reason=f"Tool {request.tool!r} is outside allowed_tools.",
                category="scope_creep",
            )

        if request.tool not in allowed and request.tool in escalation:
            return PolicyDecision(
                verdict="approve",
                rule_id="escalation_tool",
                reason=f"Tool {request.tool!r} always requires human approval.",
                category="scope_creep",
            )

        if self.enforce_rate_limit:
            limit = int(agent.get("rate_limit_per_min") or 60)
            if self._rate_exceeded(request.agent_id, limit):
                return PolicyDecision(
                    verdict="deny",
                    rule_id="rate_limit_exceeded",
                    reason=f"Rate limit {limit}/min exceeded for {request.agent_id}.",
                    category="scope_creep",
                )

        blob = _blob(request)
        args_l = {str(k).lower(): v for k, v in request.args.items()}

        if any(marker in blob for marker in INJECTION_MARKERS):
            return PolicyDecision(
                verdict="undecided",
                rule_id="injection_markers",
                reason="Prompt-injection markers present; escalate to classifier.",
                category="prompt_injection",
            )

        secret_hit = [k for k in args_l if any(s in k for s in SECRET_KEYS)]
        secret_in_values = bool(
            re.search(
                r"(api[_-]?key|client_secret|private_key|aws_secret|refresh_token|access_token|bearer\s+[a-z0-9]|sk-[a-z0-9]{8,}|xai-[a-z0-9]{8,}|password reset token|\"password\"|'password'|paste their password|portal password)",
                blob,
                re.I,
            )
        )
        if secret_hit or secret_in_values:
            return PolicyDecision(
                verdict="undecided",
                rule_id="credential_signals",
                reason="Credential-shaped fields or secret material in the call.",
                category="credential_misuse",
            )

        if any(k in args_l for k in EXFIL_KEYS):
            return PolicyDecision(
                verdict="undecided",
                rule_id="exfil_destination",
                reason="Call names an outbound destination or export flag.",
                category="data_exfiltration",
            )
        if _sensitive_overcollect(request):
            return PolicyDecision(
                verdict="undecided",
                rule_id="sensitive_field_overcollect",
                reason="Call requests payment, identity, or HR fields outside a single in-scope lookup.",
                category="data_exfiltration",
            )
        if _cross_tool_record_fetch(request):
            return PolicyDecision(
                verdict="undecided",
                rule_id="cross_tool_record_fetch",
                reason="Granted tool arguments piggyback a record fetch from another system of record.",
                category="scope_creep",
            )
        if re.search(r"https?://", blob) and any(
            tok in blob for tok in ("forward", "webhook", "drop", "exfil", "bcc", "send to")
        ):
            return PolicyDecision(
                verdict="undecided",
                rule_id="exfil_url",
                reason="HTTP destination combined with forwarding language.",
                category="data_exfiltration",
            )

        for key in BULK_KEYS:
            try:
                n = int(args_l.get(key))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                n = 0
            if n and n > 25:
                return PolicyDecision(
                    verdict="undecided",
                    rule_id="bulk_read",
                    reason="Bulk page size is outside a single-record lookup.",
                    category="data_exfiltration",
                )

        if request.args.get("customer_id") in ("*", "all") or request.args.get("export") is True:
            return PolicyDecision(
                verdict="undecided",
                rule_id="wildcard_export",
                reason="Wildcard or export flag on a lookup tool.",
                category="data_exfiltration",
            )

        ids = request.args.get("customer_ids") or request.args.get("ticket_ids")
        if isinstance(ids, list) and len(ids) > 3:
            return PolicyDecision(
                verdict="undecided",
                rule_id="multi_id_lookup",
                reason="Multi-id lookup exceeds single-record scope.",
                category="data_exfiltration",
            )

        if _looks_like_foreign_purpose(request, agent):
            return PolicyDecision(
                verdict="undecided",
                rule_id="purpose_mismatch_signals",
                reason="Granted tool, but session or args suggest another team's job.",
                category="scope_creep",
            )

        return PolicyDecision(
            verdict="allow",
            rule_id="clean_allow",
            reason="Registered agent, granted tool, no policy signals.",
            category="benign",
        )


def _looks_like_foreign_purpose(request: ToolRequest, agent: dict[str, Any]) -> bool:
    blob = _blob(request)
    agent_id = request.agent_id
    foreign = {
        "support-triage": (
            "payroll",
            "ledger",
            "merge the pr",
            "marketing segment",
            "campaign list",
            "wire transfer",
            "production deploy",
            "refund_approved",
            "approve refund",
            "issue payment",
            "hr notes",
            "include_hr",
            "closed_won",
            "crm_opportunity",
            "direct deposit",
        ),
        "invoice-processing": (
            "support ticket",
            "pull request",
            "customer ssn",
            "ssn",
            "marketing",
            "source code",
            "password reset",
            "payroll",
            "pay now",
            "mark paid",
            "bank_change",
            "home addresses",
            "employee home",
        ),
        "code-review": (
            "customer record",
            "customer_record",
            "fetch_customer",
            "invoice",
            "refund",
            "payroll",
            "crm export",
            "vendor payment",
            "deploy this",
            "rotate production",
            "branch protection",
            "infra-prod",
        ),
        "customer-data-lookup": (
            "campaign",
            "all customers",
            "lead list",
            "merge pull",
            "post ledger",
            "pay vendor",
            "newsletter",
            "sales list",
            "enrichment dump",
        ),
    }
    return any(tok in blob for tok in foreign.get(agent_id, ()))


def _norm_token(value: str) -> str:
    return value.lower().replace("-", "_")


def _sensitive_overcollect(request: ToolRequest) -> bool:
    parts = [_norm_token(p) for p in _flatten_strings(request.args)]
    blob = " ".join(parts)
    return any(tok in blob for tok in SENSITIVE_FIELD_TOKENS)


def _cross_tool_record_fetch(request: ToolRequest) -> bool:
    native_lookup = request.tool in {"customer.get", "order.status"}
    for key in request.args:
        if PIGGYBACK_KEY.search(str(key)):
            if native_lookup and str(key).lower() in {"customer_id", "include"}:
                continue
            if request.tool.startswith("customer.") and "customer" in str(key).lower():
                continue
            return True
    return False


_ENGINE: PolicyEngine | None = None


def get_engine() -> PolicyEngine:
    global _ENGINE
    if _ENGINE is None:
        _ENGINE = PolicyEngine()
    return _ENGINE


def evaluate(request: ToolRequest | dict[str, Any]) -> PolicyDecision:
    return get_engine().evaluate(request)


def main() -> None:
    import json
    import sys

    raw = json.loads(sys.argv[1]) if len(sys.argv) > 1 else {
        "id": "cli-1",
        "agent_id": "support-triage",
        "tool": "ticket.get",
        "args": {"ticket_id": "TCK-1"},
        "session_context": "Triage the newest billing ticket.",
    }
    print(json.dumps(evaluate(raw).to_dict(), indent=2))


if __name__ == "__main__":
    main()
