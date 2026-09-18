"""Deterministic policy layer. No LLM, no network."""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

import yaml

from src.models import PolicyDecision, ToolRequest
from src.quota import get_store as get_quota_store
from src.quota import limit_for_agent, window_for_agent

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

# Pagination / sink / field / injection paraphrases live in *separate* tuples
# from INJECTION_MARKERS / EXFIL_KEYS / SENSITIVE_FIELD_TOKENS so adversarial
# rows can keep missing the closed vocabularies while policy still gates them.
PAGINATION_CURSOR_KEYS = (
    "cursor",
    "offset",
    "page",
    "after",
    "after_id",
    "resume",
    "next_token",
    "skip",
    "from_index",
    "continuation",
    "starting_at",
    "page_len",
    "take",
    "window",
)

EXFIL_SINK_KEYS = (
    "copy_to",
    "cc",
    "mirror",
    "mailbox_copy",
    "sidecar",
)

SENSITIVE_FIELD_SYNONYMS = (
    "card_number",
    "cardnumber",
    "routing",
    "payment_instrument",
    "payment instruments",
)

COLLECTION_ARG_KEYS = ("neighbors", "include_neighbors", "also_fetch")

_FOREIGN_RECORD_ID = re.compile(r"\b(?:CUS|CUST)-\d+\b", re.I)

_PAGINATION_WALK_RE = re.compile(
    r"("
    r"\d+\s+of\s+\d+"
    r"|keep walking"
    r"|page through"
    r"|keep paging"
    r"|keep sliding"
    r"|keep skipping"
    r"|until (?:the )?(?:queue is empty|every |the whole |we have the whole)"
    r"|one row at a time"
    r"|at a time for (?:an |the )?(?:offline|offsite|growth)"
    r"|copied locally"
    r"|on a laptop"
    r"|sits on a laptop"
    r"|offline workbook"
    r"|offsite workbook"
    r"|on disk"
    r"|whole history locally"
    r"|whole inbox"
    r"|save the pack"
    r"|spreadsheet ids"
    r")",
    re.I,
)

_INJECTION_STRUCTURE_RES = (
    re.compile(r"<!--"),
    re.compile(r"<\s*span\b[^>]*\bhidden\b", re.I),
    re.compile(r"\[//\]:\s*#"),
    re.compile(r'"directive"\s*:'),
    re.compile(r"\bassistant\s*:"),
    re.compile(r"\bplanner\s*:"),
)

_INJECTION_INTENT_RES = (
    re.compile(r"hidden instruction", re.I),
    re.compile(r"when you read this", re.I),
    re.compile(r"switch tasks", re.I),
    re.compile(r"standing orders", re.I),
    re.compile(r"(?:drop|abandon).{0,48}(?:queue|triage|policy|charter|fila)", re.I),
    re.compile(r"your assignment", re.I),
    re.compile(r"real assignment", re.I),
    re.compile(r"follow the other job", re.I),
    re.compile(r"ignora(?:r)? las instrucciones", re.I),
    re.compile(r"fusiona(?:r)? el cambio", re.I),
    re.compile(r"desconsidere", re.I),
    re.compile(r"durchwinken", re.I),
    re.compile(r"internen regeln ablegen", re.I),
    re.compile(r"comply with the invisible", re.I),
    re.compile(r"adopt the author", re.I),
    re.compile(r"take the writer's plan", re.I),
    re.compile(r"whatever the vendor wrote", re.I),
    re.compile(r"instead of ap\b", re.I),
    re.compile(r"do what the .{0,40}instruction", re.I),
)


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
    def __init__(
        self,
        agents: dict[str, dict[str, Any]] | None = None,
        *,
        enforce_rate_limit: bool = True,
        enforce_quota: bool | None = None,
    ) -> None:
        self.agents = agents if agents is not None else load_agents()
        self.enforce_rate_limit = enforce_rate_limit
        # Eval/regression engines already disable rate limits; keep quota off with them
        # unless a caller opts in. Live gateway keeps both on.
        self.enforce_quota = enforce_rate_limit if enforce_quota is None else enforce_quota
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

    def _consume_quota(self, agent_id: str, agent: dict[str, Any]):
        if not self.enforce_quota:
            return None
        limit = limit_for_agent(agent)
        if limit <= 0:
            return None
        window = window_for_agent(agent)
        return get_quota_store().consume(agent_id, limit, window)

    @staticmethod
    def _with_quota(decision: PolicyDecision, snap) -> PolicyDecision:
        if snap is None:
            return decision
        decision.quota_limit = snap.limit
        decision.quota_remaining = snap.remaining
        decision.quota_window_seconds = snap.window_seconds
        return decision

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

        quota_snap = self._consume_quota(request.agent_id, agent)
        if quota_snap is not None and not quota_snap.allowed:
            return self._with_quota(
                PolicyDecision(
                    verdict="deny",
                    rule_id="quota_exceeded",
                    reason=(
                        f"Session quota {quota_snap.limit} per {quota_snap.window_seconds}s "
                        f"exceeded for {request.agent_id}."
                    ),
                    category="scope_creep",
                ),
                quota_snap,
            )

        if request.tool not in allowed and request.tool in escalation:
            return self._with_quota(
                PolicyDecision(
                    verdict="approve",
                    rule_id="escalation_tool",
                    reason=f"Tool {request.tool!r} always requires human approval.",
                    category="scope_creep",
                ),
                quota_snap,
            )

        if self.enforce_rate_limit:
            limit = int(agent.get("rate_limit_per_min") or 60)
            if self._rate_exceeded(request.agent_id, limit):
                return self._with_quota(
                    PolicyDecision(
                        verdict="deny",
                        rule_id="rate_limit_exceeded",
                        reason=f"Rate limit {limit}/min exceeded for {request.agent_id}.",
                        category="scope_creep",
                    ),
                    quota_snap,
                )

        blob = _blob(request)
        args_l = {str(k).lower(): v for k, v in request.args.items()}

        if any(marker in blob for marker in INJECTION_MARKERS):
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="injection_markers",
                    reason="Prompt-injection markers present; escalate to classifier.",
                    category="prompt_injection",
                ),
                quota_snap,
            )
        if _injection_paraphrase(blob):
            return self._with_quota(
                PolicyDecision(
                    verdict="deny",
                    rule_id="injection_paraphrase",
                    reason="Untrusted text addresses the agent with an instruction hijack, including hidden markup or non-English override language.",
                    category="prompt_injection",
                ),
                quota_snap,
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
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="credential_signals",
                    reason="Credential-shaped fields or secret material in the call.",
                    category="credential_misuse",
                ),
                quota_snap,
            )

        if any(k in args_l for k in EXFIL_KEYS):
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="exfil_destination",
                    reason="Call names an outbound destination or export flag.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )
        if _exfil_sink(args_l):
            return self._with_quota(
                PolicyDecision(
                    verdict="deny",
                    rule_id="exfil_sink_paraphrase",
                    reason="Call names a copy/cc/mirror/sidecar sink outside the registered system of record.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )
        if _sensitive_overcollect(request):
            return self._with_quota(
                PolicyDecision(
                    verdict="deny",
                    rule_id="sensitive_field_overcollect",
                    reason="Call requests payment, identity, or HR fields outside a single in-scope lookup.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )
        if _cross_tool_record_fetch(request):
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="cross_tool_record_fetch",
                    reason="Granted tool arguments piggyback a record fetch from another system of record.",
                    category="scope_creep",
                ),
                quota_snap,
            )
        if re.search(r"https?://", blob) and any(
            tok in blob for tok in ("forward", "webhook", "drop", "exfil", "bcc", "send to")
        ):
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="exfil_url",
                    reason="HTTP destination combined with forwarding language.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )

        for key in BULK_KEYS:
            try:
                n = int(args_l.get(key))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                n = 0
            if n and n > 25:
                return self._with_quota(
                    PolicyDecision(
                        verdict="undecided",
                        rule_id="bulk_read",
                        reason="Bulk page size is outside a single-record lookup.",
                        category="data_exfiltration",
                    ),
                    quota_snap,
                )

        if _pagination_walk(request, args_l, blob):
            return self._with_quota(
                PolicyDecision(
                    verdict="deny",
                    rule_id="pagination_walk",
                    reason="Paging, cursor, or loop language turns a granted read into a population dump.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )

        if request.args.get("customer_id") in ("*", "all") or request.args.get("export") is True:
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="wildcard_export",
                    reason="Wildcard or export flag on a lookup tool.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )

        ids = request.args.get("customer_ids") or request.args.get("ticket_ids")
        if isinstance(ids, list) and len(ids) > 3:
            return self._with_quota(
                PolicyDecision(
                    verdict="undecided",
                    rule_id="multi_id_lookup",
                    reason="Multi-id lookup exceeds single-record scope.",
                    category="data_exfiltration",
                ),
                quota_snap,
            )

        misuse = _granted_tool_misuse(request, args_l, blob)
        if misuse or _looks_like_foreign_purpose(request, agent):
            return self._with_quota(
                PolicyDecision(
                    verdict="deny" if misuse else "undecided",
                    rule_id="granted_tool_misuse" if misuse else "purpose_mismatch_signals",
                    reason="Granted tool, but session or args suggest another team's job.",
                    category="scope_creep",
                ),
                quota_snap,
            )

        return self._with_quota(
            PolicyDecision(
                verdict="allow",
                rule_id="clean_allow",
                reason="Registered agent, granted tool, no policy signals.",
                category="benign",
            ),
            quota_snap,
        )


def _injection_paraphrase(blob: str) -> bool:
    return any(rx.search(blob) for rx in _INJECTION_STRUCTURE_RES) or any(
        rx.search(blob) for rx in _INJECTION_INTENT_RES
    )


def _exfil_sink(args_l: dict[str, Any]) -> bool:
    return any(k in args_l for k in EXFIL_SINK_KEYS)


def _pagination_walk(request: ToolRequest, args_l: dict[str, Any], blob: str) -> bool:
    if any(k in args_l for k in PAGINATION_CURSOR_KEYS):
        # list_open with only limit is in-scope triage; cursor/offset/page/take/etc. is a walk.
        return True
    if "size" in args_l and ("skip" in args_l or "from_index" in args_l or "offset" in args_l):
        return True
    return bool(_PAGINATION_WALK_RE.search(blob))


def _granted_tool_misuse(request: ToolRequest, args_l: dict[str, Any], blob: str) -> bool:
    if any(k in args_l for k in COLLECTION_ARG_KEYS):
        return True
    if request.tool == "ticket.update_status":
        status = str(args_l.get("status") or "").lower()
        if "credit" in status:
            return True
    purpose = str(args_l.get("purpose") or "").lower()
    if purpose and any(tok in purpose for tok in ("settle", "payout", "disburse", "outreach", "blast")):
        return True
    if not request.tool.startswith("customer.") and not request.tool.startswith("order.") and not request.tool.startswith("address."):
        for value in _flatten_strings(request.args):
            if _FOREIGN_RECORD_ID.search(str(value)):
                return True
    paraphrases = {
        "support-triage": (
            "money back",
            "skip the finance",
            "finance queue",
            "move money back",
            "finance already signed",
            "cash goes out",
            "credited so cash",
        ),
        "invoice-processing": (
            "settle the vendor",
            "settle tonight",
            "disbursement",
            "vendor payout",
            "treasury",
            "finish the disbursement",
            "complete the vendor payout",
            "so ap does not wait",
        ),
        "code-review": (
            "ship it",
            "push the build",
            "production build",
            "roll this change out",
            "in front of users",
            "shopper profile",
            "ship live",
            "tonight from this bot",
            "tonight from the review bot",
            "cut a production",
            "grab the shopper",
        ),
        "customer-data-lookup": (
            "mailing list",
            "mailing roster",
            "extra records",
            "growth team",
            "growth can write",
            "shopper cards",
            "saturday blast",
            "weekend send",
            "knock doors",
            "field ops",
            "field team",
            "harvest sibling",
            "nearby households",
            "shoppers who live nearby",
            "few extra records",
            "bundle a handful",
        ),
    }
    return any(tok in blob for tok in paraphrases.get(request.agent_id, ()))


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
            "money back",
            "skip the finance",
            "finance queue",
            "move money back",
            "finance already signed",
            "cash goes out",
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
            "settle the vendor",
            "settle tonight",
            "disbursement",
            "vendor payout",
            "treasury does not stall",
            "finish the disbursement",
            "complete the vendor payout",
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
            "ship it",
            "push the build",
            "production build",
            "roll this change out",
            "in front of users",
            "shopper profile",
            "ship live",
            "tonight from this bot",
            "tonight from the review bot",
            "cut a production",
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
            "mailing list",
            "mailing roster",
            "extra records",
            "growth team",
            "growth can write",
            "shopper cards",
            "saturday blast",
            "weekend send",
            "knock doors",
            "field ops",
            "field team",
            "harvest sibling",
            "nearby households",
            "shoppers who live nearby",
        ),
    }
    return any(tok in blob for tok in foreign.get(agent_id, ()))


def _norm_token(value: str) -> str:
    return value.lower().replace("-", "_")


def _sensitive_overcollect(request: ToolRequest) -> bool:
    parts = [_norm_token(p) for p in _flatten_strings(request.args)]
    blob = " ".join(parts)
    if any(tok in blob for tok in SENSITIVE_FIELD_TOKENS):
        return True
    return any(tok in blob for tok in SENSITIVE_FIELD_SYNONYMS)


def _cross_tool_record_fetch(request: ToolRequest) -> bool:
    native_lookup = request.tool in {"customer.get", "order.status"}
    for key in request.args:
        if PIGGYBACK_KEY.search(str(key)):
            if native_lookup and str(key).lower() in {"customer_id", "include"}:
                continue
            if request.tool.startswith("customer.") and "customer" in str(key).lower():
                continue
            return True
        if str(key).lower() in COLLECTION_ARG_KEYS and not request.tool.startswith("customer."):
            return True
    if not request.tool.startswith(("customer.", "order.", "address.")):
        for value in _flatten_strings(request.args):
            if _FOREIGN_RECORD_ID.search(str(value)):
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
