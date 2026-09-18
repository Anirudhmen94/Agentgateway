"""Known FN classes from docs/MVP_BAR.md and docs/RED_TEAM.md.

Closed classes must stay closed. Open paraphrase/injection/bulk classes
must not `allow` — these fail loud (no xfail) until policy or grok catches them.
"""

from __future__ import annotations

import json

import pytest

from src.gateway import clear_revocations, handle
from src.policy import PolicyEngine, load_agents
from tests.helpers import ADVERSARIAL_SET, load_eval_row

CLOSED_EVAL_FNS = ("eval-142", "eval-176", "eval-182")
OPEN_ADVERSARIAL_PATTERNS = {
    "paraphrase_scope",
    "paraphrase_injection",
    "pagination_exfil",
    "paraphrase_exfil",
    "granted_tool_misuse",
}


def _adv_rows() -> list[dict]:
    return [json.loads(line) for line in ADVERSARIAL_SET.read_text().splitlines() if line.strip()]


@pytest.mark.parametrize("eid", CLOSED_EVAL_FNS)
def test_closed_fn_class_eval_142_176_182_must_not_allow(eid):
    clear_revocations()
    row = load_eval_row(eid)
    policy = PolicyEngine(load_agents(), enforce_rate_limit=False)
    decision = handle(row, use_cache=False, audit=False, policy=policy)
    assert decision.verdict != "allow", (
        f"{eid} gold={row['label']} allowed again "
        f"(layer={decision.deciding_layer} rule={decision.rule_id})."
    )
    assert decision.execution_allowed is False


@pytest.mark.parametrize("pattern", sorted(OPEN_ADVERSARIAL_PATTERNS))
def test_open_fn_class_by_pattern_must_not_allow(pattern):
    """Each known FN class fails on its own (no xfail, no blended green)."""
    clear_revocations()
    policy = PolicyEngine(load_agents(), enforce_rate_limit=False)
    rows = [r for r in _adv_rows() if r["pattern"] == pattern]
    assert rows, f"adversarial pattern {pattern} missing"
    allowed: list[str] = []
    for row in rows:
        d = handle(row, use_cache=False, audit=False, policy=policy)
        if d.verdict == "allow":
            allowed.append(
                f"{row['id']} gold={row['label']} pattern={row['pattern']} "
                f"rule={d.rule_id} layer={d.deciding_layer}"
            )
    assert not allowed, (
        f"FN class {pattern} still allows (keyword/policy miss). "
        "This is a P1 fail, not a soft green:\n" + "\n".join(allowed)
    )


def test_open_fn_class_paraphrase_injection_bulk_must_not_allow():
    """RED_TEAM / MVP_BAR open class: synonym attacks must not clean_allow.

    Fails loud with the full allow list. Do not xfail.
    """
    clear_revocations()
    policy = PolicyEngine(load_agents(), enforce_rate_limit=False)
    allowed: list[str] = []
    rows = [r for r in _adv_rows() if r["pattern"] in OPEN_ADVERSARIAL_PATTERNS]
    assert rows, "adversarial paraphrase/bulk rows missing"
    for row in rows:
        d = handle(row, use_cache=False, audit=False, policy=policy)
        if d.verdict == "allow":
            allowed.append(
                f"{row['id']} gold={row['label']} pattern={row['pattern']} "
                f"rule={d.rule_id} layer={d.deciding_layer}"
            )
    assert not allowed, (
        "FN class still allows (keyword/policy miss). "
        "This is a P1 fail, not a soft green:\n" + "\n".join(allowed)
    )
