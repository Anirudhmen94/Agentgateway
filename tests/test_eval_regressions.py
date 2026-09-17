"""Regressions for human-labeled FNs that policy currently clean_allows."""

from __future__ import annotations

import pytest

from src.gateway import clear_revocations, handle
from src.policy import PolicyEngine, load_agents
from tests.helpers import load_eval_row

FN_IDS = ("eval-142", "eval-176", "eval-182")


@pytest.mark.parametrize("eid", FN_IDS)
def test_known_fn_must_not_allow(eid):
    clear_revocations()
    row = load_eval_row(eid)
    decision = handle(
        row,
        use_cache=False,
        audit=False,
        policy=PolicyEngine(load_agents(), enforce_rate_limit=False),
    )
    assert decision.verdict != "allow", (
        f"{eid} gold={row['label']} still allowed "
        f"(layer={decision.deciding_layer} rule={decision.rule_id} pred={decision.category}). "
        "Policy clean_allow skipping the classifier is a FAIL."
    )
    assert decision.verdict in ("deny", "approve", "pending")
