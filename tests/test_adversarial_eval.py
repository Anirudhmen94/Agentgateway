"""Adversarial eval corpus: human labels, synthetic bytes, keyword misses."""

from __future__ import annotations

import json
from collections import Counter

from src.policy import PolicyEngine, load_agents
from tests.helpers import ADVERSARIAL_SET, ROOT

REQUIRED_PATTERNS = {
    "paraphrase_scope",
    "paraphrase_injection",
    "pagination_exfil",
    "approve_ignored_by_runtime",
}


def _rows() -> list[dict]:
    assert ADVERSARIAL_SET.exists(), "data/eval_adversarial.jsonl is required"
    rows = [json.loads(line) for line in ADVERSARIAL_SET.read_text().splitlines() if line.strip()]
    assert rows, "adversarial eval is empty"
    return rows


def test_adversarial_file_provenance_and_patterns():
    rows = _rows()
    patterns = Counter(r["pattern"] for r in rows)
    for name in REQUIRED_PATTERNS:
        assert patterns[name] >= 1, f"missing pattern {name}"
    for row in rows:
        assert row["label_provenance"] == "human"
        assert row["data_provenance"] == "synthetic"
        assert row["label"] in {
            "prompt_injection",
            "scope_creep",
            "data_exfiltration",
            "credential_misuse",
        }
        assert row["id"].startswith("adv-")
    provenance = (ROOT / "data" / "PROVENANCE.md").read_text()
    assert "human-authored" in provenance.lower() or "human" in provenance.lower()
    assert "eval_adversarial.jsonl" in provenance


def test_adversarial_paraphrases_miss_keyword_policy():
    """Rows tagged paraphrase_* / pagination_* should not trip the marker lists.

    approve_ignored_by_runtime uses escalation tools (policy approve), which is
    the point of that slice — excluded here.
    """
    pol = PolicyEngine(load_agents(), enforce_rate_limit=False)
    rows = [
        r
        for r in _rows()
        if r["pattern"] in {"paraphrase_scope", "paraphrase_injection", "pagination_exfil", "paraphrase_exfil"}
    ]
    missed = []
    for row in rows:
        d = pol.evaluate(row)
        if d.verdict == "allow" and d.rule_id == "clean_allow":
            missed.append(row["id"])
    assert missed, "expected keyword-miss paraphrases; regenerate if policy swallowed them"
    # Document the miss set; catching some is fine, catching none of the corpus is the design.
    assert len(missed) >= 20, f"too few keyword misses remain: {missed}"


def test_adversarial_approve_ignored_rows_are_pending_not_allow():
    """approve_ignored_by_runtime rows must hard-gate; never soft-allow."""
    from src.gateway import clear_revocations, handle

    clear_revocations()
    policy = PolicyEngine(load_agents(), enforce_rate_limit=False)
    rows = [r for r in _rows() if r["pattern"] == "approve_ignored_by_runtime"]
    assert rows
    for row in rows:
        d = handle(row, use_cache=False, audit=False, policy=policy)
        assert d.verdict == "approve", row["id"]
        assert d.verdict != "allow"
        assert d.pending is True
        assert d.execution_allowed is False
