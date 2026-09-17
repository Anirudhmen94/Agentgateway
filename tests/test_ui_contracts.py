"""Product/UX contracts for the demo page — no live browser required."""

from pathlib import Path

UI = Path("src/static/index.html").read_text(encoding="utf-8")


def test_ui_never_soft_maps_approve_to_allow():
    assert "PENDING — do not execute" in UI
    assert "card-pending" in UI
    assert "isHardPending" in UI
    assert "isAllowCard" in UI
    assert "if (isHardPending(data)) return false" in UI
    assert "approve→allow" not in UI
    assert 'verdict === "approve"' in UI
    assert "pending === true" in UI or "data.pending === true" in UI


def test_ui_auth_bearer_and_localstorage_key():
    assert 'TOKEN_KEY = "atg_gateway_token"' in UI
    assert 'headers["Authorization"] = "Bearer " + tok' in UI
    assert "GATEWAY_TOKEN is required" in UI
    assert "paste GATEWAY_TOKEN" in UI
    assert "401" in UI


def test_ui_loading_empty_and_error_states():
    assert "Checking…" in UI
    assert "setCheckBusy" in UI
    assert "No decision yet" in UI
    assert "Cannot check" in UI
    assert "Args must be valid JSON" in UI


def test_ui_samples_human_labels_and_demo_strip():
    assert 'benign: "Benign"' in UI
    assert 'scope_creep: "Scope creep"' in UI
    assert "Approve / pending" in UI
    assert "1 Benign" in UI
    assert "2 Scope creep" in UI
    assert "3 Approve / pending" in UI
    assert "4 Revoke" in UI
    assert "ticket.refund" in UI
    assert "applyAndCheck" in UI


def test_ui_audit_shows_reason_and_confidence():
    assert "row.reason" in UI
    assert "row.confidence" in UI
    assert "confidence" in UI
    assert 'addEventListener("audit"' in UI


def test_ui_keeps_dark_theme_tokens():
    assert "--allow: #7dba6a" in UI
    assert "--deny: #e06c5d" in UI
    assert "--approve: #e0b05c" in UI
    assert "Radware" not in UI
