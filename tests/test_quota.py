"""Per-agent session quotas: unit + API contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from fastapi.testclient import TestClient

from src.app import app
from src.gateway import handle, reload_quota_store
from src.policy import PolicyEngine, load_agents
from src.quota import QuotaStore, get_store
from tests.conftest import TEST_TOKEN

ROOT = Path(__file__).resolve().parent.parent


def _agents_with_quota(limit: int, window: int = 3600) -> dict:
    agents = load_agents()
    row = dict(agents["support-triage"])
    row["quota_limit"] = limit
    row["quota_window_seconds"] = window
    row["rate_limit_per_min"] = 10_000
    agents["support-triage"] = row
    return agents


def _benign(i: int = 0) -> dict:
    return {
        "id": f"quota-{i}",
        "agent_id": "support-triage",
        "tool": "ticket.get",
        "args": {"ticket_id": f"TCK-{i}"},
        "session_context": "Open the ticket and classify severity.",
        "session_id": "sess-quota",
    }


def test_quota_under_at_over():
    pol = PolicyEngine(_agents_with_quota(3))
    under = pol.evaluate(_benign(1))
    assert under.verdict == "allow"
    assert under.rule_id == "clean_allow"
    assert under.quota_limit == 3
    assert under.quota_remaining == 2

    at_fill = pol.evaluate(_benign(2))
    assert at_fill.verdict == "allow"
    assert at_fill.quota_remaining == 1

    at_cap = pol.evaluate(_benign(3))
    assert at_cap.verdict == "allow"
    assert at_cap.quota_remaining == 0

    over = pol.evaluate(_benign(4))
    assert over.verdict == "deny"
    assert over.rule_id == "quota_exceeded"
    assert over.quota_remaining == 0
    assert "quota" in (over.reason or "").lower()
    assert over.quota_limit == 3


def test_unknown_agent_does_not_consume_quota():
    pol = PolicyEngine(_agents_with_quota(1))
    denied = pol.evaluate(
        {
            "id": "unk-1",
            "agent_id": "not-a-real-agent",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1"},
            "session_context": "anything",
        }
    )
    assert denied.verdict == "deny"
    assert denied.rule_id == "unknown_agent"
    assert denied.quota_limit is None
    still = pol.evaluate(_benign(1))
    assert still.verdict == "allow"
    assert still.quota_remaining == 0
    blocked = pol.evaluate(_benign(2))
    assert blocked.rule_id == "quota_exceeded"


def test_concurrent_burst_does_not_exceed_limit():
    store = get_store()
    store.clear()
    limit = 5
    pol = PolicyEngine(_agents_with_quota(limit))

    def one(i: int):
        return pol.evaluate(_benign(i))

    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = [pool.submit(one, i) for i in range(24)]
        results = [f.result() for f in as_completed(futs)]

    allowed = [d for d in results if d.verdict == "allow"]
    denied = [d for d in results if d.rule_id == "quota_exceeded"]
    assert len(allowed) == limit
    assert len(denied) == 24 - limit
    assert all(d.verdict == "deny" for d in denied)


def test_quota_survives_new_process(tmp_path, monkeypatch):
    store = tmp_path / "quotas.json"
    monkeypatch.setenv("QUOTA_STORE_PATH", str(store))
    env = os.environ.copy()
    env["QUOTA_STORE_PATH"] = str(store)
    py = sys.executable
    first = subprocess.run(
        [
            py,
            "-c",
            "from src.gateway import reload_quota_store\n"
            "from src.quota import get_store\n"
            "reload_quota_store()\n"
            "snap = get_store().consume('support-triage', 2, 3600)\n"
            "assert snap.allowed and snap.remaining == 1\n"
            "print('quota-write-ok')\n",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert first.returncode == 0, first.stderr
    second = subprocess.run(
        [
            py,
            "-c",
            "from src.gateway import reload_quota_store\n"
            "from src.quota import get_store\n"
            "reload_quota_store()\n"
            "snap = get_store().consume('support-triage', 2, 3600)\n"
            "assert snap.allowed and snap.remaining == 0\n"
            "over = get_store().consume('support-triage', 2, 3600)\n"
            "assert over.allowed is False\n"
            "print('quota-durable-ok')\n",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert second.returncode == 0, (
        "Quota counts did not survive a new process. "
        f"stdout={second.stdout!r} stderr={second.stderr!r}."
    )
    reload_quota_store()


def test_api_under_at_over_and_unknown_agent(monkeypatch, auth_headers):
    engine = PolicyEngine(_agents_with_quota(2))
    monkeypatch.setattr("src.gateway.get_engine", lambda: engine)
    client = TestClient(app)
    first = client.post("/v1/check", headers=auth_headers, json=_benign(1))
    assert first.status_code == 200
    assert first.json()["verdict"] == "allow"
    assert first.json()["quota_remaining"] == 1
    assert first.json()["quota_limit"] == 2
    assert first.json()["execution_allowed"] is True

    at_cap = client.post("/v1/check", headers=auth_headers, json=_benign(2))
    assert at_cap.json()["verdict"] == "allow"
    assert at_cap.json()["quota_remaining"] == 0

    over = client.post("/v1/check", headers=auth_headers, json=_benign(3))
    assert over.status_code == 200
    body = over.json()
    assert body["verdict"] == "deny"
    assert body["rule_id"] == "quota_exceeded"
    assert body["pending"] is False
    assert body["execution_allowed"] is False
    assert body["quota_remaining"] == 0
    assert "quota" in (body["reason"] or "").lower()

    unknown = client.post(
        "/v1/check",
        headers=auth_headers,
        json={
            "agent_id": "ghost-bot",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1"},
            "session_context": "nope",
        },
    )
    assert unknown.status_code == 200
    unk = unknown.json()
    assert unk["verdict"] == "deny"
    assert unk["rule_id"] == "unknown_agent"
    assert unk["execution_allowed"] is False
    assert "quota_remaining" not in unk


def test_api_audit_includes_quota_remaining(monkeypatch, tmp_path, auth_headers):
    engine = PolicyEngine(_agents_with_quota(1))
    monkeypatch.setattr("src.gateway.get_engine", lambda: engine)
    monkeypatch.setattr("src.gateway.AUDIT_PATH", tmp_path / "audit.jsonl")
    client = TestClient(app)
    res = client.post("/v1/check", headers=auth_headers, json=_benign(1))
    assert res.json()["quota_remaining"] == 0
    over = client.post("/v1/check", headers=auth_headers, json=_benign(2))
    assert over.json()["rule_id"] == "quota_exceeded"
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").strip().splitlines()
    last = json.loads(lines[-1])
    assert last["rule_id"] == "quota_exceeded"
    assert last["verdict"] == "deny"
    assert last["quota_remaining"] == 0
    assert last["quota_limit"] == 1


def test_api_concurrent_burst(monkeypatch, auth_headers):
    engine = PolicyEngine(_agents_with_quota(4))
    monkeypatch.setattr("src.gateway.get_engine", lambda: engine)
    client = TestClient(app)

    def one(i: int):
        return client.post("/v1/check", headers=auth_headers, json=_benign(100 + i))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(one, i) for i in range(12)]
        bodies = [f.result().json() for f in as_completed(futs)]

    allowed = [b for b in bodies if b["verdict"] == "allow"]
    denied = [b for b in bodies if b.get("rule_id") == "quota_exceeded"]
    assert len(allowed) == 4
    assert len(denied) == 8
    assert all(b["execution_allowed"] is False and b["pending"] is False for b in denied)


def test_quota_store_corrupt_file_is_fail_closed(tmp_path):
    path = tmp_path / "bad-quotas.json"
    path.write_text("{not-json", encoding="utf-8")
    store = QuotaStore(path)
    try:
        store.all()
        raised = False
    except RuntimeError:
        raised = True
    assert raised
