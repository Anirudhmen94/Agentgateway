from fastapi.testclient import TestClient

from src.app import app
from src.gateway import clear_revocations


def test_health_and_check_benign_and_scope_creep(auth_headers):
    clear_revocations()
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "ok"
    ready = client.get("/ready")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    page = client.get("/")
    assert page.status_code == 200
    assert "Agent Trust Gateway" in page.text

    benign = client.post(
        "/v1/check",
        headers=auth_headers,
        json={
            "agent_id": "support-triage",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1042"},
            "session_context": "Open the ticket and classify severity.",
            "session_id": "s1",
        },
    )
    assert benign.status_code == 200
    body = benign.json()
    assert body["verdict"] == "allow"
    assert body["execution_allowed"] is True
    assert body["state"] == "allowed"
    assert body["pending"] is False
    assert body["category"] == "benign"
    assert body["deciding_layer"] == "policy"

    creep = client.post(
        "/v1/check",
        headers=auth_headers,
        json={
            "agent_id": "customer-data-lookup",
            "tool": "customer.get",
            "args": {"customer_id": "CUS-6601", "segment": "newsletter_opt_in"},
            "session_context": "Marketing asked for this lookup to seed a campaign.",
            "session_id": "s2",
        },
    )
    assert creep.status_code == 200
    creep_body = creep.json()
    assert creep_body["verdict"] in ("deny", "approve")
    assert creep_body["execution_allowed"] is False
    assert creep_body["category"] in ("scope_creep", "data_exfiltration", "prompt_injection")

    agents = client.get("/v1/agents").json()["agents"]
    assert len(agents) == 4

    revoked = client.post("/v1/revoke", headers=auth_headers, json={"agent_id": "support-triage"})
    assert revoked.json()["revoked"] is True
    denied = client.post(
        "/v1/check",
        headers=auth_headers,
        json={
            "agent_id": "support-triage",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1"},
            "session_context": "should be blocked",
        },
    )
    assert denied.json()["verdict"] == "deny"
    assert denied.json()["rule_id"] == "agent_revoked"
    assert denied.json()["execution_allowed"] is False
    client.post("/v1/unrevoke", headers=auth_headers, json={"agent_id": "support-triage"})
    clear_revocations()
