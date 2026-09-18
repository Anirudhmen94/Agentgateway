from src.gateway import clear_revocations, handle, revoke
from src.policy import PolicyEngine, load_agents


def test_policy_short_circuit_skips_classifier():
    called = {"n": 0}

    def boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("classifier must not run")

    decision = handle(
        {
            "id": "gw-1",
            "agent_id": "support-triage",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1042"},
            "session_context": "Open the ticket and classify severity.",
        },
        classify_fn=boom,
        policy=PolicyEngine(load_agents()),
        audit=False,
    )
    assert decision.verdict == "allow"
    assert decision.deciding_layer == "policy"
    assert called["n"] == 0


def test_revoked_agent_denied_first():
    clear_revocations()
    revoke("support-triage")
    called = {"n": 0}

    def boom(*_args, **_kwargs):
        called["n"] += 1
        raise AssertionError("classifier must not run")

    def no_policy(_req):
        raise AssertionError("policy must not run for revoked agents")

    class Stub:
        evaluate = staticmethod(no_policy)

    decision = handle(
        {
            "id": "gw-2",
            "agent_id": "support-triage",
            "tool": "ticket.get",
            "args": {"ticket_id": "TCK-1"},
            "session_context": "anything",
        },
        classify_fn=boom,
        policy=Stub(),
        audit=False,
    )
    assert decision.verdict == "deny"
    assert decision.rule_id == "agent_revoked"
    assert decision.execution_allowed is False
    assert called["n"] == 0
    clear_revocations()
