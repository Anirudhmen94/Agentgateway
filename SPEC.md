# Agent Trust Gateway — product spec

## Problem

AI agents are being granted tools that read tickets, post ledger drafts, comment on pull requests, and look up customer records. The model that plans the next tool call is not a reliable judge of whether that call still serves the job the agent was registered for. A compromised prompt, an over-eager planner, or a confused user can turn a granted tool into prompt injection, scope creep, data exfiltration, or credential misuse. The gateway sits between the agent and the tool runtime and returns a decision before the call executes.

## Decision model

For every tool call the gateway returns **allow**, **deny**, or **approve** (human-in-the-loop). Only **allow** authorizes execution. See [`docs/CONTRACT.md`](docs/CONTRACT.md). Fallback heuristic coverage is not grok-4.6 quality (`docs/MVP_BAR.md`).

1. **Revocation.** A revoked agent is denied before any other rule. The list is a JSON file (default `out/revocations.json`) and is honored after process restart.
2. **Deterministic policy.** Unknown tools, tools outside `allowed_tools`, rate limits, explicit escalation tools, sensitive over-collection, and cross-tool record piggybacks are decided with no model and no network. Escalation tools return `approve` / `pending_approval`, never allow.
3. **Intent classifier.** Only `undecided` policy results are sent to grok-4.6 (or a local fallback). The model is asked one question: does this call serve the agent's declared purpose? Cache keys hash canonical `agent_id`, `tool`, `args`, `session_context`, model, temperature, and prompt — not request id.
4. **Approve is not allow.** `approve` is `pending: true` and `execution_allowed: false` until an operator ACK. Recording a verdict without that hard gate is a fail.
5. **Audit.** Every decision is appended as one JSON line with the deciding layer, latency, execution gate, and model version when used.

Demo HTTP: mutating/control routes require `Authorization: Bearer <GATEWAY_TOKEN>` (`GATEWAY_TOKEN` from `.env`; optional alias `X-Gateway-Token`). The process listens on `127.0.0.1` unless `GATEWAY_HOST` or `--host` overrides it.

## Threat categories

| Category | Meaning |
| --- | --- |
| `benign` | In-scope use of a granted tool for the registered purpose. |
| `prompt_injection` | Untrusted content tries to override instructions or tool choice. |
| `scope_creep` | A granted tool is used for a job the agent was not registered to do. |
| `data_exfiltration` | Sensitive records are copied out of allowed scope or to an untrusted sink. |
| `credential_misuse` | Secrets, tokens, or auth material are requested, replayed, or sent outbound. |

## Non-goals

Not a full production control plane: no operator SSO, no tool sandbox, no customer telemetry. File-backed revocation is the v1 store, not a replicated database. Synthetic agents and synthetic requests only. No Radware code, documents, detection logic, or customer data.
