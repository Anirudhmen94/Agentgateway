# Agent Trust Gateway — product spec

## Problem

AI agents are being granted tools that read tickets, post ledger drafts, comment on pull requests, and look up customer records. The model that plans the next tool call is not a reliable judge of whether that call still serves the job the agent was registered for. A compromised prompt, an over-eager planner, or a confused user can turn a granted tool into prompt injection, scope creep, data exfiltration, or credential misuse. The gateway sits between the agent and the tool runtime and returns a decision before the call executes.

## Decision model

For every tool call the gateway returns **allow**, **deny**, or **approve** (human-in-the-loop).

1. **Revocation.** A revoked agent is denied before any other rule.
2. **Deterministic policy.** Unknown tools, tools outside `allowed_tools`, rate limits, and explicit escalation tools are decided with no model and no network.
3. **Intent classifier.** Only `undecided` policy results are sent to grok-4.6 (or a local fallback). The model is asked one question: does this call serve the agent's declared purpose?
4. **Audit.** Every decision is appended as one JSON line with the deciding layer, latency, and model version when used.

## Threat categories

| Category | Meaning |
| --- | --- |
| `benign` | In-scope use of a granted tool for the registered purpose. |
| `prompt_injection` | Untrusted content tries to override instructions or tool choice. |
| `scope_creep` | A granted tool is used for a job the agent was not registered to do. |
| `data_exfiltration` | Sensitive records are copied out of allowed scope or to an untrusted sink. |
| `credential_misuse` | Secrets, tokens, or auth material are requested, replayed, or sent outbound. |

## Non-goals

Not a production control plane: no operator SSO, no durable database, no tool sandbox, no customer telemetry. Synthetic agents and synthetic requests only. No Radware code, documents, detection logic, or customer data.
