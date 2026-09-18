# Agent Trust Gateway — runtime contract (v1)

This is the contract a tool runtime must honor. Verdict strings alone are not enough. This is a **prototype**, not a production-complete control plane.

## Evaluation order

On `POST /v1/check` / `handle()`: **revoke → quota/policy → classifier**.

1. **Revoke.** A revoked agent is `agent_revoked` before quota consume and before any model call. Revoke does not consume a quota slot.
2. **Quota / deterministic policy.** Request-count session quota, then policy signals (including P2 FN-class paraphrase/pagination/sink/purpose denies). Quota is never applied after a model call. Unknown agents are `unknown_agent` and do not consume quota.
3. **Classifier.** Only policy `undecided` rows. grok-4.6 only when `XAI_API_KEY` is set; otherwise `local-fallback`. That fallback is **not** grok quality.

Known adversarial FN-class rows must not `allow`. They are denied in this path **before grok** (policy deny; `adv-006` is policy `undecided` then local classifier deny).

## Execution gate

| `verdict` | `state` | `pending` | `execution_allowed` | Runtime must |
| --- | --- | --- | --- | --- |
| `allow` | `allowed` | `false` | `true` | Execute the tool call. |
| `deny` | `denied` | `false` | `false` | Do not execute. |
| `approve` | `pending_approval` | **`true`** | `false` | **Hard stop.** Do not execute. Queue for a human. Never treat as allow. |

`pending` is `true` if and only if `verdict` is `approve` (escalation / human gate). It is never mapped to allow. `execution_allowed` is true only for `allow`.

Audit SSE events (`event: audit`) include `reason` and `confidence` when those values exist on the decision. `confidence` is omitted as JSON `null` only when the gateway genuinely has no score — it is never invented.

A runtime that executes on `approve` is non-compliant, even if a human later would have said yes. The gateway cannot stop a worker that ignores `pending`.

## HTTP demo API

Mutating / control routes require `GATEWAY_TOKEN` from `.env`:

- `POST /v1/check`
- `POST /v1/revoke`
- `POST /v1/unrevoke`
- `POST /v1/revoke/clear`
- `GET /v1/audit/stream` (header or `?token=`)

Primary header (required contract):

```http
Authorization: Bearer <GATEWAY_TOKEN>
```

`GATEWAY_TOKEN` is read from `.env` only. Optional alias: `X-Gateway-Token: <GATEWAY_TOKEN>`. SSE clients that cannot set headers may pass `?token=` (same value). Missing or wrong token → **401**. An empty `GATEWAY_TOKEN` is fail-closed (also 401).

Open (demo UI): `GET /`, `GET /health` (liveness), `GET /ready` (readiness: agent catalog + revocation store + quota store), `GET /v1/agents`.

## Per-agent session quotas

Each registered agent has `quota_limit` in `config/agents.yaml` (plus `rate_limit_per_min` for the in-process 60s burst cap). The sliding window is `QUOTA_WINDOW_SECONDS` from `.env` (default 3600), or per-agent `quota_window_seconds` when set.

Counts are **request totals per `agent_id`**, not distinct record ids. Walking unique ids under the request cap with bland session text is still possible. The store is **file-backed** (`out/quotas.json` or `QUOTA_STORE_PATH`) with the same atomic JSON pattern as revoke, so a demo process restart keeps the window. It is not in-memory-only. It is not a replicated production store.

On exceed: `verdict=deny`, `rule_id=quota_exceeded`, `pending=false`, `execution_allowed=false`. Never silent drop, never approve. HTTP `POST /v1/check` and audit JSONL include `quota_limit`, `quota_remaining`, `quota_window_seconds`, and `quota_hit` (`true` only on `quota_exceeded`) when a quota was applied.

A **revoked** agent is `agent_revoked` even when it is under quota.

## Bind address

Process default is **`127.0.0.1`**. Override with `GATEWAY_HOST` or `--host`. Compose sets `0.0.0.0` inside the container so published ports work; the host mapping is `127.0.0.1:8000` by default.

## Classifier cache

Cache keys hash canonical `agent_id`, `tool`, `args`, `session_context`, plus model name, temperature, and system prompt. Request id is **not** the key. Same id with different args is a miss; different ids with the same canonical fields may hit.

## Fail-closed vs local fallback

`FAIL_CLOSED` (from `.env`): default `0`. When `1` / `true` / `yes` / `on`, a missing xAI key or a failed grok-4.6 call **denies** instead of running the local heuristic. The classifier `model` field is `fail-closed` or `local-fallback` — never grok-4.6. Audit JSONL and stdout `gateway.decision` lines include `backend` (`policy` | `fallback` | `grok` | `fail-closed`).

Split scorecards: `out/scorecard.fallback.md` vs `out/scorecard.grok.md`. Without `XAI_API_KEY`, grok is **NOT RUN**. Do not cite fallback or policy catch as LLM quality.
