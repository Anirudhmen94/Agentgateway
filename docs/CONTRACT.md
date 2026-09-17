# Agent Trust Gateway — runtime contract (v1)

This is the contract a tool runtime must honor. Verdict strings alone are not enough.

## Execution gate

| `verdict` | `state` | `execution_allowed` | Runtime must |
| --- | --- | --- | --- |
| `allow` | `allowed` | `true` | Execute the tool call. |
| `deny` | `denied` | `false` | Do not execute. |
| `approve` | `pending_approval` | `false` | **Hard stop.** Do not execute. Queue for a human. Never treat as allow. |

`execution_allowed` is derived only from `verdict == "allow"`. Escalate tools (`policy` rule `escalation_tool`) and classifier `approve` are the same gate: **pending, not proceed.** There is no soft-allow and no silent continue.

A runtime that executes on `approve` is non-compliant, even if a human later would have said yes.

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

Open (demo UI): `GET /`, `GET /health`, `GET /v1/agents`.

## Bind address

Process default is **`127.0.0.1`**. Override with `GATEWAY_HOST` or `--host`. Compose sets `0.0.0.0` inside the container so published ports work; that is an explicit override, not the process default.

## Classifier cache

Cache keys hash canonical `agent_id`, `tool`, `args`, `session_context`, plus model name, temperature, and system prompt. Request id is **not** the key. Same id with different args is a miss; different ids with the same canonical fields may hit.
