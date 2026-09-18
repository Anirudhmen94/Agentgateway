# Agent Trust Gateway

A control-plane **prototype** that sits in front of agent tool calls and returns **allow**, **deny**, or **approve** *before* anything executes. Verdict strings are not enough: a runtime must honor `pending` and `execution_allowed` ([`docs/CONTRACT.md`](docs/CONTRACT.md)).

This is synthetic demo data and a demo token. It is not a product, not SSO, not production-complete, and not Radware IP. Soft greens fail ([`docs/MVP_BAR.md`](docs/MVP_BAR.md)).

**On this branch (`3cae746`):** must-MVP contracts, per-agent **request-count** session quotas, and P2 FN-class **policy** closes. Evaluation order is **revoke → quota/policy → classifier**. After the QA re-score, `python3 -m pytest -q` is **79 passed, 0 failed** (no xfail). grok-4.6 is **NOT RUN** without `XAI_API_KEY` — do not cite heuristic coverage as LLM quality.

## Real vs stubbed

| Real (runs in this repo) | Stubbed / not built |
| --- | --- |
| Policy engine, revoke-first ordering, durable file revoke (`out/revocations.json`) | Operator SSO / identity |
| Per-agent request-count session quotas (durable `out/quotas.json`) | Distinct-record-id session quotas |
| P2 policy signals that deny known adversarial FN classes before grok | Novel paraphrases outside those detectors |
| HTTP API + live UI, SSE audit, JSONL + stdout decision logs | Operator ACK that later flips `pending` to allow |
| `Authorization: Bearer <GATEWAY_TOKEN>` from `.env` (401 if missing/wrong) | Tool sandbox / execution runtime |
| Approve hard gate: `pending: true`, `execution_allowed: false` | Production replicated revoke/quota store |
| `GET /health` (liveness) vs `GET /ready` (catalog + revoke + quota store) | Customer telemetry |
| Canonical classifier cache (not request id) | Measuring grok-4.6 without a key |
| grok-4.6 **when** `XAI_API_KEY` is set | Treating local fallback as grok-4.6 |

Without `XAI_API_KEY`, undecided rows use a **local heuristic** (`model=local-fallback`, `backend=fallback`). That is **not** grok-4.6 and **not** model quality. Split scorecards only: `out/scorecard.fallback.md` vs `out/scorecard.grok.md` (explicit `NOT RUN` if the API path did not run). Do not cite a blended or 97%-class heuristic rate as grok detection.

## Evaluation order (must)

On every `POST /v1/check` / `handle()`:

1. **Revoke** — `agent_revoked` before quota consume and before the model.
2. **Quota / deterministic policy** — request-count session quota, then keyword and P2 paraphrase/pagination/sink/purpose signals. Known FN-class rows in `data/eval_adversarial.jsonl` **must not allow**; almost all **deny in policy** (no classifier). `adv-006` is policy `undecided` then **local** classifier deny — still not grok.
3. **Classifier** — only `undecided` rows. grok-4.6 only with `XAI_API_KEY`; otherwise `local-fallback`.

Quota is never applied after a model call.

## Runtime contract (must)

| `verdict` | `pending` | `execution_allowed` | Runtime must |
| --- | --- | --- | --- |
| `allow` | `false` | `true` | Execute |
| `deny` | `false` | `false` | Do not execute |
| `approve` | **`true`** | **`false`** | **Hard stop.** Queue for a human. Never treat as allow. |

Primary auth on `POST /v1/check`, `POST /v1/revoke*`, and `GET /v1/audit/stream`:

```http
Authorization: Bearer <GATEWAY_TOKEN>
```

Token comes from `.env` only. Optional alias `X-Gateway-Token` exists; it does not replace the Bearer 401 contract. Empty `GATEWAY_TOKEN` is fail-closed (401).

Open probes (no token):

- `GET /health` → `{"status":"ok"}` (process up)
- `GET /ready` → `{"status":"ready","checks":{...}}` (agent catalog + revocation store + quota store readable; **not** the same as `/health`)

## FAIL_CLOSED vs fallback

From `.env` (default `FAIL_CLOSED=0`):

- **`0`** — if grok-4.6 is unavailable, run `local-fallback`. Label it `backend=fallback`. Demo still works. **Not grok quality.**
- **`1` / `true` / `yes` / `on`** — missing key or xAI failure **denies**. `model=fail-closed`. Does not pretend the heuristic is grok.

## Windows-first run (127.0.0.1:8000)

Secrets stay in `.env`. Copy the example; set `GATEWAY_TOKEN`. Leave `XAI_API_KEY` empty unless you intend to call grok-4.6.

```powershell
python -m pip install -r requirements.txt
copy .env.example .env
.\scripts\start.ps1
# other window:
curl.exe -sS http://127.0.0.1:8000/health
curl.exe -sS http://127.0.0.1:8000/ready
.\scripts\stop.ps1
```

Equivalent: `python -m src.app` (bind default **127.0.0.1**, not `0.0.0.0`). macOS/Linux: `make run` after `cp .env.example .env`.

Second laptop / tunnel: [`docs/SECOND_MACHINE.md`](docs/SECOND_MACHINE.md). Compose publishes **127.0.0.1:8000** on the host; inside the container `GATEWAY_HOST=0.0.0.0` is an explicit override.

Paste `GATEWAY_TOKEN` into the UI field (stored as `localStorage.atg_gateway_token`). Empty token blocks Check.

## 60-second demo (matches the UI strip)

Open `http://127.0.0.1:8000`. Watch the audit feed on the right.

1. **1 Benign** — in-scope `ticket.get`. Expect **allow**, `pending: false`, `execution_allowed: true` (green ALLOW — execution permitted).
2. **2 Scope creep** — granted tool, wrong job. Expect **deny**, `execution_allowed: false` (red DENY — do not execute).
3. **3 Approve / pending** — escalation `ticket.refund`. Expect **approve**, **`pending: true`**, **`execution_allowed: false`**, amber **PENDING — do not execute**. Not green. Not allow.
4. **4 Revoke & recheck** — revoke the selected agent, same tool. Expect **deny** / `agent_revoked`. Restore with **Restore agent**.

A worker that executes on any non-deny string is non-compliant even though the API gate is correct.

## Measure (no xfail greens)

```bash
python -m pytest -q    # or: make test   → 79 passed at 3cae746 (re-verified)
make eval              # split scorecards under out/; grok file is NOT RUN without XAI_API_KEY
```

If pytest is red, the MVP is red. Catching the current adversarial file with policy/heuristic is **not** a ship signal and **not** grok quality.

Remaining **medium** gaps (not closed): novel paraphrases outside the detectors; request-count quota ≠ distinct record ids; runtimes that ignore `pending`; grok-4.6 not measured. Details: [`docs/RED_TEAM.md`](docs/RED_TEAM.md). Labels: [`data/PROVENANCE.md`](data/PROVENANCE.md).
