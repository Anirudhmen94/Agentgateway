# Agent Trust Gateway

Agents get tools. Tools do damage when the call no longer matches the job the agent was hired to do. This gateway sits in front of those calls and answers before anything executes.

## What it does

- Every request returns **allow**, **deny**, or **approve**, plus an execution gate: only `allow` has `execution_allowed=true`. Approve/escalate responses include **`pending: true`** and must not run. Contract: [`docs/CONTRACT.md`](docs/CONTRACT.md).
- Revocation is checked first (durable file store under `out/revocations.json`).
- A deterministic policy layer decides unknown tools, allow-lists, rate limits, escalation tools, and obvious over-collection with no model and no network.
- Only leftovers go to **grok-4.6** (temperature 0, JSON schema). One question: does this call serve the registered purpose?
- Five labels: benign, prompt injection, scope creep, data exfiltration, credential misuse.
- Every decision is one JSON line in `out/audit.jsonl`.

## Results

Scorecards are **split**. Do not read fallback heuristic coverage as grok-4.6 quality.

- `out/scorecard.md` — index only (no blended model grade)
- `out/scorecard.fallback.md` — **model=fallback** (local heuristic; not grok)
- `out/scorecard.grok.md` — **model=grok** or an explicit `NOT RUN` if `XAI_API_KEY` is unset

The 200-row set is human-labeled synthetic data (`data/PROVENANCE.md`). `data/eval_adversarial.jsonl` holds paraphrases and pagination walks that keyword lists miss. Pass/fail: `docs/MVP_BAR.md`. Runtime contract: `docs/CONTRACT.md`.

Pin `grok-4.6` with `XAI_API_KEY`. Re-run `make eval` after a prompt change. Classifier cache keys hash canonical request fields (not request id).

## Architecture

Policy is cheap and boring on purpose. Most clean, in-scope calls never pay for a token. The model only sees the ambiguous granted-tool cases that policy cannot close. That split is the cost and latency story; the scorecard prints the percentage decided by each layer.

## What is real / stubbed

Real: policy engine, gateway ordering, JSONL audit, eval harness, `POST /v1/check`, SSE audit feed, demo token auth, loopback bind default, durable revocation, approve as a hard pending gate, canonical classifier cache. Stubbed: operator SSO / out-of-band ACK UI (the API already refuses to treat approve as allow). Classifier calls xAI when `XAI_API_KEY` is set; otherwise a local heuristic fallback so the demo still runs.

## What I would build next

1. Session-level quotas on distinct record ids (red team: paging around bulk limits).
2. Operator ACK workflow that flips `pending_approval` to allow only after an authenticated human.
3. Fail-closed classifier mode when the hosted model is required and the key is missing.

## What I got wrong

Keyword policy still misses paraphrased scope creep and injection that avoids the marker list — `docs/RED_TEAM.md` and `data/eval_adversarial.jsonl` lead with those. Approve-as-lock is in the API contract; a non-compliant runtime can still ignore it.

Synthetic data only. Control-plane prototype, not a product. No Radware IP.

---

## Run the live demo

```bash
python3 -m pip install -r requirements.txt
cp .env.example .env   # set GATEWAY_TOKEN; optional XAI_API_KEY for grok-4.6
make run               # http://127.0.0.1:8000 (default bind, not 0.0.0.0)
```

Override bind with `GATEWAY_HOST` / `GATEWAY_PORT` or `python -m src.app --host 0.0.0.0 --port 8000`.

Paste `GATEWAY_TOKEN` into the UI. Mutating routes (`POST /v1/check`, `/v1/revoke*`, audit stream) require:

```http
Authorization: Bearer <GATEWAY_TOKEN>
```

Optional alias: `X-Gateway-Token: <GATEWAY_TOKEN>`. Missing or wrong token → **401**.

Without an xAI key, the UI still returns decisions in real time (policy + local fallback). With a key, undecided rows call grok-4.6 at `https://api.x.ai/v1`.

Demo path: sample **benign** (policy allow, execution allowed) → sample **scope creep** (deny, blocked) → escalation tool (approve, **pending — do not execute**) → revoke the agent and resubmit → watch the audit feed.

```bash
make test              # policy + gateway + API + P0 + MVP bar (no xfail greens)
python3 -m src.eval_run --limit 20
make eval              # 200 + adversarial; split fallback vs grok scorecards
docker compose up --build   # Compose sets GATEWAY_HOST=0.0.0.0 inside the container
```
