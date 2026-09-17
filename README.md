# Agent Trust Gateway

Agents get tools. Tools do damage when the call no longer matches the job the agent was hired to do. This gateway sits in front of those calls and answers before anything executes.

## What it does

- Every request returns **allow**, **deny**, or **approve**.
- Revocation is checked first.
- A deterministic policy layer decides unknown tools, allow-lists, rate limits, and escalation tools with no model and no network.
- Only leftovers go to **grok-4.6** (temperature 0, JSON schema). One question: does this call serve the registered purpose?
- Five labels: benign, prompt injection, scope creep, data exfiltration, credential misuse.
- Every decision is one JSON line in `out/audit.jsonl`.

## Results

`out/scorecard.md` on the 200-row synthetic set, local fallback (`grok-4.6-local-fallback`, temperature 0):

- Detection rate **97.3%** (non-benign deny or approve)
- False-positive rate **0.0%**
- Policy decided **46.5%** of rows; the classifier **53.5%** — the eval set is attack-heavy on purpose. Clean triage lookups still die in policy in under a millisecond.

Pin `grok-4.6` with `XAI_API_KEY`. Re-run `make eval` after a prompt change; responses cache under `.cache/classifier/`.

## Architecture

Policy is cheap and boring on purpose. Most clean, in-scope calls never pay for a token. The model only sees the ambiguous granted-tool cases that policy cannot close. That split is the cost and latency story; the scorecard prints the percentage decided by each layer.

## What is real / stubbed

Real: policy engine, gateway ordering, audit log, eval harness, live `POST /v1/check`, SSE audit feed, revoke. Stubbed: human approval (recorded, not gated), auth, durable revocation store. Classifier calls xAI when `XAI_API_KEY` is set; otherwise a local heuristic fallback so the demo still runs.

## What I would build next

1. Session-level quotas on distinct record ids (red team: paging around bulk limits).
2. Hard-block `approve` until an operator ACK.
3. Hash the full request into the classifier cache key so live replays cannot poison eval ids.

## What I got wrong

Keyword policy still misses paraphrased scope creep and injection that avoids the marker list — the red-team file leads with those. I also treated `approve` as a decision instead of a lock, which is a false sense of control if a runtime ignores it.

Synthetic data only. Prototype to think through the control, not a product.

---

## Run the live demo

```bash
python3 -m pip install -r requirements.txt
cp .env.example .env   # optional: set XAI_API_KEY for grok-4.6
make run               # http://127.0.0.1:8000
```

Without a key, the UI still returns decisions in real time (policy + local fallback). With a key, undecided rows call grok-4.6 at `https://api.x.ai/v1`.

Demo path: sample **benign** (policy allow) → sample **scope creep** (model/heuristic deny) → revoke the agent and resubmit → watch the audit feed.

```bash
make test              # policy + gateway + API smoke
python3 -m src.eval_run --limit 20
make eval              # full 200, writes out/scorecard.md
docker compose up --build
```
