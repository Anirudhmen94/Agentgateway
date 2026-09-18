# Agent Trust Gateway scorecard — INDEX

> Split scorecards only. **Do not cite a blended detection rate as grok-4.6 or as model quality.**
> Fallback heuristic coverage is `out/scorecard.fallback.md`. grok-4.6 is `out/scorecard.grok.md`.

- Eval: `data/eval_set.jsonl` n=200
- Git commit: `a691f21`
- UTC run time: 2026-09-18T10:31:56Z
- Backend mix: `{'policy': 90, 'fallback': 110}`
- Cache: 110 hits / 0 misses

## Files

- `out/scorecard.fallback.md` — **model=fallback** (local heuristic; not grok)
- `out/scorecard.grok.md` — **model=grok** (xAI grok-4.6) or an explicit NOT RUN note

## grok-4.6

NOT RUN this session (`XAI_API_KEY` unset or no classifier rows used grok-4.6).
The fallback catch rate below is **not** grok detection quality.

- Policy-only slice: 90 rows, all gold-benign (no attack catch-rate; not a model score).
- Fallback slice catch rate: 100.0% on 110 classifier rows (**heuristic coverage only**).

Unsplit catch rate is omitted on purpose so it cannot be copy-pasted as model quality.
