# Agent Trust Gateway scorecard — INDEX

> Split scorecards only. **Do not cite a blended detection rate as grok-4.6 or as model quality.**
> Fallback heuristic coverage is `out/scorecard.fallback.md`. grok-4.6 is `out/scorecard.grok.md`.

- Eval: `data/eval_adversarial.jsonl` n=49
- Git commit: `85a2c34`
- UTC run time: 2026-09-18T12:55:32Z
- Backend mix: `{'policy': 48, 'fallback': 1}`
- Cache: 0 hits / 1 misses

## Files

- `out/scorecard.fallback.md` — **model=fallback** (local heuristic; not grok)
- `out/scorecard.grok.md` — **model=grok** (xAI grok-4.6) or an explicit NOT RUN note

## grok-4.6

NOT RUN this session (`XAI_API_KEY` unset or no classifier rows used grok-4.6).
The fallback catch rate below is **not** grok detection quality.

- Policy-only slice catch rate: 100.0% on 48 gold-positive rows (slice n=48; not a model score).
- Fallback slice catch rate: 100.0% on 1 classifier rows (**heuristic coverage only**).

Unsplit catch rate is omitted on purpose so it cannot be copy-pasted as model quality.
