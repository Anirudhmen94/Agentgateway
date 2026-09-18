# Agent Trust Gateway

## Conventions

- Python 3.11. Dependencies: openai, pyyaml, python-dotenv, pytest. Live-demo extra: fastapi, uvicorn, httpx.
- Every module runnable standalone: python -m src.<module>
- Secrets come from .env only. Never hardcode, never commit.
- One step = one commit that runs. Do not build ahead of the current step.

## Model

- Pin grok-4.6. Temperature 0. Structured outputs with an explicit JSON schema.
- Record model name, temperature and UTC timestamp in every classifier response.

## Non-goals

- No operator SSO, no tool sandbox, no customer telemetry. Demo token + loopback bind is the v1 control-plane bar.
- A simple live web UI + HTTP API is in scope (product override: real-time demo).
- Never invent or modify eval labels after they are authored. Labels are human-authored.
- Never present local-fallback scorecards as grok-4.6 quality.
