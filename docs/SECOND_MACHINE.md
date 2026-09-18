# Second machine (loopback demo)

This process binds **127.0.0.1:8000** by default. Another host cannot reach it unless you override the bind or tunnel. Windows-first start is in the README (`.\scripts\start.ps1` / `.\scripts\stop.ps1` or `python -m src.app`).

## On this machine

```powershell
copy .env.example .env   # set GATEWAY_TOKEN; leave XAI_API_KEY empty unless you want grok-4.6
# FAIL_CLOSED=0 keeps the local heuristic when the key is missing (not grok quality).
# FAIL_CLOSED=1 denies undecided rows instead of using local-fallback as if it were grok.
.\scripts\start.ps1
curl.exe -sS http://127.0.0.1:8000/health
curl.exe -sS http://127.0.0.1:8000/ready
.\scripts\stop.ps1
```

macOS/Linux: `cp .env.example .env` then `make run` or `python3 -m src.app`.

Mutating routes need:

```http
Authorization: Bearer <GATEWAY_TOKEN>
```

`approve` is `pending: true` and `execution_allowed: false`. Do not execute.

## From a second machine

Prefer an SSH tunnel so the gateway stays on loopback:

```bash
ssh -L 8000:127.0.0.1:8000 user@gateway-host
curl -sS http://127.0.0.1:8000/ready
```

Only if you intend remote bind (not the default):

```bash
GATEWAY_HOST=0.0.0.0 GATEWAY_PORT=8000 python3 -m src.app
```

Compose publishes **127.0.0.1:8000** on the host (`docker-compose.yml`). Inside the container `GATEWAY_HOST=0.0.0.0` is an explicit override so the published port works.

Do not put `XAI_API_KEY` or `GATEWAY_TOKEN` in chat, tickets, or images. `.env` only. No Radware IP.
