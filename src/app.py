"""Live HTTP API + web UI for Agent Trust Gateway."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.auth import require_gateway_token
from src.bind import resolve_bind
from src.gateway import (
    clear_revocations,
    handle,
    revoke,
    revoked_agents,
    subscribe_audit,
    unrevoke,
)
from src.policy import load_agents
from src.quota import get_store as get_quota_store
from src.quota import limit_for_agent, window_for_agent
from src.revocation import get_store

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
UI_PATH = ROOT / "src" / "static" / "index.html"
_queue: asyncio.Queue | None = None
Protected = Depends(require_gateway_token)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _queue
    loop = asyncio.get_running_loop()
    _queue = asyncio.Queue()

    def _on_audit(record: dict[str, Any]) -> None:
        try:
            loop.call_soon_threadsafe(_queue.put_nowait, record)
        except Exception:
            pass

    subscribe_audit(_on_audit)
    yield


app = FastAPI(title="Agent Trust Gateway", version="0.1.0", lifespan=lifespan)


class CheckBody(BaseModel):
    agent_id: str
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    session_context: str = ""
    session_id: str = ""
    id: str | None = None
    request_id: str | None = None


class RevokeBody(BaseModel):
    agent_id: str


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return UI_PATH.read_text(encoding="utf-8")


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process is up. Not a substitute for GET /ready."""
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict[str, Any]:
    """Readiness: revocation store, quota store, and agent catalog are usable."""
    checks: dict[str, str] = {}
    errors: list[str] = []
    try:
        agents = load_agents()
        if not agents:
            raise RuntimeError("agent catalog is empty")
        checks["agents"] = "ok"
    except Exception as exc:  # noqa: BLE001 — readiness must never raise 500 as "up"
        checks["agents"] = "error"
        errors.append(f"agents: {exc}")
    try:
        get_store().all()
        checks["revocation_store"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["revocation_store"] = "error"
        errors.append(f"revocation_store: {exc}")
    try:
        get_quota_store().all()
        checks["quota_store"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["quota_store"] = "error"
        errors.append(f"quota_store: {exc}")
    if errors:
        raise HTTPException(
            status_code=503,
            detail={"status": "not_ready", "checks": checks, "errors": errors},
        )
    return {"status": "ready", "checks": checks}


@app.get("/v1/agents")
def agents() -> dict[str, Any]:
    data = load_agents()
    revoked = revoked_agents()
    listing = []
    for agent_id, row in data.items():
        listing.append(
            {
                "id": agent_id,
                "name": row.get("name") or agent_id,
                "declared_purpose": (row.get("declared_purpose") or "").strip(),
                "allowed_tools": row.get("allowed_tools") or [],
                "escalation": row.get("escalation") or [],
                "data_scopes": row.get("data_scopes") or [],
                "rate_limit_per_min": row.get("rate_limit_per_min"),
                "quota_limit": limit_for_agent(row),
                "quota_window_seconds": window_for_agent(row),
                "revoked": agent_id in revoked,
            }
        )
    return {"agents": listing}


@app.post("/v1/check")
def check(body: CheckBody, _: None = Protected) -> dict[str, Any]:
    request = {
        "id": body.id or body.request_id or f"live-{uuid4().hex[:12]}",
        "agent_id": body.agent_id,
        "tool": body.tool,
        "args": body.args,
        "session_context": body.session_context,
        "session_id": body.session_id,
    }
    decision = handle(request, use_cache=True)
    payload = decision.to_public_dict()
    payload["request"] = request
    return payload


@app.post("/v1/revoke")
def revoke_agent(body: RevokeBody, _: None = Protected) -> dict[str, Any]:
    if body.agent_id not in load_agents():
        raise HTTPException(404, "unknown agent")
    revoke(body.agent_id)
    return {"agent_id": body.agent_id, "revoked": True}


@app.post("/v1/unrevoke")
def unrevoke_agent(body: RevokeBody, _: None = Protected) -> dict[str, Any]:
    unrevoke(body.agent_id)
    return {"agent_id": body.agent_id, "revoked": False}


@app.post("/v1/revoke/clear")
def revoke_clear(_: None = Protected) -> dict[str, str]:
    clear_revocations()
    return {"status": "cleared"}


@app.get("/v1/audit/stream")
async def audit_stream(_: None = Protected) -> StreamingResponse:
    async def gen():
        q = _queue
        yield "event: hello\ndata: {\"ok\": true}\n\n"
        if q is None:
            return
        while True:
            record = await q.get()
            yield f"event: audit\ndata: {json.dumps(record)}\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


def main() -> None:
    import uvicorn

    host, port = resolve_bind()
    uvicorn.run("src.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
