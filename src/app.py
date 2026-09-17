"""Live HTTP API + web UI for Agent Trust Gateway."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

from src.gateway import (
    clear_revocations,
    handle,
    revoke,
    revoked_agents,
    subscribe_audit,
    unrevoke,
)
from src.policy import load_agents

ROOT = Path(__file__).resolve().parent.parent
UI_PATH = ROOT / "src" / "static" / "index.html"
_queue: asyncio.Queue | None = None


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
    return {"status": "ok"}


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
                "revoked": agent_id in revoked,
            }
        )
    return {"agents": listing}


@app.post("/v1/check")
def check(body: CheckBody) -> dict[str, Any]:
    request = {
        "id": body.id or body.request_id or f"live-{uuid4().hex[:12]}",
        "agent_id": body.agent_id,
        "tool": body.tool,
        "args": body.args,
        "session_context": body.session_context,
        "session_id": body.session_id,
    }
    decision = handle(request, use_cache=True)
    return {
        "request": request,
        "verdict": decision.verdict,
        "category": decision.category,
        "confidence": decision.confidence,
        "reasoning": decision.reasoning,
        "deciding_layer": decision.deciding_layer,
        "rule_id": decision.rule_id,
        "latency_ms": decision.latency_ms,
        "model": decision.model,
        "temperature": decision.temperature,
        "timestamp_utc": decision.timestamp_utc,
        "cached": decision.cached,
    }


@app.post("/v1/revoke")
def revoke_agent(body: RevokeBody) -> dict[str, Any]:
    if body.agent_id not in load_agents():
        raise HTTPException(404, "unknown agent")
    revoke(body.agent_id)
    return {"agent_id": body.agent_id, "revoked": True}


@app.post("/v1/unrevoke")
def unrevoke_agent(body: RevokeBody) -> dict[str, Any]:
    unrevoke(body.agent_id)
    return {"agent_id": body.agent_id, "revoked": False}


@app.post("/v1/revoke/clear")
def revoke_clear() -> dict[str, str]:
    clear_revocations()
    return {"status": "cleared"}


@app.get("/v1/audit/stream")
async def audit_stream() -> StreamingResponse:
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
    import os

    import uvicorn

    host = os.getenv("GATEWAY_HOST") or "0.0.0.0"
    port = int(os.getenv("GATEWAY_PORT") or "8000")
    uvicorn.run("src.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
