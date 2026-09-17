"""Demo shared-token auth. Secrets come from the environment only."""

from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Query, Request


def gateway_token() -> str:
    return os.getenv("GATEWAY_TOKEN") or ""


def extract_token(request: Request, query_token: str | None = None) -> str | None:
    header = request.headers.get("authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    x_token = request.headers.get("x-gateway-token")
    if x_token:
        return x_token.strip()
    if query_token:
        return query_token.strip()
    return None


def tokens_match(provided: str | None, expected: str) -> bool:
    if not expected or provided is None:
        return False
    if len(provided.encode("utf-8")) != len(expected.encode("utf-8")):
        return False
    return hmac.compare_digest(provided, expected)


def require_gateway_token(
    request: Request,
    token: str | None = Query(default=None, description="Demo token for SSE clients that cannot set headers."),
) -> None:
    expected = gateway_token()
    provided = extract_token(request, token)
    if not tokens_match(provided, expected):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing gateway token",
            headers={"WWW-Authenticate": "Bearer"},
        )
