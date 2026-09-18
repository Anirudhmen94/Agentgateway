"""Reporting labels for classifier backends.

Local fallback and fail-closed must never be counted as grok-4.6 model quality.
"""

from __future__ import annotations

import os

BACKEND_FALLBACK = "fallback"
BACKEND_GROK = "grok"
BACKEND_POLICY = "policy"
BACKEND_FAIL_CLOSED = "fail-closed"
BACKEND_OTHER = "other"

GROK_MODEL = "grok-4.6"
FALLBACK_MODEL = "local-fallback"
FAIL_CLOSED_MODEL = "fail-closed"
# Historic cache/scorecard name; still mapped to fallback, never to grok.
LEGACY_FALLBACK_MODEL = "grok-4.6-local-fallback"


def fail_closed_enabled() -> bool:
    return os.getenv("FAIL_CLOSED", "0").strip().lower() in {"1", "true", "yes", "on"}


def decision_backend(model: str | None, layer: str | None = None) -> str:
    """Map a decision to a reporting backend. Never blend fallback with grok."""
    if layer == "policy" or not model:
        if layer == "policy":
            return BACKEND_POLICY
    name = (model or "").lower()
    if "fail-closed" in name or name == "unavailable":
        return BACKEND_FAIL_CLOSED
    if "fallback" in name or "local" in name:
        return BACKEND_FALLBACK
    if name.startswith("grok") or "grok-4.6" in name:
        return BACKEND_GROK
    if layer == "model" and name:
        return BACKEND_OTHER
    return BACKEND_POLICY
