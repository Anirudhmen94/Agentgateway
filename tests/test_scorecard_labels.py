"""Scorecard must label fallback vs grok and must not blend them as model quality."""

from __future__ import annotations

from src.eval_run import (
    BACKEND_FALLBACK,
    BACKEND_GROK,
    classifier_backend,
    render,
    render_grok_not_run,
    render_index,
)
from src.models import CATEGORIES


def _empty_confusion():
    return {a: {b: 0 for b in CATEGORIES} for a in CATEGORIES}


def test_backend_labels_fallback_vs_grok():
    assert classifier_backend("grok-4.6-local-fallback", "model") == BACKEND_FALLBACK
    assert classifier_backend("grok-4.6", "model") == BACKEND_GROK
    assert classifier_backend(None, "policy") == "policy"


def test_fallback_render_is_not_model_quality():
    report = {
        "n": 2,
        "backend": BACKEND_FALLBACK,
        "eval_name": "eval_set.jsonl",
        "models": ["grok-4.6-local-fallback"],
        "temperature": 0,
        "sha": "deadbeef",
        "when": "2026-09-17T00:00:00Z",
        "detection_rate": 0.973,
        "fp_rate": 0.0,
        "per_cat": [(cat, 0.0, 0.0, 0, 0, 0) for cat in CATEGORIES],
        "confusion": _empty_confusion(),
        "policy_n": 1,
        "model_n": 1,
        "lat_policy": [0.1],
        "lat_model": [1.0],
        "worst": [],
        "cache": {"hits": 0, "misses": 1},
    }
    text = render(report)
    assert "model=fallback" in text
    assert "Not grok-4.6" in text or "not grok-4.6" in text.lower()
    assert "not model quality" in text.lower()
    assert "only" in text.lower() and "classifier" in text.lower()
    assert "97.3%" in text  # allowed as heuristic coverage
    assert "grok-4.6 detection" not in text.lower() or "not grok" in text.lower()


def test_index_omits_blended_model_quality():
    report = {
        "n": 10,
        "sha": "deadbeef",
        "when": "2026-09-17T00:00:00Z",
        "cache": {"hits": 0, "misses": 10},
        "eval_path": "data/eval_set.jsonl",
        "backend_counts": {"policy": 5, "fallback": 5},
        "slices": {
            "fallback": {"detection_rate": 0.973, "n": 5},
            "policy": {"detection_rate": 1.0, "n": 5},
        },
        "detection_rate": 0.973,
    }
    text = render_index(report, grok_ran=False)
    assert "INDEX" in text
    assert "model quality" in text.lower()
    assert "NOT RUN" in text
    assert "Unsplit catch rate is omitted" in text
    grok = render_grok_not_run("deadbeef", "2026-09-17T00:00:00Z")
    assert "model=grok" in grok
    assert "NOT RUN" in grok
    assert "Do not substitute" in grok
