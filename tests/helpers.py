from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL_SET = ROOT / "data" / "eval_set.jsonl"
ADVERSARIAL_SET = ROOT / "data" / "eval_adversarial.jsonl"


def load_eval_row(eid: str, path: Path = EVAL_SET) -> dict:
    with path.open() as fh:
        for line in fh:
            row = json.loads(line)
            if row.get("id") == eid:
                return row
    raise KeyError(eid)


def auth_headers(token: str | None) -> dict[str, str]:
    """Primary contract: Authorization: Bearer <GATEWAY_TOKEN>."""
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def alias_headers(token: str | None) -> dict[str, str]:
    """Optional alias only. Do not use this as the primary contract."""
    if not token:
        return {}
    return {"X-Gateway-Token": token}
