"""Process bind address. Default is loopback; override with env or flags."""

from __future__ import annotations

import argparse
import os

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000


def resolve_bind(argv: list[str] | None = None) -> tuple[str, int]:
    parser = argparse.ArgumentParser(prog="agent-trust-gateway", add_help=True)
    parser.add_argument(
        "--host",
        default=None,
        help=f"Listen address (default {DEFAULT_HOST}; env GATEWAY_HOST). Use 0.0.0.0 only when you intend remote access.",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Listen port (default {DEFAULT_PORT}; env GATEWAY_PORT).",
    )
    args, _unknown = parser.parse_known_args(argv)
    host = args.host or os.getenv("GATEWAY_HOST") or DEFAULT_HOST
    port = args.port if args.port is not None else int(os.getenv("GATEWAY_PORT") or DEFAULT_PORT)
    return host, port
