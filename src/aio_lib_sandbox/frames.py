# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""WebSocket frame utilities and size normalization helpers."""

from __future__ import annotations

import json
from typing import Any

from .errors import SandboxClientError
from .types import SANDBOX_SIZES


def parse_frame(raw: Any) -> dict[str, Any] | None:
    """Parse a raw WebSocket message into a frame dict, or return None on failure."""
    try:
        return json.loads(raw if isinstance(raw, str) else raw.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def is_auth_ack(frame: dict[str, Any] | None, sandbox_id: str) -> bool:
    """Return True if the frame is a successful auth acknowledgement for this sandbox."""
    if frame is None:
        return False
    return frame.get("type") == "auth.ok" and (
        not frame.get("sandboxId") or frame["sandboxId"] == sandbox_id
    )


def normalize_size(size: str | dict[str, Any] | None) -> str:
    """Resolve a size name or spec dict to a canonical size tier name."""
    if size is None:
        return "MEDIUM"
    if isinstance(size, str) and size in SANDBOX_SIZES:
        return size
    if isinstance(size, dict):
        for name, spec in SANDBOX_SIZES.items():
            if (
                spec["cpu"] == size.get("cpu")
                and spec["memory"] == size.get("memory")
                and spec["gpu"] == size.get("gpu")
            ):
                return name
    raise SandboxClientError("Invalid sandbox size provided")
