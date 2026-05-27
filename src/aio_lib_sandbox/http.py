# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from .errors import (
    SandboxClientError,
    SandboxNotFoundError,
    SandboxTimeoutError,
    SandboxUnauthorizedError,
)

logger = logging.getLogger("aio_lib_sandbox")

STATUS_ERROR_MAP: dict[int, type[SandboxClientError]] = {
    401: SandboxUnauthorizedError,
    403: SandboxUnauthorizedError,
    404: SandboxNotFoundError,
    504: SandboxTimeoutError,
}


def build_auth_header(api_key: str) -> str:
    return f"Basic {base64.b64encode(api_key.encode()).decode()}"


def sandbox_http_error(status: int, detail: str) -> SandboxClientError:
    cls = STATUS_ERROR_MAP.get(status, SandboxClientError)
    return cls(detail)


def normalize_api_host(host: str) -> str:
    if not host.startswith(("http://", "https://")):
        return f"https://{host}"
    return host


def build_ws_endpoint(api_host: str, namespace: str, sandbox_id: str) -> str:
    parsed = urlparse(api_host)
    ws_scheme = "ws" if parsed.scheme == "http" else "wss"
    path = f"/ws/v1/namespaces/{namespace}/sandbox/{sandbox_id}/exec"
    return urlunparse((ws_scheme, parsed.netloc, path, "", "", ""))


async def api_request(
    method: str,
    url: str,
    *,
    api_key: str,
    body: dict[str, Any] | None = None,
    verify_ssl: bool = True,
    timeout: float = 30.0,
    operation: str = "request",
) -> Any:
    headers = {"Authorization": build_auth_header(api_key)}
    kwargs: dict[str, Any] = {"headers": headers}

    if body is not None:
        headers["Content-Type"] = "application/json"
        kwargs["content"] = json.dumps(body)

    async with httpx.AsyncClient(verify=verify_ssl, timeout=timeout) as client:
        try:
            resp = await client.request(method, url, **kwargs)
        except httpx.HTTPError as exc:
            raise SandboxClientError(f"Could not {operation}: {exc}") from exc

    if not resp.is_success:
        msg = resp.text
        detail = f"Could not {operation}: {resp.status_code}{f' {msg}' if msg else ''}"
        raise sandbox_http_error(resp.status_code, detail)

    return resp.json()
