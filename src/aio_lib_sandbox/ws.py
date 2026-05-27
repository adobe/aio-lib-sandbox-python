# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""WebSocket session — connection lifecycle, authentication, frame routing, and pending operations.

All WebSocket state and logic lives here.  ``Sandbox`` holds a ``WsSession``
instance and delegates every WS operation to it.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import ssl as ssl_module
from dataclasses import dataclass, field
from typing import Any, Callable

import websockets

from .frames import is_auth_ack, parse_frame
from .errors import (
    SandboxClientError,
    SandboxTimeoutError,
    SandboxUnauthorizedError,
    SandboxWebSocketError,
)
from .types import ExecResult, FileEntry, WriteResult

logger = logging.getLogger("aio_lib_sandbox")


# ---------------------------------------------------------------------------
# Pending-operation dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PendingExec:
    future: asyncio.Future[ExecResult]
    started: asyncio.Event = field(default_factory=asyncio.Event)
    stdout: str = ""
    stderr: str = ""
    on_output: Callable[[str, str], None] | None = None
    timeout_handle: asyncio.TimerHandle | None = None


@dataclass
class PendingFileOp:
    future: asyncio.Future[Any]


# ---------------------------------------------------------------------------
# WebSocket session
# ---------------------------------------------------------------------------


class WsSession:
    """Manages the WebSocket connection, authentication, and frame routing for a sandbox.

    ``Sandbox`` creates one instance per connection and delegates all WS work here.
    """

    def __init__(
        self,
        *,
        sandbox_id: str,
        endpoint: str,
        token: str,
        verify_ssl: bool = True,
    ) -> None:
        self.id = sandbox_id
        self.endpoint = endpoint
        self.token = token
        self.verify_ssl = verify_ssl

        self.ws: websockets.ClientConnection | None = None
        self.pending_execs: dict[str, PendingExec] = {}
        self.pending_file_ops: dict[str, PendingFileOp] = {}
        self.listener_task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open the WebSocket and authenticate. Idempotent."""
        if self.ws is not None:
            return

        ssl_ctx = None
        if self.endpoint.startswith("wss://"):
            if self.verify_ssl:
                ssl_ctx = ssl_module.create_default_context()
            else:
                ssl_ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_CLIENT)
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl_module.CERT_NONE

        try:
            ws = await websockets.connect(
                self.endpoint,
                additional_headers={},
                ssl=ssl_ctx,
            )
        except Exception as exc:
            raise SandboxWebSocketError(
                f"Could not connect sandbox '{self.id}': {exc}"
            ) from exc

        self.ws = ws
        await self.authenticate()
        self.listener_task = asyncio.get_running_loop().create_task(self.listen())

    async def authenticate(self) -> None:
        await self.send_frame({"type": "auth", "token": self.token})
        raw = await self.ws.recv()
        frame = parse_frame(raw)
        if not is_auth_ack(frame, self.id):
            raise SandboxUnauthorizedError(
                f"Sandbox '{self.id}' rejected the WebSocket authentication token"
            )

    async def send_frame(self, frame: dict[str, Any]) -> None:
        """Serialise ``frame`` and send it over the socket."""
        await self.ws.send(json.dumps(frame))

    def ensure_open(self) -> None:
        """Raise ``SandboxWebSocketError`` if the socket is not connected."""
        if self.ws is None:
            raise SandboxWebSocketError(f"Sandbox '{self.id}' is not connected")

    async def close(self) -> None:
        """Cancel the listener task and close the socket."""
        if self.listener_task:
            self.listener_task.cancel()
            self.listener_task = None
        if self.ws:
            await self.ws.close()
            self.ws = None

    # ------------------------------------------------------------------
    # Pending operation management
    # ------------------------------------------------------------------

    def register_exec(self, exec_id: str, pending: PendingExec) -> None:
        self.pending_execs[exec_id] = pending

    def register_file_op(self, exec_id: str, pending: PendingFileOp) -> None:
        self.pending_file_ops[exec_id] = pending

    def reject_pending(
        self, store: dict[str, Any], exec_id: str, error: Exception
    ) -> None:
        pending = store.pop(exec_id, None)
        if pending is None:
            return
        if hasattr(pending, "timeout_handle") and pending.timeout_handle:
            pending.timeout_handle.cancel()
        if not pending.future.done():
            pending.future.set_exception(error)

    def reject_all(self, error: Exception) -> None:
        for eid in list(self.pending_execs):
            self.reject_pending(self.pending_execs, eid, error)
        for eid in list(self.pending_file_ops):
            self.reject_pending(self.pending_file_ops, eid, error)

    async def wait_for_exec_start(self, exec_id: str) -> None:
        pending = self.pending_execs.get(exec_id)
        if pending is not None and not pending.started.is_set():
            await pending.started.wait()

    def timeout_exec(self, exec_id: str, command: str, timeout: float) -> None:
        try:
            asyncio.get_running_loop().create_task(
                self.send_frame({"type": "exec.kill", "execId": exec_id, "signal": "SIGTERM"})
            )
        except Exception:
            pass
        self.reject_pending(
            self.pending_execs,
            exec_id,
            SandboxTimeoutError(
                f"Command '{command}' exceeded timeout of {timeout}ms"
            ),
        )

    # ------------------------------------------------------------------
    # Listener loop
    # ------------------------------------------------------------------

    async def listen(self) -> None:
        try:
            async for raw in self.ws:
                frame = parse_frame(raw)
                if frame is None or is_auth_ack(frame, self.id):
                    continue
                exec_id = frame.get("execId")
                if exec_id in self.pending_file_ops:
                    self.handle_file_frame(frame)
                elif exec_id in self.pending_execs:
                    self.handle_exec_frame(frame)
        except websockets.ConnectionClosed as exc:
            self.reject_all(
                SandboxWebSocketError(
                    f"Sandbox '{self.id}' WebSocket closed with code {exc.code}"
                )
            )
        finally:
            self.ws = None

    # ------------------------------------------------------------------
    # Frame handlers
    # ------------------------------------------------------------------

    def handle_exec_frame(self, frame: dict[str, Any]) -> None:
        exec_id = frame["execId"]
        pending = self.pending_execs.get(exec_id)
        if pending is None:
            return

        ftype = frame.get("type")

        if ftype == "exec.output":
            data = frame.get("data", "")
            stream = frame.get("stream", "stdout")
            if stream == "stderr":
                pending.stderr += data
            else:
                pending.stdout += data
            if pending.on_output:
                pending.on_output(data, stream)
            return

        if ftype == "exec.exit":
            self.resolve_exec(exec_id, frame)
            return

        if ftype == "error":
            self.reject_pending(
                self.pending_execs,
                exec_id,
                SandboxClientError(frame.get("message", f"Command '{exec_id}' failed")),
            )

    def handle_file_frame(self, frame: dict[str, Any]) -> None:
        exec_id = frame["execId"]
        pending = self.pending_file_ops.get(exec_id)
        if pending is None:
            return

        ftype = frame.get("type")

        if ftype == "file.content":
            content = frame.get("content", "")
            if frame.get("encoding") == "base64":
                content = base64.b64decode(content).decode()
            self.resolve_file_op(exec_id, content)

        elif ftype == "file.writeResult":
            if not frame.get("ok"):
                self.reject_pending(
                    self.pending_file_ops,
                    exec_id,
                    SandboxClientError(f"file.write failed for path '{frame.get('path')}'"),
                )
            else:
                self.resolve_file_op(
                    exec_id,
                    WriteResult(path=frame["path"], size=frame.get("size", 0), ok=True),
                )

        elif ftype == "file.entries":
            entries = [
                FileEntry(name=e["name"], type=e["type"], size=e.get("size"))
                for e in frame.get("entries", [])
            ]
            self.resolve_file_op(exec_id, entries)

        elif ftype == "error":
            self.reject_pending(
                self.pending_file_ops,
                exec_id,
                SandboxClientError(
                    frame.get("message", f"File operation '{exec_id}' failed")
                ),
            )

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def resolve_exec(self, exec_id: str, frame: dict[str, Any]) -> None:
        pending = self.pending_execs.pop(exec_id, None)
        if pending is None:
            return
        if pending.timeout_handle:
            pending.timeout_handle.cancel()
        if not pending.future.done():
            pending.future.set_result(
                ExecResult(
                    exec_id=exec_id,
                    stdout=pending.stdout,
                    stderr=pending.stderr,
                    exit_code=frame.get("exitCode", -1),
                )
            )

    def resolve_file_op(self, exec_id: str, result: Any) -> None:
        pending = self.pending_file_ops.pop(exec_id, None)
        if pending and not pending.future.done():
            pending.future.set_result(result)
