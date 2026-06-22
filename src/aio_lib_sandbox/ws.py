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

from .errors import (
    ProtocolVersionMismatchError,
    SandboxClientError,
    SandboxCommandNotFoundError,
    SandboxMalformedFrameError,
    SandboxTimeoutError,
    SandboxUnauthorizedError,
    SandboxWebSocketError,
)
from .frames import is_auth_ack, parse_frame
from .types import DetachedCommandHandle, ExecResult, FileEntry, WriteResult

logger = logging.getLogger("aio_lib_sandbox")


# ---------------------------------------------------------------------------
# Pending-operation dataclasses
# ---------------------------------------------------------------------------


@dataclass
class PendingExec:
    future: asyncio.Future[Any]
    started: asyncio.Event = field(default_factory=asyncio.Event)
    stdout: str = ""
    stderr: str = ""
    on_output: Callable[[str, str], None] | None = None
    timeout_handle: asyncio.TimerHandle | None = None
    # Detached-process fields
    detached: bool = False
    resolved: bool = False  # True once the outer future has been set (exec.detached)
    wait_future: asyncio.Future[Any] | None = None  # resolves on exec.exit for detached


@dataclass
class PendingFileOp:
    future: asyncio.Future[Any]


@dataclass
class PendingGetOp:
    """Pending exec.get operation (resolves when exec.info arrives)."""

    future: asyncio.Future[Any]
    on_output: Callable[[str, str], None] | None = None
    sandbox_ref: Any = None


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
        self.pending_get_ops: dict[str, PendingGetOp] = {}
        self.listener_task: asyncio.Task[None] | None = None
        self.intentional_close = False

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
            raise SandboxWebSocketError(f"Could not connect sandbox '{self.id}': {exc}") from exc

        self.ws = ws
        await self.authenticate()
        self.listener_task = asyncio.get_running_loop().create_task(self.listen())

    async def authenticate(self) -> None:
        await self.send_frame({"type": "auth", "token": self.token})
        raw = await self.ws.recv()
        frame = parse_frame(raw)
        if not is_auth_ack(frame, self.id):
            raise SandboxUnauthorizedError(f"Sandbox '{self.id}' rejected the WebSocket authentication token")

    async def send_frame(self, frame: dict[str, Any]) -> None:
        """Serialise ``frame`` and send it over the socket."""
        await self.ws.send(json.dumps(frame))

    def ensure_open(self) -> None:
        """Raise ``SandboxWebSocketError`` if the socket is not connected."""
        if self.ws is None:
            raise SandboxWebSocketError(f"Sandbox '{self.id}' is not connected")

    def begin_intentional_close(self) -> None:
        """Mark the next WebSocket close as expected by sandbox teardown."""
        self.intentional_close = True

    def cancel_intentional_close(self) -> None:
        """Clear a previously requested intentional close."""
        self.intentional_close = False

    async def close(self, *, intentional: bool = False) -> None:
        """Cancel the listener task and close the socket."""
        if intentional:
            self.begin_intentional_close()
        if self.intentional_close:
            self.resolve_all_on_intentional_close()
        if self.listener_task:
            self.listener_task.cancel()
            self.listener_task = None
        if self.ws:
            await self.ws.close()
            self.ws = None
        if self.intentional_close:
            self.intentional_close = False

    # ------------------------------------------------------------------
    # Pending operation management
    # ------------------------------------------------------------------

    def register_exec(self, exec_id: str, pending: PendingExec) -> None:
        self.pending_execs[exec_id] = pending

    def register_file_op(self, exec_id: str, pending: PendingFileOp) -> None:
        self.pending_file_ops[exec_id] = pending

    def register_get_op(self, exec_id: str, pending: PendingGetOp) -> None:
        self.pending_get_ops[exec_id] = pending

    def reject_pending(self, store: dict[str, Any], exec_id: str, error: Exception) -> None:
        pending = store.pop(exec_id, None)
        if pending is None:
            return
        if hasattr(pending, "timeout_handle") and pending.timeout_handle:
            pending.timeout_handle.cancel()
        if not pending.future.done():
            pending.future.set_exception(error)

    def reject_exec(self, exec_id: str, error: Exception) -> None:
        """Reject a pending exec, honouring the detached/resolved state."""
        pending = self.pending_execs.pop(exec_id, None)
        if pending is None:
            return
        if pending.timeout_handle:
            pending.timeout_handle.cancel()
        if pending.detached and pending.resolved:
            # Outer future already resolved; reject the wait() future instead.
            if pending.wait_future and not pending.wait_future.done():
                pending.wait_future.set_exception(error)
        else:
            if not pending.future.done():
                pending.future.set_exception(error)

    def reject_all(self, error: Exception) -> None:
        for eid in list(self.pending_execs):
            self.reject_exec(eid, error)
        for eid in list(self.pending_file_ops):
            self.reject_pending(self.pending_file_ops, eid, error)
        for eid in list(self.pending_get_ops):
            pending = self.pending_get_ops.pop(eid, None)
            if pending and not pending.future.done():
                pending.future.set_exception(error)

    def resolve_exec_on_intentional_close(self, exec_id: str) -> None:
        """Resolve a pending exec during an intentional sandbox shutdown."""
        pending = self.pending_execs.pop(exec_id, None)
        if pending is None:
            return
        if pending.timeout_handle:
            pending.timeout_handle.cancel()

        wait_result = {"exit_code": None, "destroyed": True}
        if pending.detached:
            if not pending.future.done():
                pending.resolved = True
                pending.future.set_result({"pid": None, "started_at": None, "destroyed": True})
            if pending.wait_future and not pending.wait_future.done():
                pending.wait_future.set_result(wait_result)
            return

        if not pending.future.done():
            pending.future.set_result(
                ExecResult(
                    exec_id=exec_id,
                    stdout=pending.stdout,
                    stderr=pending.stderr,
                    exit_code=None,
                    destroyed=True,
                )
            )

    def resolve_all_on_intentional_close(self) -> None:
        """Drain tracked operations without errors during sandbox destroy."""
        for eid in list(self.pending_execs):
            self.resolve_exec_on_intentional_close(eid)
        for eid in list(self.pending_file_ops):
            pending = self.pending_file_ops.pop(eid, None)
            if pending and not pending.future.done():
                pending.future.set_result(None)
        for eid in list(self.pending_get_ops):
            pending = self.pending_get_ops.pop(eid, None)
            if pending and not pending.future.done():
                pending.future.set_result(None)

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
            SandboxTimeoutError(f"Command '{command}' exceeded timeout of {timeout}ms"),
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
                ftype = frame.get("type")

                # exec.info is always routed to pending_get_ops.
                # Error frames for pending get ops also go there (before exec map check).
                if ftype == "exec.info" or (ftype == "error" and exec_id in self.pending_get_ops):
                    self.handle_get_frame(frame)
                elif exec_id in self.pending_file_ops:
                    self.handle_file_frame(frame)
                elif exec_id in self.pending_execs:
                    self.handle_exec_frame(frame)
        except websockets.ConnectionClosed as exc:
            if self.intentional_close:
                self.resolve_all_on_intentional_close()
                return
            close_code = exc.rcvd.code if exc.rcvd is not None else 1006
            if close_code == 4003:
                error = ProtocolVersionMismatchError(
                    f"Sandbox '{self.id}' WebSocket protocol version does not match this SDK"
                )
            elif close_code == 4004:
                error = SandboxMalformedFrameError(f"Sandbox '{self.id}' rejected a malformed WebSocket frame")
            else:
                error = SandboxWebSocketError(f"Sandbox '{self.id}' WebSocket closed with code {close_code}")
            self.reject_all(error)
        finally:
            self.ws = None
            if self.intentional_close:
                self.intentional_close = False

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

        # Detached ack: resolve the outer future with the raw pid/startedAt data.
        # Sandbox._run() wraps this into a DetachedCommandHandle after awaiting.
        # The entry stays in pending_execs to receive subsequent output and exec.exit.
        if ftype == "exec.detached":
            if pending.timeout_handle:
                pending.timeout_handle.cancel()
                pending.timeout_handle = None
            pending.resolved = True
            if not pending.future.done():
                pending.future.set_result({"pid": frame.get("pid", 0), "started_at": frame.get("startedAt", 0)})
            return

        if ftype == "exec.exit":
            self.pending_execs.pop(exec_id, None)
            if pending.timeout_handle:
                pending.timeout_handle.cancel()
            if pending.detached and pending.resolved:
                # Detached: outer future already resolved; drive the wait() future.
                if pending.wait_future and not pending.wait_future.done():
                    pending.wait_future.set_result({"exit_code": frame.get("exitCode", -1)})
            else:
                if not pending.future.done():
                    pending.future.set_result(
                        ExecResult(
                            exec_id=exec_id,
                            stdout=pending.stdout,
                            stderr=pending.stderr,
                            exit_code=frame.get("exitCode", -1),
                        )
                    )
            return

        if ftype == "error":
            self.reject_exec(
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
            entries = [FileEntry(name=e["name"], type=e["type"], size=e.get("size")) for e in frame.get("entries", [])]
            self.resolve_file_op(exec_id, entries)

        elif ftype == "error":
            self.reject_pending(
                self.pending_file_ops,
                exec_id,
                SandboxClientError(frame.get("message", f"File operation '{exec_id}' failed")),
            )

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def resolve_file_op(self, exec_id: str, result: Any) -> None:
        pending = self.pending_file_ops.pop(exec_id, None)
        if pending and not pending.future.done():
            pending.future.set_result(result)

    def handle_get_frame(self, frame: dict[str, Any]) -> None:
        """Handle exec.info (response to exec.get) and related error frames."""
        exec_id = frame.get("execId")
        pending = self.pending_get_ops.get(exec_id)
        if pending is None:
            return

        if frame.get("type") == "exec.info":
            self.resolve_get_op(frame, pending)
        elif frame.get("type") == "error":
            self.reject_get_op(frame, pending)

    def resolve_get_op(self, frame: dict[str, Any], pending: PendingGetOp) -> None:
        """Resolve a pending exec.get by building a command handle and settling the caller's future."""
        exec_id = frame.get("execId")
        self.pending_get_ops.pop(exec_id, None)
        wait_future = self.resolve_exec_entry(frame, pending)
        command_obj = self.build_command_object(frame, wait_future, pending.sandbox_ref)
        if not pending.future.done():
            pending.future.set_result(command_obj)

    def reject_get_op(self, frame: dict[str, Any], pending: PendingGetOp) -> None:
        """Reject a pending exec.get with a not-found error."""
        exec_id = frame.get("execId")
        self.pending_get_ops.pop(exec_id, None)
        if not pending.future.done():
            pending.future.set_exception(
                SandboxCommandNotFoundError(frame.get("message", f"No running process for execId '{exec_id}'"))
            )

    def resolve_exec_entry(self, frame: dict[str, Any], pending: PendingGetOp) -> "asyncio.Future[Any]":
        """Return the wait future for the exec — reusing an existing entry from the same
        session, or registering a fresh reattached entry for a new/previous connection."""
        exec_id = frame.get("execId")
        existing = self.pending_execs.get(exec_id)
        if existing:
            self.merge_on_output_callback(existing, pending.on_output)
            return existing.wait_future
        return self.register_reattached_exec(frame, pending.on_output)

    def merge_on_output_callback(
        self,
        existing: PendingExec,
        on_output: Callable[[str, str], None] | None,
    ) -> None:
        """Append ``on_output`` to an existing exec entry's callback chain,
        preserving the previous handler."""
        if not on_output:
            return
        prev = existing.on_output

        def merged(data: str, stream: str, _prev=prev, _new=on_output) -> None:
            if _prev:
                _prev(data, stream)
            _new(data, stream)

        existing.on_output = merged

    def register_reattached_exec(
        self,
        frame: dict[str, Any],
        on_output: Callable[[str, str], None] | None,
    ) -> "asyncio.Future[Any]":
        """Create a fresh ``pending_execs`` entry for a process reattached from a
        previous connection and return its wait future."""
        exec_id = frame.get("execId")
        loop = asyncio.get_running_loop()
        wait_future: asyncio.Future[Any] = loop.create_future()
        placeholder: asyncio.Future[Any] = loop.create_future()
        monitoring = PendingExec(
            future=placeholder,
            on_output=on_output,
            detached=frame.get("detached", False),
            resolved=True,
            wait_future=wait_future,
        )
        placeholder.set_result(None)
        self.pending_execs[exec_id] = monitoring
        return wait_future

    def build_command_object(
        self,
        frame: dict[str, Any],
        wait_future: "asyncio.Future[Any]",
        sandbox: Any,
    ) -> DetachedCommandHandle:
        """Build the :class:`DetachedCommandHandle` returned to the caller of ``get_command``."""
        exec_id = frame.get("execId")
        return DetachedCommandHandle(
            exec_id=exec_id,
            pid=frame.get("pid", 0),
            started_at=frame.get("startedAt", 0),
            detached=frame.get("detached", False),
            wait_future=wait_future,
            sandbox_ref=sandbox,
            command=frame.get("command"),
        )
