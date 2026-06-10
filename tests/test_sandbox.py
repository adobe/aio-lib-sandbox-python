# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import asyncio
import base64
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import websockets

from aio_lib_sandbox import (
    SANDBOX_SIZES,
    DetachedCommandHandle,
    ExecResult,
    FileEntry,
    Sandbox,
    WriteResult,
)
from aio_lib_sandbox.errors import (
    SandboxClientError,
    SandboxCommandNotFoundError,
    SandboxInitializationError,
    SandboxInvalidPortError,
    SandboxNotFoundError,
    SandboxPortNotProvisionedError,
    SandboxTimeoutError,
    SandboxUnauthorizedError,
    SandboxWebSocketError,
)
from aio_lib_sandbox.frames import normalize_size
from aio_lib_sandbox.sandbox import _parse_preview_urls
from aio_lib_sandbox.ws import PendingExec, PendingFileOp, PendingGetOp, WsSession

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_OPTS = dict(
    sandbox_id="sb-test",
    endpoint="wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-test/exec",
    status="ready",
    namespace="ns",
    api_host="https://runtime.example.net",
    api_key="uuid:key",
    token="tok-abc",
    max_lifetime=3600,
    cluster="cluster-a",
    region="va6",
)


def _make_sandbox(**overrides):
    opts = {**BASE_OPTS, **overrides}
    sb = Sandbox(**opts)
    return sb


def _inject_ws(sandbox: Sandbox):
    """Inject a real WsSession backed by a mock WebSocket into *sandbox*."""
    session = WsSession(
        sandbox_id=sandbox.id,
        endpoint=sandbox.endpoint or "wss://mock",
        token=sandbox.token or "mock-token",
        verify_ssl=False,
    )
    ws = AsyncMock()
    ws.send = AsyncMock()
    ws.recv = AsyncMock()
    ws.close = AsyncMock()
    session.ws = ws
    sandbox.session = session
    return ws


def _frame(ws, payload: dict) -> None:
    """Queue a JSON frame to be yielded by ws.__aiter__."""
    # we patch the listener separately; for direct frame handling tests,
    # call handle_exec_frame / handle_file_frame directly.


class _AsyncFrameStream:
    def __init__(self, *frames):
        self.frames = list(frames)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.frames:
            raise StopAsyncIteration
        frame = self.frames.pop(0)
        if isinstance(frame, BaseException):
            raise frame
        return frame


# ---------------------------------------------------------------------------
# normalize_size
# ---------------------------------------------------------------------------


class TestNormalizeSize:
    def test_none_returns_medium(self):
        assert normalize_size(None) == "MEDIUM"

    def test_valid_name(self):
        assert normalize_size("LARGE") == "LARGE"

    def test_spec_dict(self):
        assert normalize_size({"cpu": "500m", "memory": "512Mi", "gpu": 0}) == "SMALL"

    def test_invalid_string_raises(self):
        with pytest.raises(SandboxClientError):
            normalize_size("HUGE")

    def test_invalid_dict_raises(self):
        with pytest.raises(SandboxClientError):
            normalize_size({"cpu": "999m", "memory": "999Gi", "gpu": 9})


# ---------------------------------------------------------------------------
# resolve_credentials
# ---------------------------------------------------------------------------


class TestResolveCredentials:
    def test_reads_from_env(self, monkeypatch):
        monkeypatch.setenv("__OW_API_HOST", "https://host.example.net")
        monkeypatch.setenv("__OW_NAMESPACE", "my-ns")
        monkeypatch.setenv("__OW_API_KEY", "k:secret")

        creds = Sandbox.resolve_credentials(api_host=None, namespace=None, auth=None)
        assert creds["api_host"] == "https://host.example.net"
        assert creds["namespace"] == "my-ns"
        assert creds["api_key"] == "k:secret"

    def test_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("__OW_API_HOST", "https://env.example.net")
        monkeypatch.setenv("__OW_NAMESPACE", "env-ns")
        monkeypatch.setenv("__OW_API_KEY", "env-key")

        creds = Sandbox.resolve_credentials(
            api_host="https://explicit.example.net",
            namespace="explicit-ns",
            auth="explicit-key",
        )
        assert creds["api_host"] == "https://explicit.example.net"
        assert creds["namespace"] == "explicit-ns"
        assert creds["api_key"] == "explicit-key"

    def test_prepends_https(self):
        creds = Sandbox.resolve_credentials(api_host="host.example.net", namespace="ns", auth="key")
        assert creds["api_host"] == "https://host.example.net"

    def test_missing_credentials_raise(self):
        with pytest.raises(SandboxInitializationError, match="Missing required credentials"):
            Sandbox.resolve_credentials(api_host=None, namespace=None, auth=None)


# ---------------------------------------------------------------------------
# SANDBOX_SIZES
# ---------------------------------------------------------------------------


class TestSandboxSizes:
    def test_sizes_are_present(self):
        assert "SMALL" in SANDBOX_SIZES
        assert "MEDIUM" in SANDBOX_SIZES
        assert "LARGE" in SANDBOX_SIZES
        assert "XLARGE" in SANDBOX_SIZES

    def test_sizes_class_attr(self):
        assert Sandbox.sizes is SANDBOX_SIZES


# ---------------------------------------------------------------------------
# Sandbox.create()
# ---------------------------------------------------------------------------


class TestSandboxCreate:
    @pytest.mark.asyncio
    async def test_create_calls_api_and_connects(self, monkeypatch):
        payload = {
            "sandboxId": "sb-new",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-new/exec",
            "status": "ready",
            "token": "tok-new",
            "maxLifetime": 3600,
            "previewUrls": {
                "3000": "https://sb-new-3000.preview.example.net",
            },
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req,
            patch.object(Sandbox, "connect", new=AsyncMock()) as mock_connect,
        ):
            sandbox = await Sandbox.create(
                name="my-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.id == "sb-new"
        assert sandbox.status == "ready"
        assert sandbox.preview_urls == {
            3000: "https://sb-new-3000.preview.example.net",
        }
        mock_req.assert_called_once()
        mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_forwards_policy(self, monkeypatch):
        policy = {"network": {"egress": [{"host": "api.github.com", "port": 443}]}}
        payload = {
            "sandboxId": "sb-pol",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-pol/exec",
            "status": "ready",
            "token": "tok-pol",
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req,
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            await Sandbox.create(
                name="policy-sb",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
                policy=policy,
            )

        _, kwargs = mock_req.call_args
        assert kwargs["body"]["policy"] == policy

    @pytest.mark.asyncio
    async def test_create_reads_env_vars(self, monkeypatch):
        monkeypatch.setenv("__OW_API_HOST", "https://runtime.example.net")
        monkeypatch.setenv("__OW_NAMESPACE", "ns")
        monkeypatch.setenv("__OW_API_KEY", "uuid:key")

        payload = {
            "sandboxId": "sb-env",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-env/exec",
            "status": "ready",
            "token": "tok-env",
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)),
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            sandbox = await Sandbox.create(name="env-sandbox")

        assert sandbox.id == "sb-env"

    @pytest.mark.asyncio
    async def test_create_raises_when_creds_missing(self):
        with pytest.raises(SandboxInitializationError):
            await Sandbox.create(name="no-creds")

    @pytest.mark.asyncio
    async def test_create_builds_ws_endpoint_when_absent(self, monkeypatch):
        payload = {
            "sandboxId": "sb-noep",
            "status": "ready",
            "token": "tok",
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)),
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            sandbox = await Sandbox.create(
                name="no-endpoint",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.endpoint is not None
        assert "sb-noep" in sandbox.endpoint
        assert sandbox.endpoint.startswith("wss://")

    @pytest.mark.asyncio
    async def test_create_forwards_ports_and_parses_preview_urls(self):
        payload = {
            "sandboxId": "sb-ports",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-ports/exec",
            "status": "ready",
            "token": "tok-ports",
            "maxLifetime": 3600,
            "previewUrls": {
                "3000": "https://sb-ports-3000.preview.example.net",
                "8080": "https://sb-ports-8080.preview.example.net",
            },
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req,
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            sandbox = await Sandbox.create(
                name="ports-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
                ports=[3000, 8080],
            )

        _, kwargs = mock_req.call_args
        assert kwargs["body"]["ports"] == [3000, 8080]
        assert sandbox.preview_urls == {
            3000: "https://sb-ports-3000.preview.example.net",
            8080: "https://sb-ports-8080.preview.example.net",
        }
        assert sandbox.get_url(3000) == "https://sb-ports-3000.preview.example.net"

    @pytest.mark.asyncio
    async def test_create_sends_default_idle_timeout_and_max_lifetime(self):
        payload = {
            "sandboxId": "sb-defaults",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-defaults/exec",
            "status": "ready",
            "token": "tok-defaults",
            "idleTimeout": 900,
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req,
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            await Sandbox.create(
                name="defaults-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        _, kwargs = mock_req.call_args
        assert kwargs["body"]["idleTimeout"] == 900
        assert kwargs["body"]["maxLifetime"] == 3600

    @pytest.mark.asyncio
    async def test_create_forwards_explicit_idle_timeout(self):
        payload = {
            "sandboxId": "sb-idle",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-idle/exec",
            "status": "ready",
            "token": "tok-idle",
            "idleTimeout": 1800,
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req,
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            await Sandbox.create(
                name="idle-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
                idle_timeout=1800,
            )

        _, kwargs = mock_req.call_args
        assert kwargs["body"]["idleTimeout"] == 1800

    @pytest.mark.asyncio
    async def test_create_stores_idle_timeout_from_response(self):
        payload = {
            "sandboxId": "sb-store",
            "wsEndpoint": "wss://runtime.example.net/api/v1/namespaces/ns/sandboxes/sb-store/exec",
            "status": "ready",
            "token": "tok-store",
            "idleTimeout": 1800,
            "maxLifetime": 3600,
        }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)),
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            sandbox = await Sandbox.create(
                name="store-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
                idle_timeout=1800,
            )

        assert sandbox.idle_timeout == 1800


# ---------------------------------------------------------------------------
# WebSocket connection
# ---------------------------------------------------------------------------


class TestWebSocketConnection:
    @pytest.mark.asyncio
    async def test_connect_opens_socket_authenticates_and_starts_listener(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
            verify_ssl=False,
        )
        ws = AsyncMock()

        async def noop_listen():
            return None

        with (
            patch("aio_lib_sandbox.ws.websockets.connect", new=AsyncMock(return_value=ws)) as connect,
            patch.object(session, "authenticate", new=AsyncMock()) as authenticate,
            patch.object(session, "listen", new=noop_listen),
        ):
            await session.connect()
            await session.listener_task

        assert session.ws is ws
        connect.assert_awaited_once()
        assert connect.await_args.kwargs["ssl"].check_hostname is False
        authenticate.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_connect_is_idempotent_when_socket_exists(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )
        session.ws = AsyncMock()

        with patch("aio_lib_sandbox.ws.websockets.connect", new=AsyncMock()) as connect:
            await session.connect()

        connect.assert_not_called()

    @pytest.mark.asyncio
    async def test_connect_wraps_websocket_connect_errors(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )

        with patch(
            "aio_lib_sandbox.ws.websockets.connect",
            new=AsyncMock(side_effect=OSError("network down")),
        ):
            with pytest.raises(SandboxWebSocketError, match="Could not connect sandbox"):
                await session.connect()

    @pytest.mark.asyncio
    async def test_authenticate_rejects_non_ack_frame(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )
        session.ws = AsyncMock()
        session.ws.recv = AsyncMock(return_value=json.dumps({"type": "auth.error"}))

        with pytest.raises(SandboxUnauthorizedError, match="rejected"):
            await session.authenticate()

        session.ws.send.assert_awaited_once_with(json.dumps({"type": "auth", "token": "tok-abc"}))

    def test_ensure_open_raises_when_socket_missing(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )

        with pytest.raises(SandboxWebSocketError, match="is not connected"):
            session.ensure_open()

    @pytest.mark.asyncio
    async def test_listen_routes_frames_and_clears_socket(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )
        session.ws = _AsyncFrameStream(
            "not-json",
            json.dumps({"type": "auth.ok", "sandboxId": "sb-test"}),
            json.dumps({"type": "exec.info", "execId": "get-1"}),
            json.dumps({"type": "file.content", "execId": "file-1"}),
            json.dumps({"type": "exec.output", "execId": "exec-1"}),
        )
        session.pending_get_ops["get-1"] = PendingGetOp(future=asyncio.get_running_loop().create_future())
        session.pending_file_ops["file-1"] = PendingFileOp(future=asyncio.get_running_loop().create_future())
        session.pending_execs["exec-1"] = PendingExec(future=asyncio.get_running_loop().create_future())
        session.handle_get_frame = MagicMock()
        session.handle_file_frame = MagicMock()
        session.handle_exec_frame = MagicMock()

        await session.listen()

        session.handle_get_frame.assert_called_once_with({"type": "exec.info", "execId": "get-1"})
        session.handle_file_frame.assert_called_once_with({"type": "file.content", "execId": "file-1"})
        session.handle_exec_frame.assert_called_once_with({"type": "exec.output", "execId": "exec-1"})
        assert session.ws is None

    @pytest.mark.asyncio
    async def test_listen_rejects_pending_on_unintentional_close(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )
        future = asyncio.get_running_loop().create_future()
        session.pending_execs["exec-1"] = PendingExec(future=future)
        session.ws = _AsyncFrameStream(websockets.ConnectionClosedError(None, None))

        await session.listen()

        with pytest.raises(SandboxWebSocketError, match="closed with code 1006"):
            await future
        assert session.ws is None

    @pytest.mark.asyncio
    async def test_listen_resolves_pending_on_intentional_close(self):
        session = WsSession(
            sandbox_id="sb-test",
            endpoint="wss://runtime.example.net/ws",
            token="tok-abc",
        )
        future = asyncio.get_running_loop().create_future()
        session.pending_execs["exec-1"] = PendingExec(future=future)
        session.intentional_close = True
        session.ws = _AsyncFrameStream(websockets.ConnectionClosedError(None, None))

        await session.listen()

        assert await future == ExecResult(
            exec_id="exec-1",
            stdout="",
            stderr="",
            exit_code=None,
            destroyed=True,
        )
        assert session.ws is None
        assert session.intentional_close is False


# ---------------------------------------------------------------------------
# Sandbox.get()
# ---------------------------------------------------------------------------


class TestSandboxGet:
    @pytest.mark.asyncio
    async def test_get_returns_sandbox_with_status(self):
        payload = {
            "sandboxId": "sb-get",
            "status": "running",
            "cluster": "cluster-b",
            "region": "va6",
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)):
            sandbox = await Sandbox.get(
                "sb-get",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.id == "sb-get"
        assert sandbox.status == "running"
        assert sandbox.cluster == "cluster-b"
        assert sandbox.session is None

    @pytest.mark.asyncio
    async def test_get_parses_preview_urls(self):
        payload = {
            "sandboxId": "sb-get",
            "status": "running",
            "previewUrls": {
                "3000": "https://sb-get-3000.preview.example.net",
            },
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)):
            sandbox = await Sandbox.get(
                "sb-get",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.preview_urls == {3000: "https://sb-get-3000.preview.example.net"}
        assert sandbox.get_url(3000) == "https://sb-get-3000.preview.example.net"

    @pytest.mark.asyncio
    async def test_get_stores_idle_timeout_from_response(self):
        payload = {
            "sandboxId": "sb-get-idle",
            "status": "running",
            "idleTimeout": 1200,
            "maxLifetime": 3600,
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)):
            sandbox = await Sandbox.get(
                "sb-get-idle",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.idle_timeout == 1200

    @pytest.mark.asyncio
    async def test_get_routes_through_management_endpoint(self):
        payload = {"sandboxId": "sb-mgmt", "status": "running"}

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req:
            sandbox = await Sandbox.get(
                "sb-mgmt",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
                management_endpoint="https://sb-mgmt.mgmt.example.net",
            )

        args, _ = mock_req.call_args
        # api_request is called positionally: (method, url, ...)
        assert args[1] == "https://sb-mgmt.mgmt.example.net/api/v1/namespaces/ns/sandboxes/sb-mgmt"
        assert sandbox.management_endpoint == "https://sb-mgmt.mgmt.example.net"

    @pytest.mark.asyncio
    async def test_get_not_found_raises(self):
        with patch(
            "aio_lib_sandbox.sandbox.api_request",
            new=AsyncMock(side_effect=SandboxNotFoundError("not found")),
        ):
            with pytest.raises(SandboxNotFoundError):
                await Sandbox.get(
                    "missing",
                    api_host="https://runtime.example.net",
                    namespace="ns",
                    auth="key",
                )

    @pytest.mark.asyncio
    async def test_get_unauthorized_raises(self):
        with patch(
            "aio_lib_sandbox.sandbox.api_request",
            new=AsyncMock(side_effect=SandboxUnauthorizedError("unauthorized")),
        ):
            with pytest.raises(SandboxUnauthorizedError):
                await Sandbox.get(
                    "sb-x",
                    api_host="https://runtime.example.net",
                    namespace="ns",
                    auth="bad",
                )


# ---------------------------------------------------------------------------
# exec
# ---------------------------------------------------------------------------


class TestExec:
    @pytest.mark.asyncio
    async def test_exec_resolves_with_result(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        task = sandbox.exec("echo hello")
        exec_id = task.exec_id

        # simulate send completing
        await asyncio.sleep(0)

        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": exec_id, "stream": "stdout", "data": "hello\n"}
        )
        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": exec_id, "exitCode": 0})

        result = await task
        assert result.stdout == "hello\n"
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_exec_accumulates_stderr(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        task = sandbox.exec("cmd")
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": exec_id, "stream": "stderr", "data": "err\n"}
        )
        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": exec_id, "exitCode": 1})

        result = await task
        assert result.stderr == "err\n"
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_exec_calls_on_output_callback(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        chunks = []

        task = sandbox.exec("cmd", on_output=lambda data, stream: chunks.append((data, stream)))
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame({"type": "exec.output", "execId": exec_id, "stream": "stdout", "data": "a"})
        sandbox.session.handle_exec_frame({"type": "exec.output", "execId": exec_id, "stream": "stderr", "data": "b"})
        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": exec_id, "exitCode": 0})

        await task
        assert chunks == [("a", "stdout"), ("b", "stderr")]

    @pytest.mark.asyncio
    async def test_exec_timeout(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        task = sandbox.exec("sleep 100", timeout=50)  # 50 ms
        exec_id = task.exec_id

        await asyncio.sleep(0)

        # Fire the timeout callback manually
        sandbox.session.timeout_exec(exec_id, "sleep 100", 50)

        with pytest.raises(SandboxTimeoutError):
            await task

    @pytest.mark.asyncio
    async def test_exec_error_frame_rejects(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        task = sandbox.exec("bad-cmd")
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame({"type": "error", "execId": exec_id, "message": "command not found"})

        with pytest.raises(SandboxClientError, match="command not found"):
            await task

    def test_exec_raises_when_not_connected(self):
        sandbox = Sandbox(**BASE_OPTS)
        with pytest.raises(SandboxWebSocketError):
            sandbox.exec("cmd")

    def test_handle_exec_frame_ignores_missing_pending_exec(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.handle_exec_frame({"type": "exec.output", "execId": "exec-missing", "data": "ignored"})


# ---------------------------------------------------------------------------
# File operations
# ---------------------------------------------------------------------------


class TestFileOps:
    @pytest.mark.asyncio
    async def test_read_file_base64_content(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        with patch.object(sandbox, "file_op", new=AsyncMock(return_value="console.log('hi')")):
            result = await sandbox.read_file("/app/hello.js")

        assert result == "console.log('hi')"

    @pytest.mark.asyncio
    async def test_write_file_encodes_content_and_delegates(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        write_result = WriteResult(path="/app/hello.js", ok=True, size=17)

        with patch.object(sandbox, "file_op", new=AsyncMock(return_value=write_result)) as file_op:
            result = await sandbox.write_file("/app/hello.js", "console.log('hi')")

        assert result is write_result
        file_op.assert_awaited_once_with(
            "file.write",
            path="/app/hello.js",
            content=base64.b64encode(b"console.log('hi')").decode(),
            encoding="base64",
        )

    @pytest.mark.asyncio
    async def test_read_file_via_frame_handler(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        loop = asyncio.get_running_loop()
        exec_id = "file-abc123"
        future: asyncio.Future[str] = loop.create_future()
        sandbox.session.pending_file_ops[exec_id] = PendingFileOp(future=future)

        encoded = base64.b64encode(b"hello world").decode()
        sandbox.session.handle_file_frame(
            {"type": "file.content", "execId": exec_id, "content": encoded, "encoding": "base64"}
        )

        result = await future
        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_write_file_result(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        loop = asyncio.get_running_loop()
        exec_id = "file-wrt123"
        future: asyncio.Future[WriteResult] = loop.create_future()
        sandbox.session.pending_file_ops[exec_id] = PendingFileOp(future=future)

        sandbox.session.handle_file_frame(
            {"type": "file.writeResult", "execId": exec_id, "path": "/app/x.js", "size": 20, "ok": True}
        )

        result = await future
        assert isinstance(result, WriteResult)
        assert result.ok is True
        assert result.size == 20

    @pytest.mark.asyncio
    async def test_write_file_failure(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        loop = asyncio.get_running_loop()
        exec_id = "file-bad"
        future: asyncio.Future[WriteResult] = loop.create_future()
        sandbox.session.pending_file_ops[exec_id] = PendingFileOp(future=future)

        sandbox.session.handle_file_frame(
            {"type": "file.writeResult", "execId": exec_id, "path": "/readonly", "ok": False}
        )

        with pytest.raises(SandboxClientError):
            await future

    @pytest.mark.asyncio
    async def test_list_files(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        loop = asyncio.get_running_loop()
        exec_id = "file-ls"
        future: asyncio.Future[list[FileEntry]] = loop.create_future()
        sandbox.session.pending_file_ops[exec_id] = PendingFileOp(future=future)

        entries = [
            {"name": "hello.js", "type": "file", "size": 42},
            {"name": "src", "type": "directory"},
        ]
        sandbox.session.handle_file_frame({"type": "file.entries", "execId": exec_id, "entries": entries})

        result = await future
        assert len(result) == 2
        assert result[0].name == "hello.js"
        assert result[1].type == "directory"

    @pytest.mark.asyncio
    async def test_list_files_empty(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        loop = asyncio.get_running_loop()
        exec_id = "file-ls-empty"
        future: asyncio.Future[list[FileEntry]] = loop.create_future()
        sandbox.session.pending_file_ops[exec_id] = PendingFileOp(future=future)

        sandbox.session.handle_file_frame({"type": "file.entries", "execId": exec_id})

        result = await future
        assert result == []

    def test_handle_file_frame_ignores_missing_pending_operation(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.handle_file_frame({"type": "file.content", "execId": "file-missing", "content": "ignored"})

    @pytest.mark.asyncio
    async def test_file_error_frame_rejects_pending_operation(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        future = asyncio.get_running_loop().create_future()
        sandbox.session.pending_file_ops["file-err"] = PendingFileOp(future=future)

        sandbox.session.handle_file_frame({"type": "error", "execId": "file-err", "message": "read failed"})

        with pytest.raises(SandboxClientError, match="read failed"):
            await future


# ---------------------------------------------------------------------------
# get_url
# ---------------------------------------------------------------------------


class TestGetUrl:
    def test_resolves_url_from_preview_urls(self):
        sandbox = _make_sandbox(preview_urls={3000: "https://sb-test-3000.preview.example.net"})
        url = sandbox.get_url(3000)
        assert url == "https://sb-test-3000.preview.example.net"

    def test_raises_when_port_not_provisioned(self):
        sandbox = _make_sandbox()
        with pytest.raises(SandboxPortNotProvisionedError):
            sandbox.get_url(3000)

    def test_raises_on_out_of_range_port(self):
        sandbox = _make_sandbox(preview_urls={3000: "https://sb-test-3000.preview.example.net"})
        with pytest.raises(SandboxInvalidPortError):
            sandbox.get_url(0)
        with pytest.raises(SandboxInvalidPortError):
            sandbox.get_url(65536)

    def test_raises_on_non_integer_port(self):
        sandbox = _make_sandbox(preview_urls={3000: "https://sb-test-3000.preview.example.net"})
        with pytest.raises(SandboxInvalidPortError):
            sandbox.get_url("3000")
        with pytest.raises(SandboxInvalidPortError):
            sandbox.get_url(3000.5)


# ---------------------------------------------------------------------------
# destroy
# ---------------------------------------------------------------------------


class TestDestroy:
    @pytest.mark.asyncio
    async def test_destroy_calls_delete_and_closes(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"status": "destroyed"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.delete = AsyncMock(return_value=mock_resp)

        with patch("aio_lib_sandbox.sandbox.httpx.AsyncClient", return_value=mock_client):
            result = await sandbox.destroy()

        assert result["status"] == "destroyed"
        assert sandbox.status == "destroyed"
        ws.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_destroy_resolves_pending_foreground_exec(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"status": "destroyed"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.delete = AsyncMock(return_value=mock_resp)

        task = sandbox.exec("sleep 100")
        await asyncio.sleep(0)

        with patch("aio_lib_sandbox.sandbox.httpx.AsyncClient", return_value=mock_client):
            await sandbox.destroy()

        result = await task
        assert result == ExecResult(
            exec_id=task.exec_id,
            stdout="",
            stderr="",
            exit_code=None,
            destroyed=True,
        )

    @pytest.mark.asyncio
    async def test_destroy_resolves_detached_wait(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.json.return_value = {"status": "destroyed"}

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.delete = AsyncMock(return_value=mock_resp)

        task = sandbox.exec("sleep infinity", detached=True)
        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame(
            {"type": "exec.detached", "execId": task.exec_id, "pid": 1234, "startedAt": 100}
        )
        handle = await task
        wait_task = asyncio.create_task(handle.wait())

        with patch("aio_lib_sandbox.sandbox.httpx.AsyncClient", return_value=mock_client):
            await sandbox.destroy()

        assert await wait_task == {"exit_code": None, "destroyed": True}

    @pytest.mark.asyncio
    async def test_destroy_raises_on_401(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 401
        mock_resp.text = "unauthorized"

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.delete = AsyncMock(return_value=mock_resp)

        with patch("aio_lib_sandbox.sandbox.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(SandboxUnauthorizedError):
                await sandbox.destroy()

    @pytest.mark.asyncio
    async def test_destroy_wraps_http_client_errors_and_clears_intentional_close(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.delete = AsyncMock(side_effect=httpx.HTTPError("boom"))

        with patch("aio_lib_sandbox.sandbox.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(SandboxClientError, match="Could not destroy sandbox"):
                await sandbox.destroy()

        assert sandbox.session.intentional_close is False


# ---------------------------------------------------------------------------
# WebSocket close drains pending operations
# ---------------------------------------------------------------------------


class TestWebSocketClose:
    @pytest.mark.asyncio
    async def test_reject_all_pending_on_close(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        loop = asyncio.get_running_loop()

        exec_future: asyncio.Future[ExecResult] = loop.create_future()
        sandbox.session.pending_execs["exec-1"] = PendingExec(future=exec_future)

        file_future: asyncio.Future[str] = loop.create_future()
        sandbox.session.pending_file_ops["file-1"] = PendingFileOp(future=file_future)

        sandbox.session.reject_all(SandboxWebSocketError("closed"))

        with pytest.raises(SandboxWebSocketError):
            await exec_future

        with pytest.raises(SandboxWebSocketError):
            await file_future

    @pytest.mark.asyncio
    async def test_reject_all_rejects_pending_get_operations(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        loop = asyncio.get_running_loop()
        get_future = loop.create_future()
        sandbox.session.pending_get_ops["exec-1"] = PendingGetOp(future=get_future)

        sandbox.session.reject_all(SandboxWebSocketError("closed"))

        with pytest.raises(SandboxWebSocketError, match="closed"):
            await get_future

    @pytest.mark.asyncio
    async def test_register_file_op_tracks_pending_operation(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        pending = PendingFileOp(future=asyncio.get_running_loop().create_future())

        sandbox.session.register_file_op("file-1", pending)

        assert sandbox.session.pending_file_ops["file-1"] is pending

    def test_reject_pending_ignores_missing_operation(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.reject_pending(
            sandbox.session.pending_file_ops,
            "file-missing",
            SandboxWebSocketError("closed"),
        )

        assert sandbox.session.pending_file_ops == {}

    @pytest.mark.asyncio
    async def test_close_with_intentional_flag_resolves_pending_and_cancels_listener(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        exec_future = asyncio.get_running_loop().create_future()
        sandbox.session.pending_execs["exec-1"] = PendingExec(future=exec_future)
        sandbox.session.listener_task = asyncio.create_task(asyncio.sleep(60))

        await sandbox.session.close(intentional=True)

        assert await exec_future == ExecResult(
            exec_id="exec-1",
            stdout="",
            stderr="",
            exit_code=None,
            destroyed=True,
        )
        assert sandbox.session.listener_task is None
        assert sandbox.session.ws is None
        assert sandbox.session.intentional_close is False
        ws.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_resolve_all_on_intentional_close_resolves_file_and_get_ops(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        loop = asyncio.get_running_loop()
        file_future = loop.create_future()
        get_future = loop.create_future()
        sandbox.session.pending_file_ops["file-1"] = PendingFileOp(future=file_future)
        sandbox.session.pending_get_ops["exec-1"] = PendingGetOp(future=get_future)

        sandbox.session.resolve_all_on_intentional_close()

        assert await file_future is None
        assert await get_future is None

    @pytest.mark.asyncio
    async def test_resolve_detached_before_ack_on_intentional_close(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        task = sandbox.exec("sleep infinity", detached=True)
        await asyncio.sleep(0)

        sandbox.session.resolve_exec_on_intentional_close(task.exec_id)

        handle = await task
        assert handle.pid is None
        assert handle.started_at is None
        assert await handle.wait() == {"exit_code": None, "destroyed": True}

    def test_resolve_exec_on_intentional_close_ignores_missing_exec(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.resolve_exec_on_intentional_close("exec-missing")

    @pytest.mark.asyncio
    async def test_resolve_exec_on_intentional_close_cancels_timeout_handle(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        future = asyncio.get_running_loop().create_future()
        timeout_handle = MagicMock()
        sandbox.session.pending_execs["exec-1"] = PendingExec(
            future=future,
            timeout_handle=timeout_handle,
        )

        sandbox.session.resolve_exec_on_intentional_close("exec-1")

        timeout_handle.cancel.assert_called_once()
        assert await future == ExecResult(
            exec_id="exec-1",
            stdout="",
            stderr="",
            exit_code=None,
            destroyed=True,
        )

    def test_reject_exec_ignores_missing_exec(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.reject_exec("exec-missing", SandboxWebSocketError("closed"))

    @pytest.mark.asyncio
    async def test_reject_exec_cancels_timeout_handle(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        future = asyncio.get_running_loop().create_future()
        timeout_handle = MagicMock()
        sandbox.session.pending_execs["exec-1"] = PendingExec(
            future=future,
            timeout_handle=timeout_handle,
        )

        sandbox.session.reject_exec("exec-1", SandboxWebSocketError("closed"))

        timeout_handle.cancel.assert_called_once()
        with pytest.raises(SandboxWebSocketError, match="closed"):
            await future

    @pytest.mark.asyncio
    async def test_wait_for_exec_start_blocks_until_started(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        loop = asyncio.get_running_loop()
        pending = PendingExec(future=loop.create_future())
        sandbox.session.pending_execs["exec-1"] = pending

        waiter = asyncio.create_task(sandbox.session.wait_for_exec_start("exec-1"))
        await asyncio.sleep(0)
        assert not waiter.done()

        pending.started.set()
        await waiter

    def test_timeout_exec_still_rejects_when_no_running_loop(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        loop = asyncio.new_event_loop()
        try:
            future = loop.create_future()
            sandbox.session.pending_execs["exec-1"] = PendingExec(future=future)

            sandbox.session.timeout_exec("exec-1", "sleep 10", 1000)

            assert future.done()
            with pytest.raises(SandboxTimeoutError):
                future.result()
        finally:
            loop.close()


# ---------------------------------------------------------------------------
# Policy passthrough (mirrors aio-lib-runtime-python tests)
# ---------------------------------------------------------------------------


class TestBuildCreateBodyPolicy:
    """Verify policy is forwarded correctly in the create request body."""

    @pytest.mark.asyncio
    async def test_policy_with_egress_rules(self):
        policy = {
            "network": {
                "egress": [
                    {"host": "api.github.com", "port": 443},
                    {"host": "*.adobe.io", "port": 443},
                ]
            }
        }
        captured = {}

        async def _mock_req(method, url, *, api_key, body=None, **kw):
            captured["body"] = body
            return {
                "sandboxId": "sb-pol",
                "wsEndpoint": "wss://x/ws",
                "status": "ready",
                "token": "t",
                "maxLifetime": 3600,
            }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=_mock_req),
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            await Sandbox.create(
                name="sb",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="key",
                policy=policy,
            )

        assert captured["body"]["policy"] == policy

    @pytest.mark.asyncio
    async def test_no_policy_omitted_from_body(self):
        captured = {}

        async def _mock_req(method, url, *, api_key, body=None, **kw):
            captured["body"] = body
            return {
                "sandboxId": "sb-nopol",
                "wsEndpoint": "wss://x/ws",
                "status": "ready",
                "token": "t",
                "maxLifetime": 3600,
            }

        with (
            patch("aio_lib_sandbox.sandbox.api_request", new=_mock_req),
            patch.object(Sandbox, "connect", new=AsyncMock()),
        ):
            await Sandbox.create(
                name="sb",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="key",
            )

        assert "policy" not in captured["body"]


# ---------------------------------------------------------------------------
# Detached exec
# ---------------------------------------------------------------------------


class TestDetachedExec:
    @pytest.mark.asyncio
    async def test_exec_detached_resolves_with_handle_on_exec_detached(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        task = sandbox.exec("npm run dev", detached=True)
        exec_id = task.exec_id

        await asyncio.sleep(0)

        sandbox.session.handle_exec_frame(
            {"type": "exec.detached", "execId": exec_id, "pid": 9999, "startedAt": 1234567890}
        )

        handle = await task
        assert isinstance(handle, DetachedCommandHandle)
        assert handle.exec_id == exec_id
        assert handle.pid == 9999
        assert handle.started_at == 1234567890
        assert handle.detached is True

    @pytest.mark.asyncio
    async def test_exec_detached_wait_resolves_on_exec_exit(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        task = sandbox.exec("sleep 100", detached=True)
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame({"type": "exec.detached", "execId": exec_id, "pid": 1234, "startedAt": 1000})

        handle = await task

        wait_coro = handle.wait()
        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": exec_id, "exitCode": 0})

        result = await wait_coro
        assert result["exit_code"] == 0

    @pytest.mark.asyncio
    async def test_exec_detached_output_frames_delivered_after_detached_ack(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        chunks = []
        task = sandbox.exec("npm run dev", detached=True, on_output=lambda d, s: chunks.append((d, s)))
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame({"type": "exec.detached", "execId": exec_id, "pid": 9000, "startedAt": 1})
        await task

        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": exec_id, "stream": "stdout", "data": "compiled\n"}
        )
        assert chunks == [("compiled\n", "stdout")]

    @pytest.mark.asyncio
    async def test_exec_detached_error_after_ack_rejects_wait(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        task = sandbox.exec("bad-cmd", detached=True)
        exec_id = task.exec_id

        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame({"type": "exec.detached", "execId": exec_id, "pid": 1, "startedAt": 1})
        handle = await task

        wait_coro = handle.wait()
        sandbox.session.handle_exec_frame({"type": "error", "execId": exec_id, "message": "process crashed"})

        with pytest.raises(SandboxClientError, match="process crashed"):
            await wait_coro

    def test_exec_detached_with_timeout_raises(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        with pytest.raises(SandboxClientError, match="timeout"):
            sandbox.exec("cmd", detached=True, timeout=1000)

    @pytest.mark.asyncio
    async def test_detached_handle_forwards_stdin_and_kill_helpers(self):
        sandbox = _make_sandbox()
        wait_future = asyncio.get_running_loop().create_future()
        handle = DetachedCommandHandle(
            exec_id="exec-1",
            pid=1234,
            started_at=100,
            detached=True,
            wait_future=wait_future,
            sandbox_ref=sandbox,
        )
        sandbox.write_stdin = AsyncMock()
        sandbox.close_stdin = AsyncMock()
        sandbox.kill = AsyncMock()

        await handle.write_stdin("input")
        await handle.close_stdin()
        await handle.kill("SIGKILL")

        sandbox.write_stdin.assert_awaited_once_with("exec-1", "input")
        sandbox.close_stdin.assert_awaited_once_with("exec-1")
        sandbox.kill.assert_awaited_once_with("exec-1", "SIGKILL")

    @pytest.mark.asyncio
    async def test_detached_ack_cancels_timeout_handle(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        wait_future = loop.create_future()
        timeout_handle = MagicMock()
        sandbox.session.pending_execs["exec-1"] = PendingExec(
            future=future,
            timeout_handle=timeout_handle,
            detached=True,
            wait_future=wait_future,
        )

        sandbox.session.handle_exec_frame({"type": "exec.detached", "execId": "exec-1", "pid": 1234, "startedAt": 100})

        timeout_handle.cancel.assert_called_once()
        assert sandbox.session.pending_execs["exec-1"].timeout_handle is None

    @pytest.mark.asyncio
    async def test_exec_exit_cancels_timeout_handle(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        future = asyncio.get_running_loop().create_future()
        timeout_handle = MagicMock()
        sandbox.session.pending_execs["exec-1"] = PendingExec(
            future=future,
            timeout_handle=timeout_handle,
        )

        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": "exec-1", "exitCode": 0})

        timeout_handle.cancel.assert_called_once()
        assert (await future).exit_code == 0


# ---------------------------------------------------------------------------
# get_command
# ---------------------------------------------------------------------------


class TestGetCommand:
    @pytest.mark.asyncio
    async def test_get_command_resolves_with_handle_on_exec_info(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        loop = asyncio.get_event_loop()
        coro = sandbox.get_command("exec-d1e2f3a4")
        task = loop.create_task(coro)

        await asyncio.sleep(0)

        sandbox.session.handle_get_frame(
            {
                "type": "exec.info",
                "execId": "exec-d1e2f3a4",
                "command": "npm run dev",
                "pid": 5678,
                "startedAt": 1711036812,
                "detached": True,
            }
        )

        handle = await task
        assert isinstance(handle, DetachedCommandHandle)
        assert handle.exec_id == "exec-d1e2f3a4"
        assert handle.command == "npm run dev"
        assert handle.pid == 5678
        assert handle.started_at == 1711036812

    @pytest.mark.asyncio
    async def test_get_command_wait_resolves_on_exec_exit(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        loop = asyncio.get_event_loop()
        coro = sandbox.get_command("exec-reattach")
        get_task = loop.create_task(coro)

        await asyncio.sleep(0)
        sandbox.session.handle_get_frame(
            {
                "type": "exec.info",
                "execId": "exec-reattach",
                "command": "sleep 60",
                "pid": 1111,
                "startedAt": 100,
                "detached": True,
            }
        )

        handle = await get_task
        wait_coro = handle.wait()

        sandbox.session.handle_exec_frame({"type": "exec.exit", "execId": "exec-reattach", "exitCode": 143})

        result = await wait_coro
        assert result["exit_code"] == 143

    @pytest.mark.asyncio
    async def test_get_command_raises_command_not_found_on_error(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()

        loop = asyncio.get_event_loop()
        coro = sandbox.get_command("exec-gone")
        get_task = loop.create_task(coro)

        await asyncio.sleep(0)
        sandbox.session.handle_get_frame(
            {
                "type": "error",
                "execId": "exec-gone",
                "code": "NOT_FOUND",
                "message": "no running process for execId",
            }
        )

        with pytest.raises(SandboxCommandNotFoundError):
            await get_task

    @pytest.mark.asyncio
    async def test_get_command_reuses_existing_exec_and_merges_output_callbacks(self):
        sandbox = _make_sandbox()
        ws = _inject_ws(sandbox)
        ws.send = AsyncMock()
        original_chunks = []
        reattached_chunks = []

        task = sandbox.exec(
            "npm run dev",
            detached=True,
            on_output=lambda data, stream: original_chunks.append((data, stream)),
        )
        await asyncio.sleep(0)
        sandbox.session.handle_exec_frame(
            {"type": "exec.detached", "execId": task.exec_id, "pid": 1234, "startedAt": 100}
        )
        original_handle = await task

        get_task = asyncio.create_task(
            sandbox.get_command(
                task.exec_id,
                on_output=lambda data, stream: reattached_chunks.append((data, stream)),
            )
        )
        await asyncio.sleep(0)
        sandbox.session.handle_get_frame(
            {
                "type": "exec.info",
                "execId": task.exec_id,
                "command": "npm run dev",
                "pid": 1234,
                "startedAt": 100,
                "detached": True,
            }
        )
        reattached_handle = await get_task

        assert reattached_handle._wait_future is original_handle._wait_future
        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": task.exec_id, "stream": "stderr", "data": "ready\n"}
        )
        assert original_chunks == [("ready\n", "stderr")]
        assert reattached_chunks == [("ready\n", "stderr")]

    @pytest.mark.asyncio
    async def test_merge_on_output_callback_ignores_missing_new_callback(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)
        chunks = []
        pending = PendingExec(
            future=asyncio.get_running_loop().create_future(),
            on_output=lambda data, stream: chunks.append((data, stream)),
        )

        sandbox.session.merge_on_output_callback(pending, None)
        pending.on_output("line\n", "stdout")

        assert chunks == [("line\n", "stdout")]

    def test_handle_get_frame_ignores_missing_pending_operation(self):
        sandbox = _make_sandbox()
        _inject_ws(sandbox)

        sandbox.session.handle_get_frame({"type": "exec.info", "execId": "exec-missing"})


# ---------------------------------------------------------------------------
# _parse_preview_urls
# ---------------------------------------------------------------------------


class TestParsePreviewUrls:
    def test_returns_empty_for_non_dict(self):
        assert _parse_preview_urls(None) == {}
        assert _parse_preview_urls("string") == {}
        assert _parse_preview_urls(42) == {}
        assert _parse_preview_urls([]) == {}

    def test_parses_string_keys_to_int(self):
        raw = {"3000": "https://sb-3000.example.net", "8080": "https://sb-8080.example.net"}
        result = _parse_preview_urls(raw)
        assert result == {
            3000: "https://sb-3000.example.net",
            8080: "https://sb-8080.example.net",
        }

    def test_skips_non_integer_keys(self):
        raw = {"3000": "https://sb-3000.example.net", "notaport": "https://sb-x.example.net"}
        result = _parse_preview_urls(raw)
        assert result == {3000: "https://sb-3000.example.net"}

    def test_skips_out_of_range_ports(self):
        raw = {
            "0": "https://zero.example.net",
            "65536": "https://toobig.example.net",
            "3000": "https://sb-3000.example.net",
        }
        result = _parse_preview_urls(raw)
        assert result == {3000: "https://sb-3000.example.net"}

    def test_skips_non_string_url_values(self):
        raw = {"3000": 12345, "8080": "https://sb-8080.example.net"}
        result = _parse_preview_urls(raw)
        assert result == {8080: "https://sb-8080.example.net"}

    def test_returns_empty_for_empty_dict(self):
        assert _parse_preview_urls({}) == {}
