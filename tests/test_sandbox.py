# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aio_lib_sandbox import (
    SANDBOX_SIZES,
    ExecResult,
    FileEntry,
    Sandbox,
    WriteResult,
)
from aio_lib_sandbox.errors import (
    SandboxClientError,
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
from aio_lib_sandbox.ws import PendingExec, PendingFileOp, WsSession

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_OPTS = dict(
    sandbox_id="sb-test",
    endpoint="wss://runtime.example.net/ws/v1/namespaces/ns/sandbox/sb-test/exec",
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
        creds = Sandbox.resolve_credentials(
            api_host="host.example.net", namespace="ns", auth="key"
        )
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
            "wsEndpoint": "wss://runtime.example.net/ws/v1/namespaces/ns/sandbox/sb-new/exec",
            "status": "ready",
            "token": "tok-new",
            "maxLifetime": 3600,
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req, \
             patch.object(Sandbox, "connect", new=AsyncMock()) as mock_connect:
            sandbox = await Sandbox.create(
                name="my-sandbox",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="uuid:key",
            )

        assert sandbox.id == "sb-new"
        assert sandbox.status == "ready"
        mock_req.assert_called_once()
        mock_connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_forwards_policy(self, monkeypatch):
        policy = {"network": {"egress": [{"host": "api.github.com", "port": 443}]}}
        payload = {
            "sandboxId": "sb-pol",
            "wsEndpoint": "wss://runtime.example.net/ws/v1/namespaces/ns/sandbox/sb-pol/exec",
            "status": "ready",
            "token": "tok-pol",
            "maxLifetime": 3600,
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req, \
             patch.object(Sandbox, "connect", new=AsyncMock()):
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
            "wsEndpoint": "wss://runtime.example.net/ws/v1/namespaces/ns/sandbox/sb-env/exec",
            "status": "ready",
            "token": "tok-env",
            "maxLifetime": 3600,
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)), \
             patch.object(Sandbox, "connect", new=AsyncMock()):
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

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)), \
             patch.object(Sandbox, "connect", new=AsyncMock()):
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
            "wsEndpoint": "wss://runtime.example.net/ws/v1/namespaces/ns/sandbox/sb-ports/exec",
            "status": "ready",
            "token": "tok-ports",
            "maxLifetime": 3600,
            "previewUrls": {
                "3000": "https://sb-ports-3000.preview.example.net",
                "8080": "https://sb-ports-8080.preview.example.net",
            },
        }

        with patch("aio_lib_sandbox.sandbox.api_request", new=AsyncMock(return_value=payload)) as mock_req, \
             patch.object(Sandbox, "connect", new=AsyncMock()):
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
        sandbox.session.handle_exec_frame(
            {"type": "exec.exit", "execId": exec_id, "exitCode": 0}
        )

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
        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": exec_id, "stream": "stdout", "data": "a"}
        )
        sandbox.session.handle_exec_frame(
            {"type": "exec.output", "execId": exec_id, "stream": "stderr", "data": "b"}
        )
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
        sandbox.session.handle_exec_frame(
            {"type": "error", "execId": exec_id, "message": "command not found"}
        )

        with pytest.raises(SandboxClientError, match="command not found"):
            await task

    def test_exec_raises_when_not_connected(self):
        sandbox = Sandbox(**BASE_OPTS)
        with pytest.raises(SandboxWebSocketError):
            sandbox.exec("cmd")


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
        sandbox.session.handle_file_frame(
            {"type": "file.entries", "execId": exec_id, "entries": entries}
        )

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

        with patch("aio_lib_sandbox.sandbox.api_request", new=_mock_req), \
             patch.object(Sandbox, "connect", new=AsyncMock()):
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

        with patch("aio_lib_sandbox.sandbox.api_request", new=_mock_req), \
             patch.object(Sandbox, "connect", new=AsyncMock()):
            await Sandbox.create(
                name="sb",
                api_host="https://runtime.example.net",
                namespace="ns",
                auth="key",
            )

        assert "policy" not in captured["body"]


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
        raw = {"0": "https://zero.example.net", "65536": "https://toobig.example.net",
               "3000": "https://sb-3000.example.net"}
        result = _parse_preview_urls(raw)
        assert result == {3000: "https://sb-3000.example.net"}

    def test_skips_non_string_url_values(self):
        raw = {"3000": 12345, "8080": "https://sb-8080.example.net"}
        result = _parse_preview_urls(raw)
        assert result == {8080: "https://sb-8080.example.net"}

    def test_returns_empty_for_empty_dict(self):
        assert _parse_preview_urls({}) == {}
