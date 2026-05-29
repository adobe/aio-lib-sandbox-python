# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

from __future__ import annotations

import asyncio
import base64
import os
import secrets
from typing import Any, Callable

import httpx

from .frames import normalize_size
from .http import (
    api_request,
    build_auth_header,
    build_ws_endpoint,
    normalize_api_host,
    sandbox_http_error,
)
from .ws import PendingExec, PendingFileOp, WsSession
from .errors import (
    SandboxClientError,
    SandboxInitializationError,
    SandboxPortNotProvisionedError,
    SandboxWebSocketError,
)
from .types import (
    SANDBOX_SIZES,
    ExecResult,
    ExecTask,
    FileEntry,
    Policy,
    WriteResult,
)


class Sandbox:
    """Connected compute sandbox session.

    Use :meth:`create` or :meth:`get` — do not instantiate directly.
    """

    sizes = SANDBOX_SIZES

    def __init__(
        self,
        *,
        sandbox_id: str,
        endpoint: str | None,
        status: str,
        cluster: str | None = None,
        region: str | None = None,
        max_lifetime: int = 3600,
        namespace: str,
        api_host: str,
        api_key: str,
        token: str | None = None,
        preview_urls: dict[int, str] | None = None,
        management_endpoint: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self.id = sandbox_id
        self.endpoint = endpoint
        self.status = status
        self.cluster = cluster
        self.region = region
        self.max_lifetime = max_lifetime

        self.namespace = namespace
        self.api_host = api_host
        self.api_key = api_key
        self.token = token
        self.preview_urls: dict[int, str] = preview_urls or {}
        self.management_endpoint = management_endpoint
        self.verify_ssl = verify_ssl

        self.session: WsSession | None = None

    # ------------------------------------------------------------------
    # Static factories
    # ------------------------------------------------------------------

    @classmethod
    async def create(
        cls,
        *,
        name: str | None = None,
        api_host: str | None = None,
        namespace: str | None = None,
        auth: str | None = None,
        type: str = "cpu:default",
        size: str | dict[str, Any] | None = None,
        max_lifetime: int = 3600,
        ports: list[int] | None = None,
        envs: dict[str, str] | None = None,
        policy: Policy | None = None,
        cluster: str | None = None,
        region: str | None = None,
        verify_ssl: bool = True,
        timeout: float = 120.0,
    ) -> "Sandbox":
        """Create a new sandbox and open its WebSocket session.

        Credentials are read from the environment automatically when running
        inside a Runtime action (``__OW_API_HOST``, ``__OW_NAMESPACE``,
        ``__OW_API_KEY``). Any value passed explicitly overrides the
        environment.

        Commands run inside the sandbox start in the ``/workspace`` directory
        by default.

        Args:
            name: Sandbox display name.
            api_host: Runtime API host (overrides ``__OW_API_HOST``).
            namespace: Runtime namespace (overrides ``__OW_NAMESPACE``).
            auth: Runtime API key (overrides ``__OW_API_KEY``).
            type: Sandbox type (default: ``'cpu:default'``).
            size: Size tier name or spec dict.
            max_lifetime: Maximum lifetime in seconds.
            ports: TCP ports to expose via preview URLs (default: ``[]``).
            envs: Environment variables to inject into the sandbox.
            policy: Network policy (e.g. egress allowlist).
            cluster: Target cluster name.
            region: Target region (e.g. ``'va6'``).
            verify_ssl: Whether to verify TLS certificates.
            timeout: HTTP request timeout in seconds.

        Returns:
            A connected :class:`Sandbox` instance.
        """
        creds = cls.resolve_credentials(api_host=api_host, namespace=namespace, auth=auth)

        body: dict[str, Any] = {
            "name": name,
            "size": normalize_size(size),
            "type": type,
            "maxLifetime": max_lifetime,
        }
        if cluster is not None:
            body["cluster"] = cluster
        if region is not None:
            body["region"] = region
        if envs is not None:
            body["envs"] = envs
        if policy is not None:
            body["policy"] = policy
        if ports is not None:
            body["ports"] = ports

        url = f"{creds['api_host']}/api/v1/namespaces/{creds['namespace']}/sandbox"
        payload = await api_request(
            "POST",
            url,
            api_key=creds["api_key"],
            body=body,
            verify_ssl=verify_ssl,
            timeout=timeout,
            operation="create sandbox",
        )

        sandbox_id = payload["sandboxId"]
        endpoint = payload.get("wsEndpoint") or build_ws_endpoint(
            creds["api_host"], creds["namespace"], sandbox_id
        )

        sandbox = cls(
            sandbox_id=sandbox_id,
            endpoint=endpoint,
            status=payload.get("status", ""),
            cluster=payload.get("cluster"),
            region=payload.get("region"),
            max_lifetime=payload.get("maxLifetime", 3600),
            preview_urls=_parse_preview_urls(payload.get("previewUrls")),
            management_endpoint=payload.get("managementEndpoint"),
            namespace=creds["namespace"],
            api_host=creds["api_host"],
            api_key=creds["api_key"],
            token=payload["token"],
            verify_ssl=verify_ssl,
        )

        await sandbox.connect()
        return sandbox

    @classmethod
    async def get(
        cls,
        sandbox_id: str,
        *,
        api_host: str | None = None,
        namespace: str | None = None,
        auth: str | None = None,
        verify_ssl: bool = True,
    ) -> "Sandbox":
        """Fetch the current status of an existing sandbox.

        Credentials are read from the environment automatically.

        Args:
            sandbox_id: ID of the sandbox to look up.
            api_host: Runtime API host override.
            namespace: Runtime namespace override.
            auth: Runtime API key override.
            verify_ssl: Whether to verify TLS certificates.

        Returns:
            A :class:`Sandbox` instance with ``status`` populated.
            This instance is **not** WebSocket-connected.
        """
        creds = cls.resolve_credentials(api_host=api_host, namespace=namespace, auth=auth)
        url = f"{creds['api_host']}/api/v1/namespaces/{creds['namespace']}/sandbox/{sandbox_id}"
        payload = await api_request(
            "GET",
            url,
            api_key=creds["api_key"],
            verify_ssl=verify_ssl,
            operation="get sandbox status",
        )

        return cls(
            sandbox_id=payload.get("sandboxId", sandbox_id),
            endpoint=None,
            status=payload.get("status", ""),
            cluster=payload.get("cluster"),
            region=payload.get("region"),
            max_lifetime=payload.get("maxLifetime", 3600),
            preview_urls=_parse_preview_urls(payload.get("previewUrls")),
            namespace=creds["namespace"],
            api_host=creds["api_host"],
            api_key=creds["api_key"],
            verify_ssl=verify_ssl,
        )

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        if self.session is None:
            self.session = WsSession(
                sandbox_id=self.id,
                endpoint=self.endpoint,
                token=self.token,
                verify_ssl=self.verify_ssl,
            )
        await self.session.connect()

    # ------------------------------------------------------------------
    # Exec
    # ------------------------------------------------------------------

    def exec(
        self,
        command: str,
        *,
        timeout: float | None = None,
        on_output: Callable[[str, str], None] | None = None,
        stdin: str | bytes | None = None,
    ) -> ExecTask:
        """Execute a command inside the sandbox.

        Returns an :class:`ExecTask` that can be ``await``-ed for the result.
        The task's ``exec_id`` attribute can be used with
        :meth:`write_stdin` / :meth:`close_stdin` before awaiting.

        Args:
            command: Shell command to run.
            timeout: Timeout in milliseconds (not seconds).
            on_output: Callback invoked with ``(data, stream)`` for each chunk.
            stdin: Data to write to stdin at startup.

        Returns:
            An :class:`ExecTask` that resolves to an :class:`ExecResult`.
        """
        self.ensure_open()
        exec_id = f"exec-{secrets.token_hex(12)}"
        loop = asyncio.get_running_loop()
        future: asyncio.Future[ExecResult] = loop.create_future()
        pending = PendingExec(future=future, on_output=on_output)

        if timeout is not None:
            pending.timeout_handle = loop.call_later(
                timeout / 1000,
                self.session.timeout_exec,
                exec_id,
                command,
                timeout,
            )

        self.session.register_exec(exec_id, pending)

        async def _run() -> ExecResult:
            await self.session.send_frame(
                {"type": "exec.run", "execId": exec_id, "command": command}
            )
            pending.started.set()
            if stdin is not None:
                await self.write_stdin(exec_id, stdin)
                await self.close_stdin(exec_id)
            return await future

        return ExecTask(exec_id=exec_id, _task=loop.create_task(_run()))

    async def kill(self, exec_id: str, signal: str = "SIGTERM") -> None:
        """Send a signal to a running command."""
        self.ensure_open()
        await self.session.send_frame({"type": "exec.kill", "execId": exec_id, "signal": signal})

    async def write_stdin(self, exec_id: str, data: str | bytes) -> None:
        """Write data to the stdin of a running command."""
        self.ensure_open()
        await self.session.wait_for_exec_start(exec_id)
        frame: dict[str, Any] = {"type": "exec.input", "execId": exec_id}
        if isinstance(data, bytes):
            frame["data"] = base64.b64encode(data).decode()
            frame["encoding"] = "base64"
        else:
            frame["data"] = data
        await self.session.send_frame(frame)

    async def close_stdin(self, exec_id: str) -> None:
        """Close stdin for a running command, signalling EOF."""
        self.ensure_open()
        await self.session.wait_for_exec_start(exec_id)
        await self.session.send_frame({"type": "exec.endInput", "execId": exec_id})

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    async def read_file(self, path: str) -> str:
        """Read a file from the sandbox filesystem.

        Returns:
            File contents as a UTF-8 string.
        """
        return await self.file_op("file.read", path=path)

    async def write_file(self, path: str, content: str | bytes) -> WriteResult:
        """Write a file to the sandbox filesystem.

        Parent directories are created automatically.

        Returns:
            A :class:`WriteResult` confirmation.
        """
        encoded = base64.b64encode(
            content if isinstance(content, bytes) else content.encode()
        ).decode()
        return await self.file_op(
            "file.write", path=path, content=encoded, encoding="base64"
        )

    async def list_files(self, path: str) -> list[FileEntry]:
        """List the contents of a directory inside the sandbox.

        Returns:
            A list of :class:`FileEntry` objects.
        """
        return await self.file_op("file.list", path=path)

    async def file_op(self, frame_type: str, **extra: Any) -> Any:
        self.ensure_open()
        exec_id = f"file-{secrets.token_hex(12)}"
        loop = asyncio.get_running_loop()
        future: asyncio.Future[Any] = loop.create_future()
        self.session.register_file_op(exec_id, PendingFileOp(future=future))
        await self.session.send_frame({"type": frame_type, "execId": exec_id, **extra})
        return await future

    # ------------------------------------------------------------------
    # URL
    # ------------------------------------------------------------------

    def get_url(self, port: int) -> str:
        """Return the public preview URL for a given port on this sandbox.

        Synchronous local lookup against the ``preview_urls`` dict returned by
        the server at create time. The URL is opaque — do not parse or
        reconstruct it.

        Args:
            port: Port number (1–65535) declared in ``create(ports=[...])``.

        Returns:
            The preview URL string for that port.

        Raises:
            SandboxPortNotProvisionedError: When ``port`` is invalid or was
                not declared in ``create(ports=[...])``.
        """
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise SandboxPortNotProvisionedError(
                f"Invalid port '{port}': must be an integer between 1 and 65535"
            )

        url = self.preview_urls.get(port)
        if url is None:
            raise SandboxPortNotProvisionedError(
                f"Port {port} was not provisioned for sandbox '{self.id}'. "
                "Declare it in create(ports=[...]) to get a preview URL."
            )
        return url

    # ------------------------------------------------------------------
    # Destroy
    # ------------------------------------------------------------------

    async def destroy(self) -> dict[str, Any]:
        """Destroy the sandbox and close its WebSocket connection.

        Returns:
            The destroy response payload.
        """
        base = self.management_endpoint or self.api_host
        url = f"{base}/api/v1/namespaces/{self.namespace}/sandbox/{self.id}"
        headers = {"Authorization": build_auth_header(self.api_key)}

        async with httpx.AsyncClient(verify=self.verify_ssl) as client:
            try:
                resp = await client.delete(url, headers=headers)
            except httpx.HTTPError as exc:
                raise SandboxClientError(
                    f"Could not destroy sandbox '{self.id}': {exc}"
                ) from exc

        if not resp.is_success:
            msg = resp.text
            detail = f"Could not destroy sandbox '{self.id}': {resp.status_code}{f' {msg}' if msg else ''}"
            raise sandbox_http_error(resp.status_code, detail)

        payload = resp.json()
        self.status = payload.get("status", self.status)
        if self.session:
            await self.session.close()
        return payload

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def ensure_open(self) -> None:
        if self.session is None:
            raise SandboxWebSocketError(f"Sandbox '{self.id}' is not connected")
        self.session.ensure_open()

    @classmethod
    def resolve_credentials(
        cls,
        *,
        api_host: str | None,
        namespace: str | None,
        auth: str | None,
    ) -> dict[str, str]:
        """Merge explicit credentials with environment variable fallbacks.

        Reads ``__OW_API_HOST``, ``__OW_NAMESPACE``, and ``__OW_API_KEY``
        from the environment when the corresponding argument is ``None``.

        Returns:
            A dict with ``api_host``, ``namespace``, and ``api_key``.

        Raises:
            SandboxInitializationError: When any credential is missing.
        """
        resolved_host = api_host or os.environ.get("__OW_API_HOST")
        resolved_ns = namespace or os.environ.get("__OW_NAMESPACE")
        resolved_key = auth or os.environ.get("__OW_API_KEY")

        missing = [
            name
            for name, val in [
                ("api_host", resolved_host),
                ("namespace", resolved_ns),
                ("auth", resolved_key),
            ]
            if not val
        ]

        if missing:
            raise SandboxInitializationError(
                f"Missing required credentials: {', '.join(missing)}. "
                "Pass them explicitly or set __OW_API_HOST, __OW_NAMESPACE, "
                "__OW_API_KEY in the environment."
            )

        return {
            "api_host": normalize_api_host(resolved_host),  # type: ignore[arg-type]
            "namespace": resolved_ns,  # type: ignore[return-value]
            "api_key": resolved_key,  # type: ignore[return-value]
        }


def _parse_preview_urls(raw: Any) -> dict[int, str]:
    """Parse the ``previewUrls`` JSON object from the API response.

    Converts string keys (port numbers) to integers and treats URL values as
    opaque strings — they are not parsed or reconstructed.

    Returns an empty dict when the server response omits ``previewUrls``
    (fail-closed: every ``get_url()`` call raises
    :exc:`SandboxPortNotProvisionedError`).
    """
    if not isinstance(raw, dict):
        return {}
    result: dict[int, str] = {}
    for key, value in raw.items():
        try:
            port = int(key)
        except (ValueError, TypeError):
            continue
        if 1 <= port <= 65535 and isinstance(value, str):
            result[port] = value
    return result
