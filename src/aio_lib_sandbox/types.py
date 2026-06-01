# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Public types, dataclasses, and constants for the sandbox SDK."""

from __future__ import annotations

import asyncio
from collections.abc import Generator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, List, Optional, Union

if TYPE_CHECKING:
    pass


# ------------------------------------------------------------------
# Size constants
# ------------------------------------------------------------------

SANDBOX_SIZES: dict[str, dict[str, Any]] = {
    "SMALL": {"cpu": "500m", "memory": "512Mi", "gpu": 0},
    "MEDIUM": {"cpu": "2000m", "memory": "4Gi", "gpu": 0},
    "LARGE": {"cpu": "4000m", "memory": "16Gi", "gpu": 0},
    "XLARGE": {"cpu": "8000m", "memory": "32Gi", "gpu": 1},
}

# ------------------------------------------------------------------
# Result types
# ------------------------------------------------------------------


@dataclass
class ExecResult:
    exec_id: str
    stdout: str
    stderr: str
    exit_code: int | None
    destroyed: bool = False


@dataclass
class WriteResult:
    path: str
    size: int
    ok: bool


@dataclass
class FileEntry:
    name: str
    type: str
    size: int | None = None


# ------------------------------------------------------------------
# Awaitable exec handle
# ------------------------------------------------------------------


class ExecTask:
    """Awaitable handle for a running command.

    Mirrors the JS SDK pattern: ``exec()`` returns synchronously with an
    ``exec_id`` attribute you can pass to ``write_stdin`` / ``close_stdin``
    while the command runs, then ``await`` the task to get the
    :class:`ExecResult`.
    """

    def __init__(self, exec_id: str, _task: asyncio.Task[ExecResult]) -> None:
        self.exec_id = exec_id
        self._task = _task

    def __await__(self) -> Generator[Any, None, ExecResult]:
        return self._task.__await__()


class DetachedCommandHandle:
    """Handle for a detached background command.

    Returned by ``await sandbox.exec(cmd, detached=True)`` once the process has
    started.  Use :meth:`wait` to block until the process exits,
    :meth:`write_stdin` / :meth:`close_stdin` to interact with stdin, and
    :meth:`kill` to terminate it.

    Do not instantiate directly — use :meth:`Sandbox.exec` with
    ``detached=True`` or :meth:`Sandbox.get_command`.
    """

    def __init__(
        self,
        exec_id: str,
        pid: int,
        started_at: int,
        detached: bool,
        wait_future: asyncio.Future[Any],
        sandbox_ref: Any,
        command: Optional[str] = None,
    ) -> None:
        self.exec_id = exec_id
        self.pid = pid
        self.started_at = started_at
        self.detached = detached
        self.command = command
        self._wait_future = wait_future
        self._sandbox = sandbox_ref

    async def wait(self) -> dict[str, Any]:
        """Wait for the process to exit.

        Returns:
            ``{"exit_code": int}`` when the process terminates.
        """
        return await self._wait_future

    async def write_stdin(self, data: Union[str, bytes]) -> None:
        """Write data to the process stdin."""
        await self._sandbox.write_stdin(self.exec_id, data)

    async def close_stdin(self) -> None:
        """Close stdin, sending EOF to the process."""
        await self._sandbox.close_stdin(self.exec_id)

    async def kill(self, signal: str = "SIGTERM") -> None:
        """Send a signal to the process."""
        await self._sandbox.kill(self.exec_id, signal)


# ------------------------------------------------------------------
# Network policy TypedDicts
# ------------------------------------------------------------------

try:
    from typing import TypedDict
except ImportError:
    from typing_extensions import TypedDict  # type: ignore[assignment]


class L7Rule(TypedDict, total=False):
    """An HTTP-layer (L7) match rule for an egress entry."""

    methods: List[str]
    pathPattern: str


class EgressRule(TypedDict, total=False):
    """A single egress allowlist entry."""

    host: str
    port: int
    protocol: str
    rules: List[L7Rule]


class NetworkPolicyOptions(TypedDict, total=False):
    """Network policy configuration."""

    egress: Union[List[EgressRule], str]


class Policy(TypedDict, total=False):
    """Sandbox policy configuration."""

    network: NetworkPolicyOptions
