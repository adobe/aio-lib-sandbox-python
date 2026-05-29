# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.

"""Adobe Runtime Sandbox SDK — standalone compute sandbox client for Python."""

from __future__ import annotations

__version__ = "0.1.0a1"

from .errors import (
    SandboxClientError,
    SandboxInitializationError,
    SandboxInvalidPortError,
    SandboxNotFoundError,
    SandboxPortNotProvisionedError,
    SandboxSDKError,
    SandboxTimeoutError,
    SandboxUnauthorizedError,
    SandboxWebSocketError,
)
from .sandbox import Sandbox
from .types import (
    SANDBOX_SIZES,
    EgressRule,
    ExecResult,
    ExecTask,
    FileEntry,
    L7Rule,
    NetworkPolicyOptions,
    Policy,
    WriteResult,
)

__all__ = [
    "Sandbox",
    "ExecResult",
    "ExecTask",
    "WriteResult",
    "FileEntry",
    "SANDBOX_SIZES",
    "L7Rule",
    "EgressRule",
    "NetworkPolicyOptions",
    "Policy",
    "SandboxSDKError",
    "SandboxInitializationError",
    "SandboxClientError",
    "SandboxInvalidPortError",
    "SandboxNotFoundError",
    "SandboxPortNotProvisionedError",
    "SandboxUnauthorizedError",
    "SandboxTimeoutError",
    "SandboxWebSocketError",
]
