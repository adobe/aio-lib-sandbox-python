# Copyright 2026 Adobe. All rights reserved.
# Licensed under the Apache License, Version 2.0.


class SandboxSDKError(Exception):
    """Base error for the Adobe Runtime Sandbox SDK."""

    def __init__(self, message: str = "") -> None:
        self.message = message
        super().__init__(message)


class SandboxInitializationError(SandboxSDKError):
    """Missing or invalid credentials passed to Sandbox.create() or Sandbox.get()."""


class SandboxClientError(SandboxSDKError):
    """General sandbox API / client error."""


class SandboxNotFoundError(SandboxSDKError):
    """Sandbox resource was not found (HTTP 404)."""


class SandboxUnauthorizedError(SandboxSDKError):
    """Authentication or authorization failure (HTTP 401/403)."""


class SandboxTimeoutError(SandboxSDKError):
    """Sandbox operation timed out (HTTP 504 or exec timeout)."""


class SandboxWebSocketError(SandboxSDKError):
    """WebSocket transport error."""


class SandboxPortNotProvisionedError(SandboxSDKError):
    """Port was not declared in ``create(ports=[...])`` and cannot be retrieved."""
