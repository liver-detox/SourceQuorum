"""Safe errors for SourceQuorum's local, fail-closed API."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType


class ErrorCode(str, Enum):
    """Stable machine-readable error codes."""

    INVALID_POLICY = "SQ100"
    INVALID_SOURCE_MANIFEST = "SQ101"
    UNSAFE_PATH = "SQ102"
    SYMLINK_FORBIDDEN = "SQ103"
    SOURCE_HASH_MISMATCH = "SQ104"
    RESOURCE_LIMIT_EXCEEDED = "SQ105"
    INVALID_JSON = "SQ106"
    SOURCE_COUNT_TOO_LOW = "SQ200"
    CANDIDATE_COUNT_INVALID = "SQ201"
    SOURCE_ID_DUPLICATE = "SQ202"
    ORIGIN_NOT_INDEPENDENT = "SQ203"
    SOURCE_NOT_FRESH = "SQ204"
    JSONL_INVALID = "SQ205"
    RECORD_SCHEMA_MISMATCH = "SQ206"
    DUPLICATE_RECORD_KEY = "SQ207"
    KEY_SET_MISMATCH = "SQ208"
    VALUE_CONFLICT = "SQ209"
    GATE_REJECTED = "SQ210"
    MANIFEST_INVALID = "SQ300"
    RELEASE_ID_MISMATCH = "SQ301"
    MEMBER_MISSING = "SQ302"
    MEMBER_TAMPERED = "SQ303"
    UNEXPECTED_MEMBER = "SQ304"
    IMMUTABLE_TARGET_CONFLICT = "SQ400"


_SAFE_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INVALID_POLICY: "invalid policy",
    ErrorCode.INVALID_SOURCE_MANIFEST: "invalid source manifest",
    ErrorCode.UNSAFE_PATH: "unsafe path",
    ErrorCode.SYMLINK_FORBIDDEN: "symlink forbidden",
    ErrorCode.SOURCE_HASH_MISMATCH: "source hash mismatch",
    ErrorCode.RESOURCE_LIMIT_EXCEEDED: "resource limit exceeded",
    ErrorCode.INVALID_JSON: "invalid JSON",
    ErrorCode.SOURCE_COUNT_TOO_LOW: "source count too low",
    ErrorCode.CANDIDATE_COUNT_INVALID: "candidate count invalid",
    ErrorCode.SOURCE_ID_DUPLICATE: "duplicate source ID",
    ErrorCode.ORIGIN_NOT_INDEPENDENT: "origin groups are not independent",
    ErrorCode.SOURCE_NOT_FRESH: "source not fresh",
    ErrorCode.JSONL_INVALID: "invalid JSONL",
    ErrorCode.RECORD_SCHEMA_MISMATCH: "record schema mismatch",
    ErrorCode.DUPLICATE_RECORD_KEY: "duplicate record key",
    ErrorCode.KEY_SET_MISMATCH: "record key sets differ",
    ErrorCode.VALUE_CONFLICT: "value conflict",
    ErrorCode.GATE_REJECTED: "gate rejected",
    ErrorCode.MANIFEST_INVALID: "invalid manifest",
    ErrorCode.RELEASE_ID_MISMATCH: "release ID mismatch",
    ErrorCode.MEMBER_MISSING: "required member missing",
    ErrorCode.MEMBER_TAMPERED: "member integrity failure",
    ErrorCode.UNEXPECTED_MEMBER: "unexpected member",
    ErrorCode.IMMUTABLE_TARGET_CONFLICT: "immutable target conflict",
}

SafeContextValue = int | bool | None


class SourceQuorumError(Exception):
    """Base error whose rendered form cannot disclose contextual input."""

    code: ErrorCode
    context: Mapping[str, SafeContextValue]

    def __init__(
        self,
        code: ErrorCode,
        context: Mapping[str, SafeContextValue] | None = None,
    ) -> None:
        if not isinstance(code, ErrorCode):
            raise TypeError("code")
        safe_context: dict[str, SafeContextValue] = {}
        if context is not None:
            if not isinstance(context, Mapping):
                raise TypeError("context")
            for key, value in context.items():
                if not isinstance(key, str) or not isinstance(value, (int, bool, type(None))):
                    raise TypeError("context")
                safe_context[key] = value
        self.code = code
        self.context = MappingProxyType(safe_context)
        super().__init__(code)

    def __str__(self) -> str:
        return f"{self.code.value}: {_SAFE_MESSAGES[self.code]}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.code.value})"


class InputError(SourceQuorumError):
    """An input or local source is malformed or unsafe."""


class GateRejectedError(SourceQuorumError):
    """A quorum gate rejected otherwise well-formed inputs."""


class IntegrityError(SourceQuorumError):
    """Stored content does not match its declared identity."""


class CommitError(SourceQuorumError):
    """An immutable commit could not be completed."""
