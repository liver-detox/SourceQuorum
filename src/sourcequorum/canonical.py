"""Strict RFC 8785 JSON helpers for stable local content identities."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from typing import Any, cast

import rfc8785

from .errors import ErrorCode, InputError
from .models import JsonValue

_MIN_SAFE_INTEGER = -(2**53) + 1
_MAX_SAFE_INTEGER = (2**53) - 1


def _invalid_json() -> InputError:
    return InputError(ErrorCode.INVALID_JSON)


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_nonfinite_constant(_: str) -> object:
    raise ValueError("non-finite number")


def loads_strict(data: str | bytes) -> JsonValue:
    """Decode UTF-8 JSON while rejecting duplicate keys and nonstandard numbers."""
    try:
        if isinstance(data, bytes):
            text = data.decode("utf-8")
        elif isinstance(data, str):
            text = data
        else:
            raise TypeError("data")
        loaded = cast(
            JsonValue,
            json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_constant,
            ),
        )
        if not _is_json_value(loaded) or not _has_valid_unicode(loaded):
            raise ValueError("invalid Unicode")
        return loaded
    except (RecursionError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise _invalid_json() from None


def _is_json_value(value: object, active_containers: set[int] | None = None) -> bool:
    if active_containers is None:
        active_containers = set()
    if value is None or isinstance(value, (str, bool)):
        return True
    if isinstance(value, int):
        return _MIN_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return _has_only_json_list_values(value, active_containers)
    if isinstance(value, dict):
        return _has_only_json_object_values(value, active_containers)
    return False


def _has_only_json_list_values(values: list[object], active_containers: set[int]) -> bool:
    container_id = id(values)
    if container_id in active_containers:
        return False
    active_containers.add(container_id)
    try:
        return all(_is_json_value(value, active_containers) for value in values)
    finally:
        active_containers.remove(container_id)


def _has_only_json_object_values(values: dict[object, object], active_containers: set[int]) -> bool:
    container_id = id(values)
    if container_id in active_containers:
        return False
    active_containers.add(container_id)
    try:
        return all(
            isinstance(key, str) and _is_json_value(value, active_containers)
            for key, value in values.items()
        )
    finally:
        active_containers.remove(container_id)


def _has_valid_unicode(value: JsonValue) -> bool:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, list):
        return all(_has_valid_unicode(item) for item in value)
    if isinstance(value, dict):
        return all(
            _has_valid_unicode(key) and _has_valid_unicode(item) for key, item in value.items()
        )
    return True


def dumps_canonical(value: object) -> bytes:
    """Encode a JSON-domain value as RFC 8785 bytes without unsafe extensions."""
    try:
        if not _is_json_value(value):
            raise ValueError("invalid JSON domain")
        return rfc8785.dumps(cast(Any, value))
    except (RecursionError, rfc8785.CanonicalizationError, TypeError, ValueError):
        raise _invalid_json() from None


def frame_jsonl(values: Iterable[JsonValue]) -> bytes:
    """Return canonical records framed by exactly one line-feed each."""
    return b"".join(dumps_canonical(value) + b"\n" for value in values)


def sha256_bytes(data: bytes) -> str:
    """Return the full lowercase SHA-256 digest of bytes."""
    if not isinstance(data, bytes):
        raise ValueError("data")
    return hashlib.sha256(data).hexdigest()
