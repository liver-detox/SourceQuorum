"""Embedded Draft 2020-12 contracts for SourceQuorum's persisted JSON."""

from __future__ import annotations

from importlib.resources import files
from jsonschema import Draft202012Validator, FormatChecker, ValidationError  # type: ignore[import-untyped]

from .canonical import loads_strict
from .errors import ErrorCode, InputError
from .models import JsonValue

SCHEMA_NAMES = ("policy", "source", "gate-report", "release-manifest")

_RESOURCE_NAMES = {
    "policy": "policy-v1.schema.json",
    "source": "source-v1.schema.json",
    "gate-report": "gate-report-v1.schema.json",
    "release-manifest": "release-manifest-v1.schema.json",
}

_ERROR_CODES = {
    "policy": ErrorCode.INVALID_POLICY,
    "source": ErrorCode.INVALID_SOURCE_MANIFEST,
    "gate-report": ErrorCode.MANIFEST_INVALID,
    "release-manifest": ErrorCode.MANIFEST_INVALID,
}


def _resource_name(name: str) -> str:
    if name not in _RESOURCE_NAMES:
        raise ValueError("schema_name")
    return _RESOURCE_NAMES[name]


def schema_bytes(name: str) -> bytes:
    """Return the original UTF-8 schema bytes embedded with the package."""
    return files("sourcequorum").joinpath("_schemas", _resource_name(name)).read_bytes()


def load_schema(name: str) -> dict[str, JsonValue]:
    """Parse a fresh independent schema mapping on every call."""
    loaded = loads_strict(schema_bytes(name))
    if not isinstance(loaded, dict):
        raise RuntimeError("embedded schema")
    return loaded


def validate_document(name: str, document: object) -> None:
    """Validate a persisted JSON document without rendering unsafe details on failure."""
    _resource_name(name)
    try:
        Draft202012Validator(load_schema(name), format_checker=FormatChecker()).validate(document)
    except ValidationError:
        raise InputError(_ERROR_CODES[name]) from None
