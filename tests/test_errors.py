from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sourcequorum import (
    CommitError,
    ErrorCode,
    GateRejectedError,
    InputError,
    IntegrityError,
    SourceQuorumError,
)


def test_error_codes_are_the_frozen_v01_taxonomy() -> None:
    """Changing an error code breaks safe, machine-readable findings."""
    assert {code.name: code.value for code in ErrorCode} == {
        "INVALID_POLICY": "SQ100",
        "INVALID_SOURCE_MANIFEST": "SQ101",
        "UNSAFE_PATH": "SQ102",
        "SYMLINK_FORBIDDEN": "SQ103",
        "SOURCE_HASH_MISMATCH": "SQ104",
        "RESOURCE_LIMIT_EXCEEDED": "SQ105",
        "INVALID_JSON": "SQ106",
        "SOURCE_COUNT_TOO_LOW": "SQ200",
        "CANDIDATE_COUNT_INVALID": "SQ201",
        "SOURCE_ID_DUPLICATE": "SQ202",
        "ORIGIN_NOT_INDEPENDENT": "SQ203",
        "SOURCE_NOT_FRESH": "SQ204",
        "JSONL_INVALID": "SQ205",
        "RECORD_SCHEMA_MISMATCH": "SQ206",
        "DUPLICATE_RECORD_KEY": "SQ207",
        "KEY_SET_MISMATCH": "SQ208",
        "VALUE_CONFLICT": "SQ209",
        "GATE_REJECTED": "SQ210",
        "MANIFEST_INVALID": "SQ300",
        "RELEASE_ID_MISMATCH": "SQ301",
        "MEMBER_MISSING": "SQ302",
        "MEMBER_TAMPERED": "SQ303",
        "UNEXPECTED_MEMBER": "SQ304",
        "IMMUTABLE_TARGET_CONFLICT": "SQ400",
    }


def test_exception_hierarchy_partitions_error_categories() -> None:
    """Using the wrong base class prevents callers from handling a category safely."""
    assert issubclass(InputError, SourceQuorumError)
    assert issubclass(GateRejectedError, SourceQuorumError)
    assert issubclass(IntegrityError, SourceQuorumError)
    assert issubclass(CommitError, SourceQuorumError)


def test_exception_rendering_uses_only_the_safe_code_and_message() -> None:
    """Rendering context would disclose local locations or source values."""
    raw_path = Path("restricted/records.jsonl").absolute()
    raw_value = "unrenderable-source-value"
    error = InputError(
        ErrorCode.INVALID_JSON,
        {"distinctive_key": 918273645, "accepted": False, "count": None},
    )

    rendered = str(error)
    representation = repr(error)

    assert error.code is ErrorCode.INVALID_JSON
    assert error.context == {"distinctive_key": 918273645, "accepted": False, "count": None}
    assert ErrorCode.INVALID_JSON.value in rendered
    assert "distinctive_key" not in rendered
    assert "918273645" not in rendered
    assert "distinctive_key" not in representation
    assert "918273645" not in representation
    assert raw_path.as_posix() not in rendered
    assert raw_value not in rendered
    assert raw_path.as_posix() not in representation
    assert raw_value not in representation


@pytest.mark.parametrize("value", ["raw context", Path("unsafe-context").absolute(), 1.5, object()])
def test_exception_rejects_unsafe_context_values(value: object) -> None:
    """Allowing arbitrary context values creates a future unsafe-rendering channel."""
    unsafe_context = cast(Mapping[str, int | bool | None], {"detail": value})
    with pytest.raises(TypeError, match="context") as raised:
        SourceQuorumError(ErrorCode.INVALID_POLICY, unsafe_context)
    assert str(value) not in str(raised.value)
    assert str(value) not in repr(raised.value)
