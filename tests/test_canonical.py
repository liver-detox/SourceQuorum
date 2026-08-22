from __future__ import annotations

import math
from typing import cast

import pytest

from sourcequorum.canonical import (
    dumps_canonical,
    frame_jsonl,
    loads_strict,
    sha256_bytes,
)
from sourcequorum.errors import ErrorCode, InputError


def test_dumps_canonical_matches_a_hand_checked_rfc8785_vector() -> None:
    """A non-JCS serializer would change the bytes used in release identities."""
    value = {"numbers": [333333333.33333329, 1e30, 4.5, 2e-3], "literals": [None, True, False]}

    assert (
        dumps_canonical(value)
        == b'{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002]}'
    )


def test_dumps_canonical_uses_unicode_utf16_code_unit_key_order() -> None:
    """Sorting with insertion or code-point order would make JCS bytes platform-dependent."""
    value = {
        "\ufb33": "Hebrew letter dalet with dagesh",
        "\U0001f600": "grinning face",
        "\u20ac": "Euro Sign",
        "\r": "Carriage Return",
        "1": "One",
        "\u0080": "Control",
    }

    assert (
        dumps_canonical(value)
        == b'{"\\r":"Carriage Return","1":"One","\xc2\x80":"Control","\xe2\x82\xac":"Euro Sign","\xf0\x9f\x98\x80":"grinning face","\xef\xac\xb3":"Hebrew letter dalet with dagesh"}'
    )


def test_loads_strict_accepts_utf8_and_dumps_stable_key_order() -> None:
    """Parsing the same object in a different member order must not change canonical bytes."""
    parsed = loads_strict(b'{"z":"\xe6\xb5\x8b\xe8\xaf\x95","a":1}')

    assert parsed == {"z": "测试", "a": 1}
    assert dumps_canonical(parsed) == b'{"a":1,"z":"\xe6\xb5\x8b\xe8\xaf\x95"}'
    assert dumps_canonical({"a": 1, "z": "测试"}) == dumps_canonical(parsed)


@pytest.mark.parametrize(
    "payload",
    [
        '{"same": 1, "same": 2}',
        '{"number": NaN}',
        '{"number": Infinity}',
        '{"number": -Infinity}',
        r'"\ud800"',
        "1e400",
        "-1e400",
        "9007199254740992",
        b"\xff",
        "{not json}",
    ],
)
def test_loads_strict_wraps_malformed_or_ambiguous_json(payload: str | bytes) -> None:
    """Permitting parser extensions or duplicate keys would make source content ambiguous."""
    with pytest.raises(InputError) as raised:
        loads_strict(payload)

    assert raised.value.code is ErrorCode.INVALID_JSON
    assert str(raised.value) == "SQ106: invalid JSON"


@pytest.mark.parametrize(
    "value",
    [
        {"value": math.nan},
        {"value": math.inf},
        {"value": -math.inf},
        9007199254740992,
        -9007199254740992,
        {1: "not a string key"},
        ("not", "a", "json", "array"),
    ],
)
def test_dumps_canonical_rejects_values_outside_json_or_jcs_domains(value: object) -> None:
    """Unsupported values or unsafe integers could produce non-portable canonical bytes."""
    with pytest.raises(InputError) as raised:
        dumps_canonical(value)

    assert raised.value.code is ErrorCode.INVALID_JSON
    assert str(raised.value) == "SQ106: invalid JSON"


def test_dumps_canonical_wraps_cyclic_containers_as_safe_invalid_json() -> None:
    """A recursive container must not leak RecursionError or raw object details."""
    cyclic: list[object] = []
    cyclic.append(cyclic)

    with pytest.raises(InputError) as raised:
        dumps_canonical(cyclic)

    assert raised.value.code is ErrorCode.INVALID_JSON
    assert str(raised.value) == "SQ106: invalid JSON"


def test_jcs_safe_integer_boundaries_are_preserved() -> None:
    """An off-by-one safe-integer check silently changes large record values."""
    assert dumps_canonical(9007199254740991) == b"9007199254740991"
    assert dumps_canonical(-9007199254740991) == b"-9007199254740991"


def test_frame_jsonl_adds_exactly_one_lf_per_canonical_record() -> None:
    """Missing or doubled terminators would change records.jsonl content identities."""
    assert frame_jsonl([{"b": 2, "a": 1}, "x"]) == b'{"a":1,"b":2}\n"x"\n'
    assert frame_jsonl([]) == b""


def test_sha256_bytes_returns_the_full_lowercase_digest() -> None:
    """A shortened or nonstandard digest cannot safely identify immutable members."""
    payload = b"abc"

    assert (
        sha256_bytes(payload) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert len(sha256_bytes(payload)) == 64
    assert sha256_bytes(payload).islower()
    with pytest.raises(ValueError, match="^data$"):
        sha256_bytes(cast(bytes, bytearray(payload)))
