from __future__ import annotations

from datetime import UTC, datetime

from sourcequorum import ComparisonMode, FieldRule, ReleasePolicy, ValueType


def test_policy_document_preserves_rule_order_and_normalizes_decimals() -> None:
    from sourcequorum.manifest import policy_document

    policy = ReleasePolicy(
        "sourcequorum.policy.v1",
        "synthetic.inventory",
        ("id",),
        (
            FieldRule("id", ValueType.STRING, ComparisonMode.EXACT, False),
            FieldRule("ratio", ValueType.NUMBER, ComparisonMode.NUMERIC, True),
        ),
    )
    assert policy_document(policy)["fields"] == [
        {
            "name": "id",
            "value_type": "string",
            "comparison": "exact",
            "nullable": False,
            "tolerances": {"absolute": "0", "relative": "0"},
        },
        {
            "name": "ratio",
            "value_type": "number",
            "comparison": "numeric",
            "nullable": True,
            "tolerances": {"absolute": "0", "relative": "0"},
        },
    ]


def test_timestamp_is_fixed_utc_microsecond_format() -> None:
    from sourcequorum.manifest import utc_timestamp

    assert utc_timestamp(datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)) == "2030-01-02T03:04:05.000000Z"
