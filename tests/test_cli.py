"""Black-box contracts for the deliberately small safe command-line boundary."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

import pytest

from sourcequorum.canonical import dumps_canonical


AT = "2042-06-07T08:09:10.123456Z"


def _policy_document() -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.policy.v1",
        "dataset_id": "cli.test",
        "key_fields": ["id"],
        "fields": [
            {
                "name": "id",
                "value_type": "string",
                "comparison": "exact",
                "nullable": False,
                "tolerances": {"absolute": "0", "relative": "0"},
            },
            {
                "name": "value",
                "value_type": "integer",
                "comparison": "exact",
                "nullable": False,
                "tolerances": {"absolute": "0", "relative": "0"},
            },
        ],
        "limits": {
            "min_sources": 2,
            "max_sources": 2,
            "max_age_seconds": 60,
            "max_future_skew_seconds": 0,
            "max_records_per_source": 3,
            "max_line_bytes": 1024,
            "max_member_bytes": 4096,
            "require_distinct_origin_groups": True,
        },
    }


def _source_document(records: bytes, source_id: str, role: str) -> dict[str, object]:
    return {
        "schema_version": "sourcequorum.source.v1",
        "source_id": source_id,
        "origin_group": f"origin-{source_id}",
        "role": role,
        "collected_at": AT,
        "records": {
            "path": "records.jsonl",
            "sha256": hashlib.sha256(records).hexdigest(),
            "byte_count": len(records),
            "record_count": 1,
        },
    }


def _inputs(tmp_path: Path, *, crosscheck_value: int = 7) -> tuple[Path, Path, Path]:
    policy = tmp_path / "policy.json"
    policy.write_bytes(dumps_canonical(_policy_document()))
    directories: list[Path] = []
    for source_id, role, value in (
        ("candidate", "candidate", 7),
        ("crosscheck", "crosscheck", crosscheck_value),
    ):
        directory = tmp_path / source_id
        directory.mkdir()
        records = dumps_canonical({"id": "one", "value": value}) + b"\n"
        (directory / "records.jsonl").write_bytes(records)
        (directory / "source.json").write_bytes(
            dumps_canonical(_source_document(records, source_id, role))
        )
        directories.append(directory)
    return policy, directories[0], directories[1]


def test_check_emits_canonical_safe_report_and_normalizes_timezone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Dropping evaluation or UTC normalization must fail this check boundary."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path)
    result = main(
        [
            "check",
            "--policy",
            str(policy),
            "--source",
            str(candidate),
            "--source",
            str(crosscheck),
            "--at",
            "2042-06-07T16:09:10.123456+08:00",
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    assert captured.out == (
        '{"dataset_id":"cli.test","evaluated_at":"2042-06-07T08:09:10.123456Z",'
        '"findings":[],"record_count":1,"schema_version":"sourcequorum.gate-report.v1",'
        '"source_count":2,"status":"ACCEPTED"}\n'
    )


def test_check_rejection_and_human_output_are_safe(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rendering raw source values or treating a rejected gate as accepted must fail."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path, crosscheck_value=999)
    result = main(
        [
            "check",
            "--policy",
            str(policy),
            "--source",
            str(candidate),
            "--source",
            str(crosscheck),
            "--at",
            AT,
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert captured.err == ""
    assert captured.out.startswith(
        "REJECTED dataset=cli.test sources=2 records=1 findings=1\nSQ209 "
    )
    assert "source_id=crosscheck" in captured.out
    assert "field=value" in captured.out
    assert str(tmp_path) not in captured.out
    assert "999" not in captured.out


@pytest.mark.parametrize("argv", [["check"], ["publish", "--policy", "x", "--source", "y"]])
def test_check_and_publish_require_explicit_timestamp(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Adding an implicit clock or accepting a missing timestamp must fail."""
    from sourcequorum.cli import main

    assert main(argv) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: invalid arguments\n"


def test_publish_without_commit_prepares_without_touching_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Calling filesystem commit logic without --commit must fail this dry prepare contract."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path)
    output = tmp_path / "must-not-exist"
    monkeypatch.setattr(Path, "mkdir", lambda *_args, **_kwargs: pytest.fail("unexpected write"))

    result = main(
        [
            "publish",
            "--policy",
            str(policy),
            "--source",
            str(candidate),
            "--source",
            str(crosscheck),
            "--at",
            AT,
            "--output",
            str(output),
            "--json",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload == {"release_id": payload["release_id"], "status": "PREPARED"}
    assert payload["release_id"].startswith("sq-v1-")
    assert not output.exists()


def test_publish_commit_requires_output_and_maps_commit_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Committing without a destination or misclassifying immutable refusal must fail."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path)
    no_output = main(
        [
            "publish",
            "--policy",
            str(policy),
            "--source",
            str(candidate),
            "--source",
            str(crosscheck),
            "--at",
            AT,
            "--commit",
        ]
    )
    first = capsys.readouterr()
    refusal = main(
        [
            "publish",
            "--policy",
            str(policy),
            "--source",
            str(candidate),
            "--source",
            str(crosscheck),
            "--at",
            AT,
            "--output",
            str(tmp_path / "missing"),
            "--commit",
        ]
    )
    second = capsys.readouterr()
    assert no_output == 2 and first.err == "error: invalid arguments\n"
    assert (
        refusal == 4
        and second.out == ""
        and second.err == "error: SQ400: immutable target conflict\n"
    )
    assert str(tmp_path) not in second.err


def test_publish_rejection_emits_a_safe_report_without_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Routing an expected gate rejection through an exception error stream must fail."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path, crosscheck_value=999)
    assert (
        main(
            [
                "publish",
                "--policy",
                str(policy),
                "--source",
                str(candidate),
                "--source",
                str(crosscheck),
                "--at",
                AT,
                "--json",
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.err == ""
    payload = json.loads(captured.out)
    assert payload["status"] == "REJECTED"
    assert payload["findings"] == [
        {
            "code": "SQ209",
            "source_id": "crosscheck",
            "field": "value",
            "key_digest": payload["findings"][0]["key_digest"],
        }
    ]
    assert "999" not in captured.out


def test_publish_commit_without_output_is_rejected_before_loading_rejected_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Moving the commit/output check after policy loading or evaluation must fail."""
    from sourcequorum.cli import main

    policy, candidate, crosscheck = _inputs(tmp_path, crosscheck_value=999)
    assert (
        main(
            [
                "publish",
                "--policy",
                str(policy),
                "--source",
                str(candidate),
                "--source",
                str(crosscheck),
                "--at",
                AT,
                "--commit",
                "--json",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: invalid arguments\n"
    assert str(tmp_path) not in captured.err
    assert "999" not in captured.err


def test_verify_and_schema_have_safe_deterministic_outputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Changing integrity exit mapping or schema manifest mapping must fail."""
    from sourcequorum.cli import main

    invalid = tmp_path / "RAW_RELEASE_PATH"
    assert main(["verify", str(invalid), "--json"]) == 3
    verify = capsys.readouterr()
    assert verify.err == ""
    assert verify.out == '{"findings":[{"code":"SQ102"}],"valid":false}\n'
    assert "RAW_RELEASE_PATH" not in verify.out

    assert main(["schema", "manifest"]) == 0
    schema = capsys.readouterr()
    assert schema.err == ""
    from sourcequorum.schema import schema_bytes

    assert schema.out.encode() == schema_bytes("release-manifest") + b"\n"


@pytest.mark.parametrize("argument", ["--force", "--latest", "--allow-stale", "RAW_ARG_SENTINEL"])
def test_argument_failures_do_not_echo_untrusted_tokens(
    argument: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """Letting argparse echo an untrusted token must fail this safe boundary."""
    from sourcequorum.cli import main

    assert main(["check", argument]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: invalid arguments\n"
    assert argument not in captured.err


def test_unexpected_exception_is_a_fixed_safe_refusal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rendering an unexpected exception cause or traceback must fail."""
    import sourcequorum.cli as cli

    monkeypatch.setattr(
        cli, "load_policy", lambda _path: (_ for _ in ()).throw(RuntimeError("OS_SENTINEL"))
    )
    assert cli.main(["check", "--policy", "RAW_PATH", "--source", "RAW_SOURCE", "--at", AT]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "error: SQ000 internal refusal\n"
    assert "OS_SENTINEL" not in captured.err
    assert "RAW_PATH" not in captured.err


def test_built_wheel_installs_both_subprocess_entry_points(
    tmp_path: Path,
) -> None:
    """Dropping either packaged entry point or diverging their schema behavior must fail."""
    from sourcequorum.schema import schema_bytes

    repository = Path(__file__).resolve().parents[1]
    wheelhouse = tmp_path / "wheelhouse"
    archive = tmp_path / "archive"
    environment = tmp_path / "environment"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--outdir",
            str(wheelhouse),
        ],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    wheels = tuple(wheelhouse.glob("sourcequorum-*.whl"))
    assert len(wheels) == 1
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--target",
            str(archive),
            str(wheels[0]),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [sys.executable, "-m", "venv", str(environment)],
        check=True,
        capture_output=True,
        text=True,
    )
    python = environment / "bin" / "python"
    script = environment / "bin" / "sourcequorum"
    hostile_environment = {
        **os.environ,
        "PYTHONHOME": str(archive),
        "PYTHONPATH": str(archive),
        "PYTHONUSERBASE": str(archive),
        "PIP_TARGET": str(archive),
    }
    installation_environment = hostile_environment.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE", "PIP_TARGET"):
        installation_environment.pop(name, None)
    installation_environment["PYTHONNOUSERSITE"] = "1"
    subprocess.run(
        [str(python), "-m", "pip", "install", "--no-index", "--no-deps", str(wheels[0])],
        env=installation_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    assert script.is_file()
    dependency_path = Path(sysconfig.get_paths()["purelib"])
    assert not tuple(dependency_path.glob("sourcequorum"))
    assert not tuple(dependency_path.glob("sourcequorum-*.dist-info"))
    local_environment = {**os.environ, "PYTHONPATH": str(dependency_path)}
    expected = schema_bytes("release-manifest") + b"\n"
    console = subprocess.run(
        [str(script), "schema", "manifest"],
        cwd=tmp_path,
        env=local_environment,
        check=False,
        capture_output=True,
    )
    module = subprocess.run(
        [str(python), "-m", "sourcequorum", "schema", "manifest"],
        cwd=tmp_path,
        env=local_environment,
        check=False,
        capture_output=True,
    )
    assert (console.returncode, console.stdout, console.stderr) == (0, expected, b"")
    assert (module.returncode, module.stdout, module.stderr) == (0, expected, b"")
