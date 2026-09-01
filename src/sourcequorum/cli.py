"""A small, local command line boundary with deliberately safe rendering."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn, TypeVar, cast, overload

from .canonical import dumps_canonical
from .errors import CommitError, GateRejectedError, IntegrityError, SourceQuorumError
from .gate import evaluate
from .manifest import gate_report_document
from .models import Finding, GateReport, VerificationReport
from .publish import prepare_release
from .schema import schema_bytes
from .source import load_policy, load_source
from .storage import commit_release
from .verify import verify_release


class _ArgumentFailure(Exception):
    """A private parse failure rendered from fixed parser metadata only."""

    def __init__(self, usage: str, message: str) -> None:
        self.usage = usage
        self.message = message


_Namespace = TypeVar("_Namespace")


class _SafeParser(argparse.ArgumentParser):
    @overload
    def parse_known_args(
        self,
        args: Iterable[str] | None = ...,
        namespace: None = ...,
    ) -> tuple[argparse.Namespace, list[str]]: ...

    @overload
    def parse_known_args(
        self,
        args: Iterable[str] | None,
        namespace: _Namespace,
    ) -> tuple[_Namespace, list[str]]: ...

    @overload
    def parse_known_args(self, *, namespace: _Namespace) -> tuple[_Namespace, list[str]]: ...

    def parse_known_args(
        self,
        args: Iterable[str] | None = None,
        namespace: object | None = None,
    ) -> tuple[object, list[str]]:
        if args is None:
            self._input_args = tuple(sys.argv[1:])
            return super().parse_known_args(None, namespace)
        self._input_args = tuple(args)
        return super().parse_known_args(self._input_args, namespace)

    def error(self, message: str) -> NoReturn:
        if message.startswith("argument --at:"):
            safe_message = "--at requires an ISO 8601 timestamp with a timezone"
        elif (
            message.startswith("the following arguments are required:")
            and not self._has_unknown_input()
        ):
            missing = message.partition(": ")[2]
            safe_message = f"missing required arguments: {missing}"
        else:
            safe_message = "invalid or unrecognized arguments"
        raise _ArgumentFailure(self.format_usage(), safe_message)

    def _has_unknown_input(self) -> bool:
        if any(not action.option_strings for action in self._actions):
            return False
        actions = {option: action for action in self._actions for option in action.option_strings}
        value_expected = False
        for token in self._input_args:
            if value_expected:
                value_expected = False
                continue
            option, separator, _value = token.partition("=")
            action = actions.get(option)
            if action is None:
                return True
            value_expected = not separator and action.nargs != 0
        return False


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError
        return parsed.astimezone(UTC)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("invalid timestamp") from None


def _parser() -> _SafeParser:
    parser = _SafeParser(prog="sourcequorum")
    subcommands = parser.add_subparsers(dest="command", required=True)

    check = subcommands.add_parser(
        "check",
        help="compare sources without writing a release",
        description="compare sources without writing a release",
    )
    _add_evaluation_arguments(check)
    check.add_argument("--json", action="store_true", help="JSON output")

    publish = subcommands.add_parser(
        "publish",
        help="prepare a release; --commit and --output write it",
        description="prepare a release; --commit and --output write it",
    )
    _add_evaluation_arguments(publish)
    publish.add_argument("--output", help="existing output root")
    publish.add_argument("--commit", action="store_true")
    publish.add_argument("--json", action="store_true", help="JSON output")
    publish.set_defaults(_usage=publish.format_usage())

    verify = subcommands.add_parser(
        "verify",
        help="verify a stored release; repeated --source values replay it",
        description="verify a stored release; repeated --source values replay it",
    )
    verify.add_argument("release_dir")
    verify.add_argument(
        "--source", action="append", default=[], help="source directory; repeat for each source"
    )
    verify.add_argument("--json", action="store_true", help="JSON output")

    schema = subcommands.add_parser(
        "schema",
        help="print a bundled JSON Schema",
        description="print a bundled JSON Schema",
    )
    schema.add_argument("name", choices=("policy", "source", "gate-report", "manifest"))
    return parser


def _add_evaluation_arguments(parser: _SafeParser) -> None:
    parser.add_argument("--policy", required=True, help="policy JSON file")
    parser.add_argument(
        "--source", action="append", required=True, help="source directory; repeat for each source"
    )
    parser.add_argument(
        "--at",
        required=True,
        type=_timestamp,
        help="evaluation time with timezone in ISO 8601 form",
    )


def _json(document: object) -> None:
    sys.stdout.buffer.write(dumps_canonical(document) + b"\n")


def _finding_text(finding: Finding) -> str:
    fields = [finding.code.value]
    for name in ("source_id", "field", "key_digest", "count"):
        value = getattr(finding, name)
        if value is not None:
            fields.append(f"{name}={value}")
    return " ".join(fields)


def _report_text(report: GateReport) -> str:
    lines = [
        f"{report.status.value} dataset={report.dataset_id} sources={report.source_count} "
        f"records={report.record_count} findings={len(report.findings)}"
    ]
    lines.extend(_finding_text(finding) for finding in report.findings)
    return "\n".join(lines) + "\n"


def _verification_document(report: VerificationReport) -> dict[str, object]:
    document: dict[str, object] = {"valid": report.valid}
    if report.release_id is not None:
        document["release_id"] = report.release_id
    if report.findings:
        document["findings"] = [
            {
                key: value
                for key, value in (
                    ("code", finding.code.value),
                    ("source_id", finding.source_id),
                    ("field", finding.field),
                    ("key_digest", finding.key_digest),
                    ("count", finding.count),
                )
                if value is not None
            }
            for finding in report.findings
        ]
    return document


def _verification_text(report: VerificationReport) -> str:
    if report.valid:
        return f"VALID release={report.release_id}\n"
    lines = [f"INVALID findings={len(report.findings)}"]
    lines.extend(_finding_text(finding) for finding in report.findings)
    return "\n".join(lines) + "\n"


def _load_evaluation(namespace: argparse.Namespace) -> tuple[object, tuple[object, ...], datetime]:
    policy = load_policy(Path(namespace.policy))
    sources = tuple(load_source(Path(directory), policy=policy) for directory in namespace.source)
    return policy, sources, cast(datetime, namespace.at)


def _check(namespace: argparse.Namespace) -> int:
    policy, sources, evaluated_at = _load_evaluation(namespace)
    report = evaluate(policy, sources, evaluated_at=evaluated_at)  # type: ignore[arg-type]
    if namespace.json:
        _json(gate_report_document(report))
    else:
        sys.stdout.write(_report_text(report))
    return 0 if report.status.value == "ACCEPTED" else 1


def _publish(namespace: argparse.Namespace) -> int:
    if namespace.commit and namespace.output is None:
        raise _ArgumentFailure(cast(str, namespace._usage), "--commit requires --output")
    policy, sources, evaluated_at = _load_evaluation(namespace)
    report = evaluate(policy, sources, evaluated_at=evaluated_at)  # type: ignore[arg-type]
    if report.status.value == "REJECTED":
        if namespace.json:
            _json(gate_report_document(report))
        else:
            sys.stdout.write(_report_text(report))
        return 1
    prepared = prepare_release(policy, sources, evaluated_at=evaluated_at)  # type: ignore[arg-type]
    if namespace.commit:
        commit_release(prepared, Path(namespace.output))
        status = "COMMITTED"
    else:
        status = "PREPARED"
    document = {"release_id": prepared.release_id, "status": status}
    if namespace.json:
        _json(document)
    else:
        sys.stdout.write(f"{status} release={prepared.release_id}\n")
    return 0


def _verify(namespace: argparse.Namespace) -> int:
    report = verify_release(
        Path(namespace.release_dir), source_dirs=tuple(Path(item) for item in namespace.source)
    )
    if namespace.json:
        _json(_verification_document(report))
    else:
        sys.stdout.write(_verification_text(report))
    return 0 if report.valid else 3


def _error(error: SourceQuorumError) -> int:
    sys.stderr.write(f"error: {error}\n")
    if isinstance(error, GateRejectedError):
        return 1
    if isinstance(error, IntegrityError):
        return 3
    if isinstance(error, CommitError):
        return 4
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    """Run one explicit local operation and return a stable process exit status."""
    try:
        namespace = _parser().parse_args(argv)
        if namespace.command == "check":
            return _check(namespace)
        if namespace.command == "publish":
            return _publish(namespace)
        if namespace.command == "verify":
            return _verify(namespace)
        if namespace.command == "schema":
            name = "release-manifest" if namespace.name == "manifest" else namespace.name
            sys.stdout.buffer.write(schema_bytes(name) + b"\n")
            return 0
        raise _ArgumentFailure("", "invalid or unrecognized arguments")
    except _ArgumentFailure as error:
        sys.stderr.write(error.usage)
        sys.stderr.write(f"error: {error.message}\n")
        return 2
    except SystemExit as error:
        return cast(int, error.code)
    except SourceQuorumError as error:
        return _error(error)
    except Exception:
        sys.stderr.write("error: SQ000 internal refusal\n")
        return 2
