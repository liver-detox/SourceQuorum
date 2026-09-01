"""Run the checked-in synthetic inventory example from check through verification."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile

from sourcequorum.cli import main as cli_main


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "inventory"
AT = "2040-01-15T00:05:00+00:00"


def _run(arguments: list[str]) -> tuple[int, str]:
    output = StringIO()
    with redirect_stdout(output), redirect_stderr(StringIO()):
        status = cli_main(arguments)
    return status, output.getvalue()


def _evaluation_arguments() -> list[str]:
    return [
        "--policy",
        str(EXAMPLE / "policy.json"),
        "--source",
        str(EXAMPLE / "candidate"),
        "--source",
        str(EXAMPLE / "crosscheck"),
        "--at",
        AT,
    ]


def run_demo() -> int:
    try:
        status, _ = _run(["check", *_evaluation_arguments()])
        if status != 0:
            print("check failed.")
            return 1
        print("1/3 check: ACCEPTED")

        with tempfile.TemporaryDirectory(prefix=".sourcequorum-demo-", dir=ROOT) as output_root:
            status, published = _run(
                [
                    "publish",
                    *_evaluation_arguments(),
                    "--output",
                    output_root,
                    "--commit",
                ]
            )
            prefix = "COMMITTED release="
            if status != 0 or not published.startswith(prefix):
                print("publish failed.")
                return 1
            release_id = published.removeprefix(prefix).strip()
            if not release_id:
                print("publish failed.")
                return 1
            print("2/3 publish: COMMITTED")

            status, _ = _run(["verify", str(Path(output_root) / "releases" / release_id)])
            if status != 0:
                print("verify failed.")
                return 1
        print("3/3 verify: VALID")
        print("Demo complete.")
        return 0
    except Exception:
        print("demo failed.")
        return 1


if __name__ == "__main__":
    raise SystemExit(run_demo())
