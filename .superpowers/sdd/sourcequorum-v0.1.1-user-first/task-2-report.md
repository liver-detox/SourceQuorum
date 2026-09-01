# Task 2 report: recoverable CLI help and argument errors

## Scope

Implemented normal argparse help and safe, actionable argument failures in
`src/sourcequorum/cli.py`. The change retains the established refusal,
redaction, JSON, gate, verification, and commit behavior.

## Test-first record

### RED

Added behavior tests to `tests/test_cli.py` before changing production code.

Initial command attempted:

```text
pytest -q tests/test_cli.py
```

Output:

```text
zsh:1: command not found: pytest
```

The repository virtual environment provides the test runner, so the RED run
was repeated with:

```text
.venv/bin/python -m pytest -q tests/test_cli.py
```

Output summary:

```text
13 failed, 7 passed in 2.94s
```

The failures were the intended missing behavior: all five help cases returned
2 with `error: invalid arguments`, and argument errors lacked usage and the
safe actionable messages required by the new tests.

### GREEN

Implemented the minimal parser boundary changes, then ran:

```text
.venv/bin/python -m pytest -q tests/test_cli.py
```

Output:

```text
20 passed in 2.67s
```

Final full-suite command:

```text
.venv/bin/python -m pytest -q
```

Output:

```text
485 passed in 12.35s
```

Additional final static check:

```text
.venv/bin/ruff check src/sourcequorum/cli.py tests/test_cli.py
```

Output:

```text
All checks passed!
```

## Files changed

- `src/sourcequorum/cli.py`
  - Restored top-level and subcommand help with concise, scoped descriptions.
  - Added help text for policy/source/timestamp/output/JSON options.
  - Rendered parser-generated usage plus fixed safe error text.
  - Kept unknown tokens and timestamp values out of output.
  - Added the explicit `--commit` / `--output` error after publish usage.
- `tests/test_cli.py`
  - Added black-box `main` tests for top-level and subcommand help, scoped
    options, missing required options, timezone-free timestamps, and redacted
    hostile arguments.
  - Updated prior assertions from the obsolete opaque parse error to the new
    safe, actionable behavior.

## Self-review

- Help is emitted by argparse to stdout and `main` converts its successful
  `SystemExit(0)` into return code 0.
- Usage comes only from fixed parser metadata; no paths, supplied values, or
  unknown tokens are rendered.
- Missing known required flags are named; unknown or malformed input remains a
  generic `invalid or unrecognized arguments` refusal.
- The timestamp-specific message does not include the supplied timestamp.
- Existing runtime error mapping, gate/verification/commit exit codes, and
  JSON output remain covered by the full suite.

## Concerns

None. The shell did not expose `pytest` globally; all verification used the
repository's pinned virtual environment.
