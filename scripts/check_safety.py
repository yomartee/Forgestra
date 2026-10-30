"""Deterministic PR 01 gate. No dependency install, SDK, shell or remote calls."""

from pathlib import Path
import ast
import contextlib
import io
import json
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

# Synthetic fixtures are never credentials for a service. They are still kept
# out of test failure logs, including traceback source lines and assertions.
REGRESSION_CANARIES = (
    "canary-provider-do-not-use",
    "canary-admin-do-not-use",
    "canary-workik-do-not-use",
    "canary-cleanup-credential",
    "canary-log-credential",
    'synthetic-credential-"-backslash\\-end',
)


def valid_regression_result(document):
    fields = {
        "collected",
        "tests",
        "failures",
        "errors",
        "skipped",
        "expected_failures",
        "unexpected_successes",
    }
    return (
        isinstance(document, dict)
        and set(document) == fields | {"status"}
        and document["status"] == "PASSED"
        and all(type(document[field]) is int for field in fields)
        and document["tests"] == document["collected"]
        and document["tests"] > 0
        and all(document[field] == 0 for field in fields - {"tests", "collected"})
    )


def run_suite(suite, stream=None):
    from forgestra_safety import redact

    count = suite.countTestCases()
    if not count:
        return {"status": "FAILED", "tests": 0, "reason": "zero tests collected"}
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    (stream if stream is not None else sys.stderr).write(
        redact(output.getvalue(), REGRESSION_CANARIES)
    )
    passed = (
        result.wasSuccessful()
        and result.testsRun == count
        and result.testsRun > 0
        and not result.skipped
        and not result.expectedFailures
        and not result.unexpectedSuccesses
    )
    return {
        "status": "PASSED" if passed else "FAILED",
        "collected": count,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }


def main():
    for path in [
        *ROOT.glob("scripts/**/*.py"),
        *ROOT.glob("mcp-server/*.py"),
        *ROOT.glob("tests/*.py"),
        *ROOT.glob("src/**/*.py"),
    ]:
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    result = run_suite(unittest.defaultTestLoader.discover(str(ROOT / "tests")))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
