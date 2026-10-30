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

DIAGNOSTIC_PREFIX = "FORGESTRA_REGRESSION_DIAGNOSTIC_V1 "
DIAGNOSTIC_PROFILE = "FORGESTRA_FACTORY_FAILURE_V1"
MAX_DIAGNOSTIC_IDS = 20
COUNT_FIELDS = {
    "collected",
    "tests",
    "failures",
    "errors",
    "skipped",
    "expected_failures",
    "unexpected_successes",
}


def factory_test_ids(root=None):
    """Static declared factory identifiers only; never import code for logging."""
    from public_contract import source_paths
    from forgestra.verification import plain_file

    root = ROOT if root is None else Path(root)
    names = set()
    for relative in source_paths(root):
        if not relative.startswith("tests/test_") or not relative.endswith(".py"):
            continue
        module = Path(relative).stem
        tree = ast.parse(plain_file(root / relative))
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for method in node.body:
                    if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"):
                        names.add(module + "." + node.name + "." + method.name)
    return names


def valid_failure_diagnostic(value, known_ids):
    """Diagnostic data never changes a check's verdict or grants authority."""
    if not isinstance(value, dict) or set(value) != {
        "profile",
        "counts",
        "test_ids",
        "ids_omitted",
        "unlisted_count",
    }:
        return False
    counts, names = value["counts"], value["test_ids"]
    if (
        value["profile"] != DIAGNOSTIC_PROFILE
        or not isinstance(counts, dict)
        or set(counts) != COUNT_FIELDS
        or any(type(counts[f]) is not int or not 0 <= counts[f] <= 1_000_000 for f in counts)
        or not isinstance(names, list)
        or len(names) > MAX_DIAGNOSTIC_IDS
        or any(not isinstance(n, str) or n not in known_ids for n in names)
        or names != sorted(set(names))
        or any(type(value[f]) is not int or value[f] < 0 for f in ("ids_omitted", "unlisted_count"))
    ):
        return False
    total = sum(counts[f] for f in COUNT_FIELDS - {"tests", "collected"})
    return len(names) + value["ids_omitted"] + value["unlisted_count"] <= total


def failure_diagnostic(result, counts):
    known = factory_test_ids()
    tests = [
        case
        for case, _ in result.failures + result.errors + result.skipped + result.expectedFailures
    ]
    tests.extend(result.unexpectedSuccesses)
    names, unlisted = set(), 0
    for test in tests:
        # Subtest id() includes parameter reprs. Use only the owning factory method.
        test = getattr(test, "test_case", test)
        cls = type(test)
        name = cls.__module__ + "." + cls.__qualname__ + "." + getattr(test, "_testMethodName", "")
        if name in known:
            names.add(name)
        else:
            unlisted += 1
    ordered = sorted(names)
    value = {
        "profile": DIAGNOSTIC_PROFILE,
        "counts": counts,
        "test_ids": ordered[:MAX_DIAGNOSTIC_IDS],
        "ids_omitted": max(0, len(ordered) - MAX_DIAGNOSTIC_IDS),
        "unlisted_count": unlisted,
    }
    if not valid_failure_diagnostic(value, known):
        raise ValueError("invalid authored diagnostic")
    return value


def emit_failure_diagnostic(result, counts, stream):
    value = failure_diagnostic(result, counts)
    stream.write(DIAGNOSTIC_PREFIX + json.dumps(value, sort_keys=True) + "\n")


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
        emit_failure_diagnostic(
            unittest.TestResult(),
            {f: 0 for f in COUNT_FIELDS},
            stream if stream is not None else sys.stderr,
        )
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
    document = {
        "status": "PASSED" if passed else "FAILED",
        "collected": count,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }
    if not passed:
        emit_failure_diagnostic(
            result,
            {f: document[f] for f in COUNT_FIELDS},
            stream if stream is not None else sys.stderr,
        )
    return document


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
