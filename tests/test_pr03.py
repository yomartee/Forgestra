"""Offline PR 03 contracts: real CLI/planner/parser with synthetic provider fixtures."""

import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from forgestra.assessment import Improver, assess, sample, validate_assessment
from forgestra.cli import main
from forgestra.providers import (
    ANTHROPIC_MODEL,
    CLAUDE_ACTION_COMMIT,
    ProviderConfig,
    Status,
    action_proposal,
    configuration,
    live,
    replay,
    request_proposal,
)
from forgestra_safety import Blocked


def fixture(document):
    return {
        "kind": "OFFLINE_REPLAY",
        "response": {
            "type": "message",
            "stop_reason": "end_turn",
            "content": [{"type": "text", "text": json.dumps(document)}],
        },
    }


class PR03Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="forgestra-pr03-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("scripts/agents/worker.py", ".github/workflows/ci.yml", "policy.json"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("example\nnested evidence\n", encoding="utf-8")
        self.ref: dict[str, Any] = {
            "path": "scripts/agents/worker.py",
            "sha256": hashlib.sha256(
                (self.root / "scripts/agents/worker.py").read_bytes()
            ).hexdigest(),
            "start": 1,
            "end": 2,
        }
        self.document: dict[str, Any] = {
            "schema_version": 1,
            "findings": [
                {
                    "id": "F-example",
                    "title": "Review worker",
                    "severity": "HIGH",
                    "evidence": [self.ref],
                    "details": {
                        "summary": "Advisory",
                        "scope_gaps": [
                            {"description": "Missing behavior evidence", "evidence": [self.ref]}
                        ],
                    },
                }
            ],
            "limitations": ["Fixture only"],
        }

    def test_nested_round_trip_preserves_evidence(self):
        response = assess(self.root, fixture(self.document))
        self.assertEqual(response["status"], Status.FINDINGS)
        self.assertEqual(response["assessment"], self.document)
        self.assertEqual(json.loads(json.dumps(response))["assessment"], self.document)

    def test_complete_json_only(self):
        for raw in ('{"x":', "```json\n{}\n```", "{} trailing", '{"x":1,"x":2}', '{"x":NaN}'):
            value = fixture({})
            value["response"]["content"][0]["text"] = raw
            with self.subTest(raw=raw):
                self.assertEqual(assess(self.root, value)["status"], Status.ERROR)

    def test_refusal_truncation_unknown_stop_never_clean(self):
        for stop in ("refusal", "max_tokens", "pause_turn", "tool_use", None, "unknown"):
            value = fixture(self.document)
            value["response"]["stop_reason"] = stop
            result = assess(self.root, value)
            self.assertEqual(result["status"], Status.UNKNOWN)
            self.assertIsNone(result["assessment"])
            self.assertIsNone(result["completion_percentage"])

    def test_provider_errors_never_forward_secrets(self):
        for category in (
            "authentication_error",
            "rate_limit_error",
            "not_found_error",
            "overloaded_error",
        ):
            value = {
                "kind": "OFFLINE_REPLAY",
                "response": {
                    "type": "error",
                    "error": {"type": category, "message": "canary-provider-do-not-use"},
                },
            }
            result = assess(self.root, value)
            self.assertEqual(result["status"], Status.ERROR)
            self.assertNotIn("canary-provider-do-not-use", json.dumps(result))

    def test_no_findings_is_only_advisory(self):
        result = assess(
            self.root, fixture({"schema_version": 1, "findings": [], "limitations": []})
        )
        self.assertEqual(result["status"], Status.EMPTY)
        self.assertEqual(result["target_tests"], "UNTESTED")
        self.assertEqual(result["live_provider"], "NOT_RUN")

    def test_missing_fixture_blocks_even_with_credentials(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "canary-provider-do-not-use"}):
            with patch.object(socket.socket, "connect", side_effect=AssertionError("network")):
                self.assertEqual(assess(self.root)["status"], Status.BLOCKED)
                with self.assertRaises(Blocked):
                    live(ProviderConfig("anthropic", "unverified", "ANTHROPIC_API_KEY"))

    def test_invalid_provider_config(self):
        ProviderConfig().validate()
        for kwargs in (
            {"provider": "unknown"},
            {"retries": 1},
            {"timeout_seconds": True},
            {"model": "retired"},
            {"max_tokens": 0},
            {"provider": "anthropic", "model": "x", "credential_env": "GH_TOKEN"},
        ):
            with self.assertRaises(Blocked):
                ProviderConfig(**kwargs).validate()

    def test_schema_invalid_values_and_authority(self):
        for key, value in (
            ("schema_version", True),
            ("findings", {}),
            ("completion_percentage", 50),
            ("approval", True),
            ("limitations", "none"),
        ):
            document = copy.deepcopy(self.document)
            document[key] = value
            self.assertEqual(assess(self.root, fixture(document))["status"], Status.ERROR)

    def test_duplicate_finding_rejected(self):
        self.document["findings"] *= 2
        self.assertEqual(assess(self.root, fixture(self.document))["status"], Status.ERROR)

    def test_bad_evidence_rejected(self):
        for key, value in (
            ("path", "../escape"),
            ("path", "missing.py"),
            ("sha256", "0" * 64),
            ("start", True),
            ("end", 50),
        ):
            document = copy.deepcopy(self.document)
            document["findings"][0]["evidence"][0][key] = value
            self.assertEqual(assess(self.root, fixture(document))["status"], Status.ERROR)

    def test_nested_schema_checked(self):
        self.document["findings"][0]["details"]["scope_gaps"][0]["evidence"] = []
        self.assertEqual(assess(self.root, fixture(self.document))["status"], Status.ERROR)

    def test_sampling_includes_workflow_agents_policy(self):
        coverage = sample(self.root)
        included = {f["path"] for f in coverage["files"] if f["status"] == "INCLUDED"}
        self.assertEqual(
            included, {".github/workflows/ci.yml", "scripts/agents/worker.py", "policy.json"}
        )
        self.assertIsNone(coverage["identity"]["git_commit"])

    def test_sampling_limits_and_sensitive_paths_visible(self):
        (self.root / ".env").write_text("canary-admin-do-not-use")
        (self.root / "large.txt").write_text("x" * 100)
        coverage = sample(self.root, max_bytes=25, max_file_bytes=40)
        reasons = {f["path"]: f["reason"] for f in coverage["files"]}
        self.assertEqual(reasons[".env"], "SENSITIVE_FILE")
        self.assertEqual(reasons["large.txt"], "FILE_LIMIT")
        self.assertIn("CONTEXT_LIMIT", reasons.values())
        self.assertNotIn("canary-admin-do-not-use", json.dumps(coverage))

    def test_changed_file_invalidates_evidence(self):
        (self.root / self.ref["path"]).write_text("different\n")
        self.assertEqual(assess(self.root, fixture(self.document))["status"], Status.ERROR)

    def test_empty_tests_and_proposals_earn_no_progress(self):
        (self.root / "tests").mkdir()
        first = Improver().run(self.root, fixture(self.document))
        second = Improver().run(self.root, fixture(self.document))
        self.assertEqual(first["work_items"], second["work_items"])
        self.assertEqual(len(first["work_items"]), 1)
        self.assertIsNone(first["completion_percentage"])
        self.assertEqual(first["applied_changes"], [])
        self.assertEqual(first["target_tests"], "UNTESTED")
        self.assertEqual(first["publication"], "BLOCKED")

    def test_cli_reaches_improver_and_writes_nothing(self):
        response = self.root / "replay.json"
        response.write_text(json.dumps(fixture(self.document)))
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(["improve", str(self.root), "--replay", str(response)])
        result = json.loads(stream.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(result["operation"], "IMPROVEMENT_PLAN")
        self.assertEqual(len(result["work_items"]), 1)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_cli_failure_nonzero_and_canary_redacted(self):
        self.document["findings"][0]["title"] = "canary-provider-do-not-use"
        response = self.root / "replay.json"
        response.write_text(json.dumps(fixture(self.document)))
        stream = io.StringIO()
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "canary-provider-do-not-use"}):
            with contextlib.redirect_stdout(stream):
                self.assertEqual(main(["audit", str(self.root), "--replay", str(response)]), 0)
        self.assertNotIn("canary-provider-do-not-use", stream.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["audit", str(self.root)]), 1)

    def test_fixture_marker_and_content_types_fail_closed(self):
        for value in (
            {},
            {"kind": "LIVE", "response": {}},
            fixture(None),
            {
                "kind": "OFFLINE_REPLAY",
                "response": {"type": "message", "stop_reason": "end_turn", "content": []},
            },
        ):
            self.assertEqual(assess(self.root, value)["status"], Status.ERROR)

    def test_nontext_blocks_are_not_ignored(self):
        value = fixture(self.document)
        value["response"]["content"].append({"type": "tool_use", "input": {}})
        self.assertEqual(replay(value)[0], Status.ERROR)

    def test_public_validator_rejects_unverified_document(self):
        with self.assertRaises(ValueError):
            validate_assessment({}, sample(self.root))

    def test_provider_configuration_does_not_enable_live_calls(self):
        config = configuration(
            {
                "provider": "anthropic",
                "model": ANTHROPIC_MODEL,
                "credential_env": "ANTHROPIC_API_KEY",
                "timeout_seconds": 30,
                "max_tokens": 4096,
                "retries": 0,
            }
        )
        with self.assertRaises(Blocked):
            assess(self.root, fixture(self.document), config)
        values: list[Any] = [{}, {"api_key": "canary-provider-do-not-use"}, []]
        for value in values:
            with self.assertRaises(Blocked):
                configuration(value)

    def test_shared_assessment_redacts_known_credentials(self):
        self.document["findings"][0]["title"] = "canary-provider-do-not-use"
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "canary-provider-do-not-use"}):
            result = assess(self.root, fixture(self.document))
        self.assertNotIn("canary-provider-do-not-use", json.dumps(result))

    def test_inventory_bounds_are_blocking(self):
        for kwargs in ({"max_bytes": True}, {"max_file_bytes": 0}, {"max_bytes": -1}):
            with self.assertRaises(Blocked):
                sample(self.root, **kwargs)

    def test_source_cli_process_reports_provider_outage_nonzero(self):
        from bootstrap import environment

        response = self.root / "outage.json"
        response.write_text(json.dumps({"kind": "OFFLINE_REPLAY", "response": {"type": "error"}}))
        root = Path(__file__).resolve().parents[1]
        command = subprocess.run(
            [
                sys.executable,
                "-I",
                str(root / "scripts/forgestra_cli.py"),
                "improve",
                str(self.root),
                "--replay",
                str(response),
            ],
            cwd=self.root,
            env=environment(),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(command.returncode, 1)
        result = json.loads(command.stdout)
        self.assertEqual(result["status"], Status.ERROR)
        self.assertEqual(result["operation"], "IMPROVEMENT_PLAN")

    def test_unknown_severity_and_excluded_evidence_rejected(self):
        self.document["findings"][0]["severity"] = "CRITICAL_AUTO_APPROVED"
        self.assertEqual(assess(self.root, fixture(self.document))["status"], Status.ERROR)
        self.document["findings"][0]["severity"] = "HIGH"
        self.document["findings"][0]["evidence"][0]["path"] = ".env"
        self.assertEqual(assess(self.root, fixture(self.document))["status"], Status.ERROR)

    def test_kill_switch_does_not_allow_live_client_construction(self):
        with patch.dict("os.environ", {"FORGESTRA_KILL_SWITCH": "1"}):
            with self.assertRaises(Blocked):
                live(ProviderConfig())

    def test_pinned_action_input_contract_is_inert(self):
        root = Path(__file__).resolve().parents[1]
        contract = json.loads((root / "config/provider.contract.json").read_text())
        config = ProviderConfig("anthropic", ANTHROPIC_MODEL, "ANTHROPIC_API_KEY")
        proposal = action_proposal(config)
        self.assertEqual(contract["action_commit"], CLAUDE_ACTION_COMMIT)
        self.assertEqual(contract["candidate_model"], ANTHROPIC_MODEL)
        self.assertEqual(
            proposal["uses"], "anthropics/claude-code-action@" + contract["action_commit"]
        )
        self.assertLessEqual(set(proposal["with"]), set(contract["reviewed_input_subset"]))
        self.assertNotIn("model", proposal["with"])
        self.assertEqual(proposal["with"]["claude_args"], "--model " + ANTHROPIC_MODEL)
        self.assertEqual(proposal["status"], Status.BLOCKED)
        self.assertEqual(proposal["execution"], "DISABLED")

    def test_request_proposal_uses_canonical_bounded_configuration(self):
        config = ProviderConfig("anthropic", ANTHROPIC_MODEL, "ANTHROPIC_API_KEY", 15, 512, 0)
        proposal = request_proposal(config, "Synthetic review request")
        self.assertEqual(proposal["request"]["model"], ANTHROPIC_MODEL)
        self.assertEqual(proposal["request"]["max_tokens"], 512)
        self.assertEqual(proposal["timeout_seconds"], 15)
        self.assertEqual(proposal["retries"], 0)
        self.assertEqual(proposal["status"], Status.BLOCKED)
        self.assertEqual(proposal["credential_env"], "ANTHROPIC_API_KEY")
        with self.assertRaises(Blocked):
            ProviderConfig(
                "anthropic", "claude-3-5-sonnet-20241022", "ANTHROPIC_API_KEY"
            ).validate()
