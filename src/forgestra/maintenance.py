"""Bounded local maintenance: untrusted evidence is read-only, never authority."""

from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import uuid

import forgestra_safety as safety
from forgestra import repair
from forgestra.verification import bounded_file

REPOSITORY = "yomartee/maintenance-fixture"
ACTOR = "yomartee"
DIFF = [{"operation": "modify", "path": "src/arithmetic.py"}]
# Interpret this tiny AST grammar; never import, eval or execute candidate code.
CHECK = r"""
import ast,json,pathlib,sys
result={"status":"FAILED","collected":3,"tests":0,"failures":0,"errors":0,"skipped":0,"expected_failures":0,"unexpected_successes":0}
try:
    t=ast.parse(pathlib.Path("src/arithmetic.py").read_text(encoding="utf-8"))
    assert len(t.body)==1 and isinstance(t.body[0],ast.FunctionDef)
    f=t.body[0]
    assert f.name=="add" and not f.decorator_list and f.returns is None and not f.type_params
    assert ast.dump(f.args)==ast.dump(ast.parse("def add(a,b): pass").body[0].args)
    if len(f.body)==2:
        a,r=f.body
        assert isinstance(a,ast.Assign) and len(a.targets)==1
        assert isinstance(a.targets[0],ast.Name) and a.targets[0].id=="total"
        assert isinstance(r,ast.Return) and isinstance(r.value,ast.Name) and r.value.id=="total"
        n=a.value
    else:
        assert len(f.body)==1 and isinstance(f.body[0],ast.Return)
        n=f.body[0].value
    assert isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.Sub))
    assert isinstance(n.left,ast.Name) and n.left.id=="a"
    assert isinstance(n.right,ast.Name) and n.right.id=="b"
    for a,b,want in [(2,3,5),(-1,1,0),(0,0,0)]:
        got=a+b if isinstance(n.op,ast.Add) else a-b
        result["tests"]+=1
        result["failures"]+=int(got!=want)
except Exception:
    result["errors"]+=1
passed=result["tests"]==3 and result["failures"]==result["errors"]==0
result["status"]="PASSED" if passed else "FAILED"
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result["status"]=="PASSED" else 1)
"""
CHECK_SHA = repair.digest(CHECK.encode())


def policy_hash():
    return repair.digest(bounded_file(Path(__file__)) + repair.policy_hash().encode())


def counts(value, failed=False):
    expected = {
        "status": "FAILED" if failed else "PASSED",
        "collected": 3,
        "tests": 3,
        "failures": 2 if failed else 0,
        "errors": 0,
        "skipped": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    return value == expected and all(type(value[k]) is int for k in expected if k != "status")


def fingerprint(event):
    # A new delivery/run UUID cannot reset the budget for the same failed check.
    return repair.digest(
        repair.canonical({k: v for k, v in event.items() if k != "run_id"}).encode()
    )


def review(event):
    repair.checkpoint()
    if isinstance(event, dict) and ("log" not in event or event["log"] in (None, "")):
        return {
            "status": "ESCALATED",
            "reason_code": "MISSING_FAILURE_LOG",
            "origin_verification": "UNVERIFIED_DECLARATION",
            "execution": "DISABLED",
            "publication": "BLOCKED",
            "privileged_automation": "DISABLED",
            "side_effects": [],
        }
    fields = {
        "schema_version",
        "kind",
        "repository",
        "actor",
        "workflow",
        "run_id",
        "head_sha",
        "check_sha256",
        "conclusion",
        "log",
        "log_sha256",
        "changes",
    }
    if not isinstance(event, dict) or set(event) != fields:
        raise safety.Blocked("BLOCKED: complete maintenance evidence required")
    if (
        type(event["schema_version"]) is not int
        or event["schema_version"] != 1
        or not isinstance(event["kind"], str)
        or event["kind"] not in {"repair", "refactor"}
        or event["repository"] != REPOSITORY
        or event["actor"] != ACTOR
        or event["workflow"] != "authored-addition-check"
        or not isinstance(event["run_id"], str)
        or str(uuid.UUID(event["run_id"])) != event["run_id"]
        or not isinstance(event["head_sha"], str)
        or not re.fullmatch(r"[0-9a-f]{40}", event["head_sha"])
        or event["check_sha256"] != CHECK_SHA
    ):
        raise safety.Blocked("BLOCKED: unsupported maintenance origin/check")
    log = event["log"]
    failed = event["kind"] == "repair"
    if (
        not isinstance(log, str)
        or not 1 <= len(log.encode()) <= 32000
        or safety.redact(log) != log
        or repair.digest(log.encode()) != event["log_sha256"]
        or event["conclusion"] != ("failure" if failed else "success")
        or not counts(safety.strict_json_loads(log), failed)
    ):
        raise safety.Blocked("BLOCKED: missing or inconsistent checked log")
    changes = safety.validate_diff(event["changes"])
    if len(changes) > 8 or safety.redact(repair.canonical(event)) != repair.canonical(event):
        raise safety.Blocked("BLOCKED: sensitive or oversized maintenance evidence")
    risk = safety.classify_diff(changes)
    return {
        "status": "REVIEW_REQUIRED",
        "failure_fingerprint": fingerprint(event),
        "kind": event["kind"],
        "risk_tier": risk,
        "changes": changes,
        "reason_code": "PRIVILEGED_DIFF" if risk == 2 else "TRUSTED_APPROVAL_REQUIRED",
        "origin_verification": "UNVERIFIED_DECLARATION",
        "execution": "DISABLED",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }


def runtime_maintenance():
    repair.checkpoint()
    return {
        "status": "BLOCKED",
        "reason_code": "RUNTIME_MAINTENANCE_DISABLED",
        "privileged_automation": "DISABLED",
        "publication": "BLOCKED",
        "target_execution": "DISABLED",
        "side_effects": [],
    }


@dataclass(frozen=True)
class Observation:
    payload: str
    signature: str


@dataclass(frozen=True)
class Grant:
    payload: str
    signature: str
    repair_approval: repair.Approval


class FixtureMaintenance:
    """Trusted harness adapter over PR 04; no caller-selected roots or publishers."""

    def __init__(self, control):
        control._check()
        self.control = control
        self.parent = control.parent
        path = self.parent / "maintenance.sqlite"
        if path.is_symlink() or path.is_junction():
            raise safety.Blocked("BLOCKED: linked maintenance journal")
        self.db = sqlite3.connect(path, timeout=0.2, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS attempts("
            "fingerprint TEXT PRIMARY KEY, status TEXT, receipt TEXT, proof TEXT)"
        )
        self.db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS single_active ON attempts(status) "
            "WHERE status='EXECUTING'"
        )

    def close(self):
        self.db.close()

    def scope(self):
        self.control._check()
        if self.parent != safety._LOCAL_OUTPUT_PARENT.get():
            raise safety.Blocked("BLOCKED: expired maintenance scope")

    def sign(self, document):
        self.scope()
        return hmac.new(
            self.control.key, repair.canonical(document).encode(), hashlib.sha256
        ).hexdigest()

    def verify(self, payload, signature):
        if not isinstance(payload, str) or not isinstance(signature, str):
            raise safety.Blocked("BLOCKED: issued maintenance proof required")
        document = safety.strict_json_loads(payload)
        if not hmac.compare_digest(self.sign(document), signature):
            raise safety.Blocked("BLOCKED: untrusted maintenance proof")
        return document

    def check(self, root):
        self.scope()
        if root.parent != self.parent or not root.name.startswith("candidate-"):
            raise safety.Blocked("BLOCKED: issued diagnostic candidate required")
        snapshot = repair.files(root)
        command = subprocess.run(
            [sys.executable, "-I", "-c", CHECK],
            cwd=root,
            env=repair.environment(self.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        log = safety.redact(command.stdout)
        if len(log.encode()) > 32000 or command.stderr:
            raise safety.Blocked("BLOCKED: invalid diagnostic output")
        result = safety.strict_json_loads(log)
        if type(command.returncode) is not int or not (
            command.returncode == 0
            and counts(result)
            or command.returncode == 1
            and counts(result, True)
        ):
            raise safety.Blocked("BLOCKED: inconsistent diagnostic execution")
        if repair.files(root) != snapshot:
            raise safety.Blocked("BLOCKED: diagnostic bytes changed during checks")
        return {
            "files_sha256": snapshot,
            "argv": [sys.executable, "-I", "-c", CHECK],
            "exit_code": command.returncode,
            "log": log,
            "log_sha256": repair.digest(log.encode()),
            "result": result,
            "check_sha256": CHECK_SHA,
        }

    def observe(self):
        self.scope()
        c = self.control
        if (
            repair.files(c.source) != c.input_files
            or repair.git(c.source, "rev-parse", "HEAD").strip() != c.input_commit
            or {n: repair.digest(v.encode()) for n, v in c.seed.items()} != c.input_files
            or repair.git(c.source, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise safety.Blocked("BLOCKED: diagnostic source changed")
        root = self.parent / "candidate-observation"
        safety.write_new_tree(root, [{"path": n, "content": v} for n, v in c.seed.items()])
        checked = self.check(root)
        if (
            checked["files_sha256"] != c.input_files
            or repair.files(root) != c.input_files
            or repair.files(c.source) != c.input_files
            or repair.git(c.source, "rev-parse", "HEAD").strip() != c.input_commit
            or repair.git(c.source, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise safety.Blocked("BLOCKED: diagnostic does not match source commit")
        kind = "refactor" if c.seed["src/arithmetic.py"] == repair.FIX else "repair"
        event = {
            "schema_version": 1,
            "kind": kind,
            "repository": REPOSITORY,
            "actor": ACTOR,
            "workflow": "authored-addition-check",
            "run_id": str(uuid.uuid4()),
            "head_sha": c.input_commit,
            "check_sha256": CHECK_SHA,
            "conclusion": "failure" if kind == "repair" else "success",
            "log": checked["log"],
            "log_sha256": checked["log_sha256"],
            "changes": DIFF,
        }
        review(event)
        body = {
            "event": event,
            "diagnostic": checked,
            "policy_sha256": policy_hash(),
            "scope_id": c.scope_id,
        }
        return Observation(repair.canonical(body), self.sign(body))

    def observed(self, observation):
        if not isinstance(observation, Observation):
            raise safety.Blocked("BLOCKED: trusted observed failure required")
        body = self.verify(observation.payload, observation.signature)
        event = body["event"]
        if review(event)["status"] != "REVIEW_REQUIRED":
            raise safety.Blocked("BLOCKED: diagnostic escalation requires review")
        c = self.control
        if (
            body["policy_sha256"] != policy_hash()
            or body["scope_id"] != c.scope_id
            or event["head_sha"] != c.input_commit
            or event["changes"] != DIFF
            or repair.files(c.source) != c.input_files
            or repair.git(c.source, "rev-parse", "HEAD").strip() != c.input_commit
            or repair.git(c.source, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise safety.Blocked("BLOCKED: changed maintenance input or policy")
        return event

    def approve(self, observation, plan):
        event = self.observed(observation)
        c = self.control
        approval = c.approve(plan)
        body = {
            "observation_sha256": repair.digest(observation.payload.encode()),
            "plan_sha256": repair.digest(repair.canonical(plan).encode()),
            "policy_sha256": policy_hash(),
            "fingerprint": fingerprint(event),
        }
        return Grant(repair.canonical(body), self.sign(body), approval)

    def verified_candidate(self, result):
        """Authenticate the executor boundary and recheck its exact local proposal."""
        self.scope()
        name = result.get("candidate")
        run_id = result.get("run_id")
        if (
            not isinstance(run_id, str)
            or str(uuid.UUID(run_id)) != run_id
            or name != "candidate-" + run_id
            or result.get("input_commit") != self.control.input_commit
            or result.get("target_id") != self.control.target_id
        ):
            raise safety.Blocked("BLOCKED: executor candidate identity mismatch")
        candidate = self.parent / name
        proposal = repair.LocalPublisher.prepare(candidate, result)
        if result.get("proposal") != proposal:
            raise safety.Blocked("BLOCKED: executor proposal differs from verified commit")
        return candidate

    def run(self, observation, plan, grant=None):
        event = self.observed(observation)
        if not isinstance(grant, Grant):
            raise safety.Blocked("BLOCKED: trusted maintenance approval required")
        expected = {
            "observation_sha256": repair.digest(observation.payload.encode()),
            "plan_sha256": repair.digest(repair.canonical(plan).encode()),
            "policy_sha256": policy_hash(),
            "fingerprint": fingerprint(event),
        }
        if self.verify(grant.payload, grant.signature) != expected:
            raise safety.Blocked("BLOCKED: stale maintenance approval")
        self.control._approved(plan, grant.repair_approval)
        key = fingerprint(event)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT status,receipt,proof FROM attempts WHERE fingerprint=?", (key,)
            ).fetchone()
            if row:
                if row[0] not in {"READY_FOR_LOCAL_REVIEW", "ESCALATED"} or not row[1]:
                    raise safety.Blocked("BLOCKED: maintenance reconciliation required")
                receipt = self.verify(row[1], row[2])
                if receipt["status"] != row[0] or receipt["failure_fingerprint"] != key:
                    raise safety.Blocked("BLOCKED: corrupt maintenance receipt")
                if row[0] == "READY_FOR_LOCAL_REVIEW":
                    self.verified_candidate(receipt["repair"])
                self.db.execute("COMMIT")
                return {"status": "DUPLICATE", "receipt": receipt, "execution": "DISABLED"}
            self.db.execute("INSERT INTO attempts VALUES(?,'EXECUTING',NULL,NULL)", (key,))
            self.db.execute("COMMIT")
        except (sqlite3.Error, safety.Blocked, ValueError, TypeError, KeyError):
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise safety.Blocked("BLOCKED: duplicate, corrupt or active maintenance run") from None
        receipt = {
            "status": "ESCALATED",
            "reason_code": "NEEDS_RECONCILIATION",
            "failure_fingerprint": key,
            "observation": event,
            "policy_sha256": policy_hash(),
            "publication": "BLOCKED",
            "remote_pr": "NOT_RUN",
            "attempts": 1,
        }
        try:
            result = self.control.execute(plan, grant.repair_approval)
            receipt["repair"] = result
            receipt["reason_code"] = {
                "NO_OP": "NO_FIX",
                "VALIDATION_FAILED": "FAILED_VALIDATION",
                "TIMED_OUT": "CHECK_TIMEOUT",
                "CANCELLED": "CANCELLED",
                "BLOCKED": "ATTEMPT_EXHAUSTED",
            }.get(result["status"], "NEEDS_RECONCILIATION")
            if result["status"] == "VALIDATED_LOCAL":
                candidate = self.verified_candidate(result)
                head = repair.git(candidate, "rev-parse", "HEAD").strip()
                checked = self.check(candidate)
                if (
                    head != result["tested_commit"]
                    or head == event["head_sha"]
                    or checked["exit_code"] != 0
                    or result["diff"] != DIFF
                    or repair.files(candidate) != result["candidate_files"]
                    or repair.git(candidate, "rev-parse", "HEAD").strip() != head
                    or repair.git(candidate, "status", "--porcelain=v1", "--untracked-files=all")
                ):
                    raise safety.Blocked("BLOCKED: new-commit verification failed")
                self.observed(observation)
                self.control._approved(plan, grant.repair_approval)
                self.verified_candidate(result)
                receipt.update(
                    status="READY_FOR_LOCAL_REVIEW",
                    reason_code="VERIFIED_NEW_COMMIT",
                    post_commit_check={**checked, "head_sha": head, "run_id": str(uuid.uuid4())},
                )
        except (
            safety.Blocked,
            OSError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ):
            receipt.update(status="ESCALATED", reason_code="NEEDS_RECONCILIATION")
            if isinstance(receipt.get("repair"), dict):
                receipt["repair"] = {k: v for k, v in receipt["repair"].items() if k != "proposal"}
        count = self.db.execute(
            "UPDATE attempts SET status=?,receipt=?,proof=? "
            "WHERE fingerprint=? AND status='EXECUTING'",
            (receipt["status"], repair.canonical(receipt), self.sign(receipt), key),
        ).rowcount
        if count != 1:
            raise safety.Blocked("BLOCKED: maintenance terminal state changed")
        return receipt
