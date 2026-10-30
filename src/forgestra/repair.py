"""PR 04 local control/executor/publisher separation on authored fixtures only.

No caller-chosen destination, target code execution, provider or remote transport.
Python objects in this trusted process are not an OS isolation boundary.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import hashlib
import hmac
import json
from itertools import islice
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid

import forgestra_safety as safety
from forgestra.verification import bounded_file

SEED = {
    "README.md": "Authored offline addition fixture; no customer code.\n",
    "src/arithmetic.py": "def add(a, b):\n    return a - b\n",
}
FIX = "def add(a, b):\n    return a + b\n"
REFACTOR = "def add(a, b):\n    total = a + b\n    return total\n"
CHECK = r"""
import ast,json,pathlib,sys
try:
    tree=ast.parse(pathlib.Path("src/arithmetic.py").read_text(encoding="utf-8"))
    assert len(tree.body)==1 and isinstance(tree.body[0],ast.FunctionDef)
    f=tree.body[0]
    assert f.name=="add" and not f.decorator_list and not f.args.defaults
    assert f.returns is None and not f.type_params
    assert ast.dump(f.args)==ast.dump(ast.parse("def add(a,b): pass").body[0].args)
    if len(f.body)==2:
        assignment,ret=f.body
        assert isinstance(assignment,ast.Assign) and len(assignment.targets)==1
        assert isinstance(assignment.targets[0],ast.Name) and assignment.targets[0].id=="total"
        assert (isinstance(ret,ast.Return) and isinstance(ret.value,ast.Name)
                and ret.value.id=="total")
        node=assignment.value
    else:
        assert len(f.body)==1 and isinstance(f.body[0],ast.Return)
        node=f.body[0].value
    assert isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Add,ast.Sub))
    assert isinstance(node.left,ast.Name) and node.left.id=="a"
    assert isinstance(node.right,ast.Name) and node.right.id=="b"
    cases=[(2,3,5),(-1,1,0),(0,0,0)]
    count=0
    for a,b,want in cases:
        got=a+b if isinstance(node.op,ast.Add) else a-b
        assert got==want
        count+=1
    result={"status":"PASSED","collected":3,"tests":count,"failures":0,"errors":0,"skipped":0,"expected_failures":0,"unexpected_successes":0}
except Exception:
    result={"status":"FAILED","collected":3,"tests":0,"failures":1,"errors":0,"skipped":0,"expected_failures":0,"unexpected_successes":0}
print(json.dumps(result,sort_keys=True))
sys.exit(0 if result["status"]=="PASSED" else 1)
"""
CHECKS_HASH = hashlib.sha256(CHECK.encode()).hexdigest()
_GIT_CONFIGS: ContextVar[dict | None] = ContextVar("fixture_git_configs", default=None)
_PROOF_KEY: ContextVar[bytes | None] = ContextVar("fixture_verification_key", default=None)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def checkpoint():
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise safety.Blocked("BLOCKED: kill switch active")


def environment(profile):
    allowed = {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
    env = {k: v for k, v in os.environ.items() if k.upper() in allowed}
    env.update(
        {
            "HOME": str(profile),
            "USERPROFILE": str(profile),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_AUTHOR_NAME": "Forgestra local fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Forgestra local fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
            "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
            "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
        }
    )
    return env


def git(root, *args):
    """Fixed calls on safety-issued fixture roots, no shell/config/hooks/remotes."""
    checkpoint()
    allowed = {
        ("init", "--template=", "--initial-branch=fixture-base"),
        ("init", "--template=", "--initial-branch=fixture-repair"),
        ("add", "--", *SEED),
        ("add", "--", "src/arithmetic.py"),
        ("commit", "--no-verify", "-m", "Authored offline fixture"),
        ("commit", "--no-verify", "-m", "Offline fixture addition repair"),
        ("rev-parse", "HEAD"),
        ("status", "--porcelain=v1", "--untracked-files=all"),
    }
    diff = (
        len(args) == 8
        and args[:6]
        == ("diff", "--no-ext-diff", "--no-textconv", "--name-status", "-z", "--no-renames")
        and all(
            isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value)
            for value in args[6:]
        )
    )
    if args not in allowed and not diff:
        raise safety.Blocked("BLOCKED: unsupported Git command")
    parent = safety._LOCAL_OUTPUT_PARENT.get()
    registry = _GIT_CONFIGS.get()
    if parent is None or registry is None or root.absolute().parent != parent:
        raise safety.Blocked("BLOCKED: Git is restricted to issued fixture roots")
    for path in (root, root / ".git"):
        if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
            raise safety.Blocked("BLOCKED: linked fixture root")
    metadata = root / ".git"
    if metadata.exists():
        pending, entries = [metadata], 0
        while pending:
            directory = pending.pop()
            children = list(islice(directory.iterdir(), 1001 - entries))
            entries += len(children)
            if entries > 1000:
                raise safety.Blocked("BLOCKED: fixture Git metadata limit")
            for path in children:
                if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                    raise safety.Blocked("BLOCKED: linked Git metadata")
                if path.is_dir():
                    pending.append(path)
        if registry.get(str(root)) != digest(bounded_file(metadata / "config")):
            raise safety.Blocked("BLOCKED: fixture Git configuration changed")
        for name in ("info/attributes", "info/grafts", "objects/info/alternates"):
            if (metadata / name).exists():
                raise safety.Blocked("BLOCKED: unsupported Git controls")
    executable = "C:/Program Files/Git/cmd/git.exe" if os.name == "nt" else shutil.which("git")
    if not executable:
        raise safety.Blocked("BLOCKED: local Git unavailable")
    command = subprocess.run(
        [
            executable,
            "--no-optional-locks",
            "-c",
            "core.hooksPath=" + str(root.parent / "no-hooks"),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.autocrlf=false",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.attributesFile=" + os.devnull,
            *args,
        ],
        cwd=root,
        env=environment(root.parent),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    if command.returncode != 0:
        raise safety.Blocked("BLOCKED: local Git command failed")
    if args and args[0] == "init":
        registry[str(root)] = digest(bounded_file(metadata / "config"))
    return command.stdout


def files(root):
    output = {}
    for name in SEED:
        output[name] = digest(bounded_file(root / name, 32000))
    observed = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        children = list(islice(directory.iterdir(), 5))
        if len(children) > 4:
            raise safety.Blocked("BLOCKED: unexpected fixture entries")
        for path in children:
            name = path.relative_to(root).as_posix()
            if name == ".git":
                continue  # Git controls are separately validated before every Git invocation.
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                raise safety.Blocked("BLOCKED: linked fixture")
            if path.is_dir():
                if name != "src":
                    raise safety.Blocked("BLOCKED: unexpected fixture directory")
                pending.append(path)
            elif path.is_file():
                observed.add(name)
            else:
                raise safety.Blocked("BLOCKED: special fixture file")
    if observed != set(SEED):
        raise safety.Blocked("BLOCKED: unexpected fixture files")
    return output


def policy_hash():
    return digest(bounded_file(Path(__file__)) + bounded_file(Path(safety.__file__)))


@dataclass(frozen=True)
class Approval:
    payload: str
    signature: str


class LocalPublisher:
    """Prepare an offline proposal only after rechecking the tested candidate."""

    @staticmethod
    def prepare(candidate, record):
        checkpoint()
        if not isinstance(record, dict):
            raise safety.Blocked("BLOCKED: invalid verification receipt")
        key = _PROOF_KEY.get()
        material = {
            k: v for k, v in record.items() if k not in {"verification_signature", "proposal"}
        }
        if (
            key is None
            or not isinstance(record.get("verification_signature"), str)
            or not hmac.compare_digest(
                hmac.new(key, canonical(material).encode(), "sha256").hexdigest(),
                record["verification_signature"],
            )
        ):
            raise safety.Blocked("BLOCKED: trusted verification receipt required")
        if (
            record["status"] != "VALIDATED_LOCAL"
            or record["policy_sha256"] != policy_hash()
            or record["checks_sha256"] != CHECKS_HASH
            or record["tests"].get("status") != "PASSED"
            or record["check_exit_code"] != 0
            or git(candidate, "rev-parse", "HEAD").strip() != record["tested_commit"]
            or files(candidate) != record["candidate_files"]
            or git(candidate, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise safety.Blocked("BLOCKED: tested candidate changed")
        return {
            "kind": "OFFLINE_PR_PROPOSAL",
            "head_sha": record["tested_commit"],
            "base_sha": record["input_commit"],
            "remote": "NOT_RUN",
            "publication": "BLOCKED",
        }

    @staticmethod
    def publish(*_args, **_kwargs):
        safety.require("publication")


class FixtureControl:
    """Trusted ephemeral fixture control, never authority for customer repositories."""

    def __init__(self, parent, seal, profile="repair"):
        if (
            profile not in {"repair", "refactor"}
            or seal is not _ISSUED
            or parent != safety._LOCAL_OUTPUT_PARENT.get()
            or _GIT_CONFIGS.get() is None
        ):
            raise safety.Blocked("BLOCKED: fixture control must be safety-issued")
        self.seed = {**SEED, "src/arithmetic.py": FIX} if profile == "refactor" else dict(SEED)
        self.parent = parent
        self.source = parent / "source"
        self.scope_id = str(uuid.uuid4())
        self.key = secrets.token_bytes(32)
        self.active = True
        self.target_id = digest((self.scope_id + ":authored-fixture").encode())
        self.journal = sqlite3.connect(parent / "runs.sqlite", isolation_level=None)
        self.journal.execute("PRAGMA synchronous=FULL")
        self.journal.execute(
            "CREATE TABLE runs (key TEXT PRIMARY KEY, run_id TEXT, status TEXT, result TEXT)"
        )
        self.journal.execute("CREATE TABLE budget (id INTEGER PRIMARY KEY, attempts INTEGER)")
        self.journal.execute("INSERT INTO budget VALUES (1, 0)")
        safety.write_new_tree(
            self.source, [{"path": p, "content": c} for p, c in self.seed.items()]
        )
        git(self.source, "init", "--template=", "--initial-branch=fixture-base")
        git(self.source, "add", "--", *SEED)
        git(self.source, "commit", "--no-verify", "-m", "Authored offline fixture")
        self.input_commit = git(self.source, "rev-parse", "HEAD").strip()
        self.input_files = files(self.source)

    def plan(self, content=FIX):
        self._check()
        try:
            if not isinstance(content, str) or len(content.encode("utf-8")) > 32000:
                raise safety.Blocked("BLOCKED: fixture change exceeds byte budget")
        except UnicodeError:
            raise safety.Blocked("BLOCKED: invalid fixture encoding") from None
        safety.validate_manifest([{"path": "src/arithmetic.py", "content": content}])
        return {
            "schema_version": 1,
            "mode": "AUTHORED_FIXTURE_ONLY",
            "scope_id": self.scope_id,
            "target_id": self.target_id,
            "input_commit": self.input_commit,
            "input_files": dict(self.input_files),
            "policy_sha256": policy_hash(),
            "checks_sha256": CHECKS_HASH,
            "changes": [
                {
                    "operation": "modify",
                    "path": "src/arithmetic.py",
                    "before_sha256": self.input_files["src/arithmetic.py"],
                    "content": content,
                }
            ],
        }

    def _check(self):
        checkpoint()
        if (
            not self.active
            or self.parent != safety._LOCAL_OUTPUT_PARENT.get()
            or self.source != self.parent / "source"
        ):
            raise safety.Blocked("BLOCKED: expired fixture scope")

    def approve(self, plan):
        """Trusted harness approval; no JSON/CLI approval command exists."""
        self._validate(plan)
        payload = canonical(
            {
                "plan_sha256": digest(canonical(plan).encode()),
                "target_id": self.target_id,
                "input_commit": self.input_commit,
                "policy_sha256": policy_hash(),
                "checks_sha256": CHECKS_HASH,
                "scope_id": self.scope_id,
                "expires_at": time.time() + 300,
            }
        )
        return Approval(payload, hmac.new(self.key, payload.encode(), "sha256").hexdigest())

    def _validate(self, plan):
        self._check()
        if not isinstance(plan, dict) or set(plan) != set(self.plan()):
            raise safety.Blocked("BLOCKED: invalid plan")
        changes = plan.get("changes")
        if not isinstance(changes, list) or len(changes) != 1:
            raise safety.Blocked("BLOCKED: unsupported change batch")
        change = changes[0]
        if not isinstance(change, dict) or set(change) != {
            "operation",
            "path",
            "before_sha256",
            "content",
        }:
            raise safety.Blocked("BLOCKED: invalid change")
        expected = self.plan(change["content"])
        if canonical(plan) != canonical(expected):
            raise safety.Blocked("BLOCKED: changed target, input, policy, checks or protected path")
        if (
            files(self.source) != self.input_files
            or git(self.source, "rev-parse", "HEAD").strip() != self.input_commit
            or git(self.source, "status", "--porcelain=v1", "--untracked-files=all")
        ):
            raise safety.Blocked("BLOCKED: source changed")

    def _approved(self, plan, approval):
        self._validate(plan)
        if not isinstance(approval, Approval):
            raise safety.Blocked("BLOCKED: trusted approval required")
        if not isinstance(approval.payload, str) or not isinstance(approval.signature, str):
            raise safety.Blocked("BLOCKED: invalid approval types")
        signature = hmac.new(self.key, approval.payload.encode(), "sha256").hexdigest()
        if not hmac.compare_digest(signature, approval.signature):
            raise safety.Blocked("BLOCKED: invalid approval")
        data = safety.strict_json_loads(approval.payload)
        if (
            data["expires_at"] <= time.time()
            or data["scope_id"] != self.scope_id
            or data["plan_sha256"] != digest(canonical(plan).encode())
            or data["target_id"] != self.target_id
            or data["input_commit"] != self.input_commit
            or data["policy_sha256"] != policy_hash()
            or data["checks_sha256"] != CHECKS_HASH
        ):
            raise safety.Blocked("BLOCKED: approval expired or binding changed")

    def execute(self, plan, approval=None):
        try:
            return self._execute(plan, approval)
        except (
            sqlite3.Error,
            OSError,
            subprocess.SubprocessError,
            safety.Blocked,
            ValueError,
            TypeError,
            KeyError,
        ):
            return {"status": "NEEDS_RECONCILIATION", "publication": "BLOCKED"}

    def _execute(self, plan, approval=None):
        try:
            self._approved(plan, approval)
        except (safety.Blocked, ValueError, TypeError, KeyError, OSError):
            return {"status": "BLOCKED", "publication": "BLOCKED", "side_effects": []}
        key = digest(canonical(plan).encode())
        prior = self.journal.execute(
            "SELECT status, result FROM runs WHERE key=?", (key,)
        ).fetchone()
        if prior:
            return self._cached(key, prior)
        lock = self.parent / "target.lock"
        try:
            handle = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return {"status": "BLOCKED", "reason_code": "TARGET_LOCKED", "publication": "BLOCKED"}
        os.close(handle)
        try:
            return self._execute_locked(plan, key, approval)
        finally:
            lock.unlink(missing_ok=True)

    def _cached(self, key, prior):
        try:
            result = safety.strict_json_loads(prior[1])
            if (
                not isinstance(result, dict)
                or result.get("idempotency_key") != key
                or result.get("plan_sha256") != key
                or result.get("target_id") != self.target_id
                or result.get("status") != prior[0]
                or prior[0]
                not in {
                    "NO_OP",
                    "VALIDATION_FAILED",
                    "TIMED_OUT",
                    "CANCELLED",
                    "NEEDS_RECONCILIATION",
                    "VALIDATED_LOCAL",
                }
            ):
                raise safety.Blocked("BLOCKED: incomplete or inconsistent run")
            proof_key = _PROOF_KEY.get()
            material = {
                k: v for k, v in result.items() if k not in {"verification_signature", "proposal"}
            }
            if (
                proof_key is None
                or not isinstance(result.get("verification_signature"), str)
                or not hmac.compare_digest(
                    hmac.new(proof_key, canonical(material).encode(), "sha256").hexdigest(),
                    result["verification_signature"],
                )
            ):
                raise safety.Blocked("BLOCKED: invalid journal receipt")
            if result["status"] == "VALIDATED_LOCAL":
                result["proposal"] = LocalPublisher.prepare(
                    self.parent / result["candidate"], result
                )
            return result
        except (safety.Blocked, OSError, TypeError, ValueError, KeyError):
            return {"status": "NEEDS_RECONCILIATION", "publication": "BLOCKED"}

    def _execute_locked(self, plan, key, approval):
        try:
            self._approved(plan, approval)
        except (safety.Blocked, ValueError, TypeError, KeyError, OSError):
            return {"status": "BLOCKED", "publication": "BLOCKED"}
        prior = self.journal.execute(
            "SELECT status, result FROM runs WHERE key=?", (key,)
        ).fetchone()
        if prior:
            return self._cached(key, prior)
        self.journal.execute("BEGIN IMMEDIATE")
        run_id = str(uuid.uuid4())
        try:
            attempts = self.journal.execute("SELECT attempts FROM budget WHERE id=1").fetchone()[0]
            if attempts >= 1:
                self.journal.execute("ROLLBACK")
                return {
                    "status": "BLOCKED",
                    "reason_code": "BUDGET_EXHAUSTED",
                    "publication": "BLOCKED",
                }
            self.journal.execute("UPDATE budget SET attempts=attempts+1 WHERE id=1")
            self.journal.execute("INSERT INTO runs VALUES (?, ?, 'RUNNING', '{}')", (key, run_id))
            self.journal.execute("COMMIT")
        except Exception:
            self.journal.execute("ROLLBACK")
            raise
        candidate = self.parent / ("candidate-" + run_id)
        result = {
            "run_id": run_id,
            "idempotency_key": key,
            "target_id": self.target_id,
            "input_commit": self.input_commit,
            "plan_sha256": key,
            "policy_sha256": plan["policy_sha256"],
            "checks_sha256": CHECKS_HASH,
            "approval_sha256": digest(approval.payload.encode()),
            "status": "RUNNING",
            "publication": "BLOCKED",
            "remote_pr": "NOT_RUN",
            "auto_merge": False,
            "candidate": candidate.name,
            "tests": "NOT_RUN",
            "mode": "AUTHORED_FIXTURE_ONLY",
        }
        result.update(
            approval_source="TRUSTED_FIXTURE_HARNESS",
            executor="TRUSTED_AST_SEMANTICS",
            publisher="OFFLINE_PROPOSAL_ONLY",
        )
        try:
            content = plan["changes"][0]["content"]
            if content == self.seed["src/arithmetic.py"]:
                result["status"] = "NO_OP"
            else:
                safety.write_new_tree(
                    candidate,
                    [
                        {"path": p, "content": content if p == "src/arithmetic.py" else c}
                        for p, c in self.seed.items()
                    ],
                )
                git(candidate, "init", "--template=", "--initial-branch=fixture-repair")
                git(candidate, "add", "--", *SEED)
                # Recreate the exact base first; never clone or fetch an untrusted remote.
                (candidate / "src/arithmetic.py").write_bytes(
                    self.seed["src/arithmetic.py"].encode()
                )
                git(candidate, "add", "--", *SEED)
                git(candidate, "commit", "--no-verify", "-m", "Authored offline fixture")
                if git(candidate, "rev-parse", "HEAD").strip() != self.input_commit:
                    raise safety.Blocked("BLOCKED: fixture base mismatch")
                checkpoint()
                (candidate / "src/arithmetic.py").write_bytes(content.encode())
                checked_files = files(candidate)
                command = self.check(candidate)
                result["tests"] = command["result"]
                result["check_exit_code"] = command["exit_code"]
                result["check_argv"] = command["argv"]
                if not command["passed"]:
                    result["status"] = "VALIDATION_FAILED"
                else:
                    checkpoint()
                    self._approved(plan, approval)
                    if files(candidate) != checked_files:
                        raise safety.Blocked("BLOCKED: candidate changed during checks")
                    git(candidate, "add", "--", "src/arithmetic.py")
                    git(candidate, "commit", "--no-verify", "-m", "Offline fixture addition repair")
                    head = git(candidate, "rev-parse", "HEAD").strip()
                    changes = git(
                        candidate,
                        "diff",
                        "--no-ext-diff",
                        "--no-textconv",
                        "--name-status",
                        "-z",
                        "--no-renames",
                        self.input_commit,
                        head,
                    ).split("\0")
                    if changes != ["M", "src/arithmetic.py", ""]:
                        raise safety.Blocked("BLOCKED: full Git diff differs from approved plan")
                    result.update(
                        status="VALIDATED_LOCAL",
                        tested_commit=head,
                        candidate_files=checked_files,
                        diff=[{"operation": "modify", "path": "src/arithmetic.py"}],
                        risk_tier=safety.classify_diff(
                            [{"operation": "modify", "path": "src/arithmetic.py"}]
                        ),
                    )
                    proof_key = _PROOF_KEY.get()
                    if proof_key is None:
                        raise safety.Blocked("BLOCKED: trusted verification scope expired")
                    result["verification_signature"] = hmac.new(
                        proof_key, canonical(result).encode(), "sha256"
                    ).hexdigest()
                    result["proposal"] = LocalPublisher.prepare(candidate, result)
        except subprocess.TimeoutExpired:
            result["status"] = "TIMED_OUT"
        except (OSError, safety.Blocked, ValueError, TypeError, KeyError):
            result["status"] = (
                "CANCELLED"
                if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0"
                else "NEEDS_RECONCILIATION"
            )
            result.pop("proposal", None)
            result.pop("verification_signature", None)
        proof_key = _PROOF_KEY.get()
        if proof_key is None:
            raise safety.Blocked("BLOCKED: verification scope expired")
        material = {
            k: v for k, v in result.items() if k not in {"verification_signature", "proposal"}
        }
        result["verification_signature"] = hmac.new(
            proof_key, canonical(material).encode(), "sha256"
        ).hexdigest()
        self.journal.execute(
            "UPDATE runs SET status=?, result=? WHERE key=?",
            (result["status"], canonical(result), key),
        )
        return result

    def check(self, candidate):
        self._check()
        if candidate.parent != self.parent or not candidate.name.startswith("candidate-"):
            raise safety.Blocked("BLOCKED: checks restricted to issued candidates")
        command = subprocess.run(
            [sys.executable, "-I", "-c", CHECK],
            cwd=candidate,
            env=environment(self.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        try:
            result = safety.strict_json_loads(command.stdout)
        except (TypeError, ValueError):
            result = {"status": "INVALID_RESULT"}
        valid = (
            isinstance(result, dict)
            and set(result)
            == {
                "status",
                "collected",
                "tests",
                "failures",
                "errors",
                "skipped",
                "expected_failures",
                "unexpected_successes",
            }
            and result["status"] in {"PASSED", "FAILED"}
            and all(type(result[k]) is int for k in result if k != "status")
            and result["collected"] == 3
            and 0 <= result["tests"] <= 3
            and all(result[k] >= 0 for k in result if k != "status")
        )
        return {
            "argv": [sys.executable, "-I", "-c", CHECK],
            "exit_code": command.returncode,
            "result": result if valid else {"status": "INVALID_RESULT"},
            "passed": (
                command.returncode == 0
                and valid
                and result["status"] == "PASSED"
                and result["tests"] == 3
                and all(result[k] == 0 for k in result if k not in {"status", "collected", "tests"})
            ),
        }


_ISSUED = object()


@contextmanager
def local_repair_fixture(profile="repair"):
    """Only trusted harness code uses this; it cannot accept a customer root."""
    with safety.private_output_workspace() as parent:
        token = _GIT_CONFIGS.set({})
        proof_token = _PROOF_KEY.set(secrets.token_bytes(32))
        control = FixtureControl.__new__(FixtureControl)
        try:
            FixtureControl.__init__(control, parent, _ISSUED, profile)
            yield control
        finally:
            _GIT_CONFIGS.reset(token)
            _PROOF_KEY.reset(proof_token)
            control.active = False
            control.key = b""
            connection = getattr(control, "journal", None)
            if connection is not None:
                connection.close()


def runtime_repair():
    try:
        safety.require("target_modification")
    except safety.Blocked:
        pass
    return {
        "status": "BLOCKED",
        "reason_code": "RUNTIME_REPAIR_DISABLED",
        "privileged_automation": "DISABLED",
        "publication": "BLOCKED",
        "target_execution": "DISABLED",
    }
