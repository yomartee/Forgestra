"""Read-only adoption planning and private authored-fixture transitions.

No customer writes, target commands, Git transport or publishing authority.
Ownership metadata is a declaration to review, never runtime authorization.
"""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Any

import forgestra_safety as safety
from forgestra.verification import bounded_file
from forgestra.workspaces import plan as workspace_plan
from forgestra.workspaces import read_package
from forgestra.configuration import load, validate, safe_directory

NAMESPACE = ".forgestra"
RECEIPT = NAMESPACE + "/installation.json"
VERSIONS = ("0.2.0.dev0", "0.2.0.dev1")  # Authored, unreleased fixture catalog.
_SEAL = object()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def assets(version):
    if version not in VERSIONS:
        raise safety.Blocked("BLOCKED: unknown factory asset version")
    return {
        NAMESPACE
        + "/assets/README.md": (
            "# Forgestra offline adoption assets\n"
            + "Unreleased fixture version: "
            + version
            + "\n"
            + "No workflows, hooks, dependencies or automation are enabled.\n"
        ).encode(),
        NAMESPACE
        + "/assets/settings.json": encoded(
            {"factory_version": version, "privileged_automation": "DISABLED"}
        ),
    }


def receipt(version):
    return encoded(
        {
            "schema_version": 1,
            "product": "forgestra",
            "factory_version": version,
            "ownership": {name: digest(data) for name, data in assets(version).items()},
        }
    )


def checkpoint():
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise safety.Blocked("BLOCKED: kill switch active")


def read_tree(root):
    """Bounded byte snapshot; metadata is excluded and never executed."""
    root = Path(root).absolute()
    if not root.is_dir():
        raise safety.Blocked("BLOCKED: target directory missing")
    for path in [root, *root.parents]:
        if path.is_symlink() or path.is_junction():
            raise safety.Blocked("BLOCKED: linked target unsupported")
    files = {}
    directories = []
    stack = [root]
    seen = set()
    count = 0
    size = 0
    while stack:
        directory = stack.pop()
        for path in directory.iterdir():
            count += 1
            if count > 512:
                raise safety.Blocked("BLOCKED: target entry budget exceeded")
            relative = path.relative_to(root).as_posix()
            safety.relative_path(relative)
            folded = relative.casefold()
            if folded in seen or len(path.relative_to(root).parts) > 16:
                raise safety.Blocked("BLOCKED: ambiguous or deep target path")
            seen.add(folded)
            if path.is_symlink() or path.is_junction():
                raise safety.Blocked("BLOCKED: linked target entry unsupported")
            if folded == ".git":
                if relative != ".git" or not path.is_dir():
                    raise safety.Blocked("BLOCKED: unsupported Git metadata layout")
                continue
            if path.is_dir():
                directories.append(relative)
                stack.append(path)
            elif path.is_file():
                data = bounded_file(path, 262144)
                size += len(data)
                if size > 2_000_000:
                    raise safety.Blocked("BLOCKED: target byte budget exceeded")
                files[relative] = data
            else:
                raise safety.Blocked("BLOCKED: special target entry unsupported")
    return {"files": files, "directories": sorted(directories)}


def tree_hash(tree):
    return digest(
        encoded(
            {
                "files": {k: digest(v) for k, v in sorted(tree["files"].items())},
                "directories": tree["directories"],
            }
        )
    )


def default_branch(root):
    """Cached origin/HEAD is advisory; missing permissions never imply master."""
    path = Path(root) / ".git/refs/remotes/origin/HEAD"
    try:
        text = bounded_file(path, 1024).decode("ascii").strip()
    except FileNotFoundError:
        return {"name": None, "source": "UNAVAILABLE", "live_verified": False}
    prefix = "ref: refs/remotes/origin/"
    branch = text.removeprefix(prefix)
    if (
        not text.startswith(prefix)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./-]{0,199}", branch)
        or any(
            p in {"", ".", ".."} or p.startswith(".") or p.endswith(".lock")
            for p in branch.split("/")
        )
        or ".." in branch
        or "//" in branch
        or branch.endswith((".", "/"))
    ):
        raise safety.Blocked("BLOCKED: invalid cached default branch")
    return {"name": branch, "source": "LOCAL_CACHED_ORIGIN_HEAD", "live_verified": False}


def _plan(tree, action, version, branch, workspaces):
    if action not in {"install", "upgrade", "uninstall"}:
        raise safety.Blocked("BLOCKED: unsupported adoption operation")
    desired = assets(version)
    files = tree["files"]
    conflicts = []
    changes: list[dict[str, Any]] = []
    old_version = None
    owned = {}
    if RECEIPT in files:
        try:
            document = safety.strict_json_loads(files[RECEIPT].decode("utf-8"))
            old_version = document["factory_version"]
            if files[RECEIPT] != receipt(old_version):
                raise ValueError("unrecognized receipt")
            owned = assets(old_version)
        except (ValueError, TypeError, KeyError, safety.Blocked):
            old_version = None
            conflicts.append({"path": RECEIPT, "reason": "INVALID_OWNERSHIP_MANIFEST"})
    elif action in {"upgrade", "uninstall"}:
        conflicts.append({"path": RECEIPT, "reason": "MISSING_OWNERSHIP_MANIFEST"})
    # Every managed file must still match the installed version, even on repeat.
    for name, data in owned.items():
        if files.get(name) != data:
            conflicts.append({"path": name, "reason": "MODIFIED_OR_MISSING_OWNED_FILE"})
    if old_version and action == "install" and old_version != version:
        conflicts.append({"path": RECEIPT, "reason": "EXPLICIT_UPGRADE_REQUIRED"})
    if (
        old_version in VERSIONS
        and action == "upgrade"
        and VERSIONS.index(version) < VERSIONS.index(old_version)
    ):
        conflicts.append({"path": RECEIPT, "reason": "DOWNGRADE_REQUIRES_REVIEW"})
    proposed = {} if action == "uninstall" else {**desired, RECEIPT: receipt(version)}
    managed = set(owned) | ({RECEIPT} if owned else set())
    for name in set(proposed) | managed:
        for entry in [*files, *tree["directories"]]:
            if entry == name and entry in managed and entry not in tree["directories"]:
                continue
            if (
                entry.casefold() == name.casefold()
                or name.casefold().startswith(entry.casefold() + "/")
                and (entry in files or not name.startswith(entry + "/"))
                or entry.casefold().startswith(name.casefold() + "/")
                or entry.casefold() == NAMESPACE
                and entry != NAMESPACE
                or entry.casefold().startswith(NAMESPACE + "/")
                and entry.split("/")[0] != NAMESPACE
            ):
                conflicts.append({"path": entry, "reason": "UNOWNED_DESTINATION_COLLISION"})
        before = files.get(name)
        after = proposed.get(name)
        if before != after:
            changes.append(
                {
                    "operation": (
                        "delete" if after is None else "add" if before is None else "modify"
                    ),
                    "path": name,
                    "before_sha256": digest(before) if before is not None else None,
                    "after_sha256": digest(after) if after is not None else None,
                }
            )
    unique_conflicts = sorted({(c["path"], c["reason"]) for c in conflicts})
    prerequisites = []
    if branch["name"] is None:
        prerequisites.append("DEFAULT_BRANCH_UNAVAILABLE_NO_FALLBACK")
    if workspaces["status"] != "PLANNED_LOCAL":
        prerequisites.append("TARGET_TOOLCHAIN_CONFIGURATION_REQUIRED")
    else:
        for workspace in workspaces["workspaces"]:
            if "test" not in workspace["commands"]:
                prerequisites.append("TARGET_TEST_COMMAND_REQUIRED")
            if workspace["language"] == "python" and workspace["lockfile"] is None:
                prerequisites.append("TARGET_DEPENDENCY_LOCK_REQUIRED")
            if workspace.get("declared_build_missing", False):
                prerequisites.append("TARGET_BUILD_COMMAND_REQUIRED")
    result = {
        "schema_version": 1,
        "status": (
            "REVIEW_REQUIRED"
            if unique_conflicts or prerequisites
            else "PLANNED_LOCAL" if changes else "NO_OP"
        ),
        "action": action,
        "input_sha256": tree_hash(tree),
        "installed_factory_version": old_version,
        "proposed_factory_version": version,
        "asset_catalog": "UNRELEASED_AUTHORED_FIXTURE",
        "default_branch": branch,
        "workspaces": workspaces,
        "prerequisites": sorted(set(prerequisites)),
        "conflicts": [{"path": p, "reason": r} for p, r in unique_conflicts],
        "changes": sorted(changes, key=lambda c: c["path"]),
        "ownership_authority": "UNTRUSTED_DECLARATION_REQUIRES_REVIEW",
        "execution": "BLOCKED",
        "target_tests": "NOT_RUN",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "remote": "NOT_RUN",
        "side_effects": [],
    }
    result["plan_sha256"] = digest(encoded(result))
    return result


def plan(root, action="install", version=VERSIONS[0], configuration=None):
    configuration = load() if configuration is None else validate(configuration)
    root = Path(root).absolute()
    tree = read_tree(root)
    branch = default_branch(root)
    try:
        manifests = {
            (str(Path(name).parent), "node" if name.endswith("package.json") else "python")
            for name in tree["files"]
            if Path(name).name in {"package.json", "pyproject.toml", "requirements.txt"}
        }
        if len(manifests) > 1 and not configuration["workspaces"]:
            raise safety.Blocked("BLOCKED: mixed target needs explicit workspaces")
        workspaces = workspace_plan(root, configuration)
        for workspace in workspaces["workspaces"]:
            if workspace["language"] == "javascript":
                scripts = read_package(safe_directory(root, workspace["path"]) / "package.json")
                if "build" in scripts and "build" not in workspace["commands"]:
                    workspace["declared_build_missing"] = True
    except (OSError, ValueError, TypeError, safety.Blocked):
        workspaces = {"status": "BLOCKED", "reason": "EXPLICIT_TOOLCHAIN_REQUIRED"}
    if tree != read_tree(root) or branch != default_branch(root):
        raise safety.Blocked("BLOCKED: target changed during planning")
    result = _plan(tree, action, version, branch, workspaces)
    # A redacted path/command/branch would describe a different immutable plan.
    from forgestra.providers import sanitized

    if sanitized(result) != result:
        raise safety.Blocked("BLOCKED: adoption plan contains sensitive metadata")
    return result


def runtime_install():
    return {
        "status": "BLOCKED",
        "reason_code": "RUNTIME_INSTALL_DISABLED",
        "privileged_automation": "DISABLED",
        "publication": "BLOCKED",
        "target_execution": "DISABLED",
    }


# Literal authored data only. Workflow stays inert and is never run.
SEED = {
    "README.md": b"Customer application\r\n",
    "CLAUDE.md": b"Preserve customer instructions.\n",
    "requirements.txt": b"# Customer dependencies, never installed\n",
    "config/customer.json": b'{"customer":true}\n',
    ".github/workflows/customer.yml": b"name: Customer workflow\non: workflow_dispatch\n",
    "package.json": b'{"scripts":{"build":"node build.js","test":"node test.js"}}\n',
    "package-lock.json": b'{"lockfileVersion":3,"packages":{"":{}}}\n',
    "build.js": b"console.log('authored fixture build');\n",
    "test.js": b"require('node:assert/strict').equal(2 + 3, 5);\n",
    "binary.dat": bytes([0, 255, 13, 10]),
}
FIXTURE_CONFIGURATION: dict[str, Any] = {
    "version": 1,
    "capabilities": {},
    "targets": [],
    "workspaces": [
        {
            "path": ".",
            "language": "javascript",
            "manager": "npm",
            "commands": {name: ["npm", "run", name] for name in ("build", "test")},
        }
    ],
}


class FixtureInstaller:
    """Trusted test harness; never accepts a caller-owned target or asset set."""

    def __init__(self, parent, seal):
        if seal is not _SEAL or parent != safety._LOCAL_OUTPUT_PARENT.get():
            raise safety.Blocked("BLOCKED: fixture control is not issued")
        checkpoint()
        self.parent = parent
        self.active = True
        self.current = parent / "authored-target"
        self.current.mkdir()
        for name, data in SEED.items():
            checkpoint()
            output = self.current / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(data)
        # Cached metadata is synthetic and explicitly not a live default-branch check.
        head = self.current / ".git/refs/remotes/origin/HEAD"
        head.parent.mkdir(parents=True)
        head.write_bytes(b"ref: refs/remotes/origin/team/trunk\n")

    def preview(self, action="install", version=VERSIONS[0]):
        return plan(self.current, action, version, FIXTURE_CONFIGURATION)

    def transition(self, action="install", version=VERSIONS[0]):
        checkpoint()
        if not self.active or self.parent != safety._LOCAL_OUTPUT_PARENT.get():
            raise safety.Blocked("BLOCKED: fixture scope expired")
        if (
            self.current.parent != self.parent
            or self.current.is_symlink()
            or self.current.is_junction()
        ):
            raise safety.Blocked("BLOCKED: fixture root changed")
        before = read_tree(self.current)
        proposal = self.preview(action, version)
        if proposal["status"] != "PLANNED_LOCAL":
            return {"status": proposal["status"], "plan": proposal, "candidate": None}
        checkpoint()
        candidate = self.parent / ("adoption-" + uuid.uuid4().hex)
        candidate.mkdir()
        output_files = dict(before["files"])
        for change in proposal["changes"]:
            name = change["path"]
            if change["operation"] == "delete":
                del output_files[name]
            else:
                output_files[name] = receipt(version) if name == RECEIPT else assets(version)[name]
        for name in before["directories"]:
            checkpoint()
            (candidate / name).mkdir(parents=True, exist_ok=True)
        for name, data in output_files.items():
            checkpoint()
            path = candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        # Recreate only the authored cached ref; never copy arbitrary Git metadata.
        checkpoint()
        head = candidate / ".git/refs/remotes/origin/HEAD"
        head.parent.mkdir(parents=True)
        head.write_bytes(
            ("ref: refs/remotes/origin/" + proposal["default_branch"]["name"] + "\n").encode(
                "ascii"
            )
        )
        checkpoint()
        if before != read_tree(self.current) or proposal != self.preview(action, version):
            raise safety.Blocked("BLOCKED: fixture source changed")
        if read_tree(candidate)["files"] != output_files:
            raise safety.Blocked("BLOCKED: fixture candidate validation failed")
        checkpoint()
        self.current = candidate
        return {
            "status": "APPLIED_FIXTURE_ONLY",
            "plan": proposal,
            "candidate": candidate.name,
            "output_sha256": tree_hash(read_tree(candidate)),
        }


@contextmanager
def local_install_fixture():
    with safety.private_output_workspace() as parent:
        control = FixtureInstaller(parent, _SEAL)
        try:
            yield control
        finally:
            control.active = False
