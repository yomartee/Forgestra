"""Offline safety primitives. Repository/model configuration never grants authority.

PR 01 intentionally supports inspection and new local fixture output only. Remote
and legacy mutation need later approval, budgets and isolation implementations.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
from pathlib import Path, PureWindowsPath
import re
import shutil
import tempfile
import time

CAPABILITIES = frozenset(
    {
        "paid_provider",
        "target_modification",
        "publication",
        "product_creation",
        "scheduled",
        "synchronization",
        "self_healing",
        "auto_merge",
        "outreach",
    }
)
ENV_EXAMPLE = (
    "# Configure user authentication on the backend.\n"
    "NEXT_PUBLIC_HASURA_ENDPOINT=https://example.invalid/v1/graphql\n"
)
PROTECTED_PARTS = frozenset(
    {
        ".git",
        ".github",
        ".gitmodules",
        ".gitconfig",
        ".gitattributes",
        ".gitignore",
        ".codex",
        ".agents",
        ".claude",
        ".cursor",
        ".vscode",
        ".idea",
        ".devcontainer",
        ".ssh",
        ".aws",
        ".docker",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".repo-index",
        ".coderabbit.yaml",
        ".coderabbit.yml",
        "agents",
        "workflows",
        "prompts",
        "policy",
        "policies",
        "config",
        "configs",
        "agents.md",
        "claude.md",
        "copilot-instructions.md",
        "codeowners",
        "security.md",
        "forgestra_safety.py",
        "check_safety.py",
        "check_workflows.py",
        "run_safety_isolated.py",
        "record_pr01_evidence.py",
        "record_pr03_evidence.py",
        "record_pr04_evidence.py",
        "record_pr05_evidence.py",
        "record_pr06_evidence.py",
        "pr06_web_validation.py",
        "pr07_creation_validation.py",
        "creation.py",
        "component_registry.py",
        "synchronization.py",
        "sync_control.py",
        "maintenance.py",
        "integrations.py",
        "pr10_mcp_validation.py",
        "record_pr10_evidence.py",
        "record_pr11_evidence.py",
        "pr11_release_validation.py",
        "release.py",
        "public_contract.py",
        "public_checks.py",
        "private_evidence.py",
        "build_distribution.py",
        "manifest.in",
        "pr10-mcp-tools.json",
        "forgestra_mcp",
        "pr09_maintenance_validation.py",
        "record_pr09_evidence.py",
        "record_pr08_evidence.py",
        "pr08_sync_validation.py",
        "record_pr07_evidence.py",
        "local_generation.py",
        "inspect_local.py",
        "pr01_validation.py",
        "forgestra_cli.py",
        "bootstrap.py",
        "acquire_tools.py",
        "ci.py",
        "record_pr02_evidence.py",
        "mcp.json",
    }
)
_LOCAL_OUTPUT_PARENT: ContextVar[Path | None] = ContextVar(
    "forgestra_private_output_parent", default=None
)


@contextmanager
def private_output_workspace():
    """Trusted offline fixture scope; no caller/model-provided root is accepted.

    This permits inert new local output only. It does not permit execution,
    customer changes, provider calls or publication. The private parent is
    single-writer and owned by this context; it is removed on exit.
    """
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        _blocked("kill switch active")
    try:
        temporary = tempfile.TemporaryDirectory(prefix="forgestra-local-")
    except OSError:
        raise Blocked("BLOCKED: private workspace unavailable") from None
    parent = Path(temporary.name).absolute()
    token = _LOCAL_OUTPUT_PARENT.set(parent)
    try:
        yield parent
    finally:
        _LOCAL_OUTPUT_PARENT.reset(token)
        for delay in (0, 0.1, 0.3, 1, 2):
            if delay:
                time.sleep(delay)
            try:
                temporary.cleanup()
                break
            except OSError:
                # Windows can enumerate a long Next/Git cache path but fail to
                # remove its children through the legacy path spelling. Keep
                # the same issued root and use the extended local-drive spelling.
                if os.name == "nt" and re.fullmatch(r"[A-Za-z]:", parent.drive):
                    temporary.name = "\\\\?\\" + str(parent)
                continue
        else:
            raise Blocked("BLOCKED: private workspace cleanup needs reconciliation") from None


def unique_pairs(items):
    """Ambiguous JSON must not discard earlier policy/diff evidence."""
    output = {}
    for key, value in items:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def strict_json_loads(content):
    def reject_constant(_value):
        raise ValueError("non-finite JSON value")

    return json.loads(content, object_pairs_hook=unique_pairs, parse_constant=reject_constant)


class Blocked(RuntimeError):
    """Terminal BLOCKED result; messages deliberately exclude untrusted inputs."""


def _blocked(reason):
    raise Blocked("BLOCKED: " + reason)


class Policy:
    def __init__(self, document=None):
        if document is None:
            document = {"version": 1, "capabilities": {}, "targets": []}
        if not isinstance(document, dict) or set(document) != {
            "version",
            "capabilities",
            "targets",
        }:
            _blocked("invalid policy schema")
        if type(document["version"]) is not int or document["version"] != 1:
            _blocked("unsupported policy version")
        caps = document["capabilities"]
        if (
            not isinstance(caps, dict)
            or set(caps) - CAPABILITIES
            or any(type(v) is not bool for v in caps.values())
        ):
            _blocked("invalid capabilities")
        targets = document["targets"]
        if not isinstance(targets, list):
            _blocked("invalid targets")
        self.targets: set[tuple[str, str, str]] = set()
        for target in targets:
            if not isinstance(target, dict) or set(target) != {"owner", "repository", "path"}:
                _blocked("invalid target")
            owner, repo, path = target["owner"], target["repository"], target["path"]
            if not all(
                isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", s)
                for s in (owner, repo)
            ):
                _blocked("invalid repository identity")
            if (
                repo in {".", ".."}
                or not isinstance(path, str)
                or not Path(path).is_absolute()
                or "*" in path
            ):
                _blocked("invalid target root")
            identity = (owner, repo, str(Path(path).resolve()))
            if identity in self.targets:
                _blocked("duplicate target")
            self.targets.add(identity)
        self.capabilities = dict(caps)

    @classmethod
    def load(cls, path):
        try:
            document = strict_json_loads(Path(path).read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                _blocked("invalid policy schema")
            return cls(document)
        except (OSError, ValueError, TypeError):
            _blocked("unreadable policy")

    def require(self, capability, target=None):
        # Re-read the kill switch on every boundary, including long-lived objects.
        if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
            _blocked("kill switch active")
        if not isinstance(capability, str) or capability not in CAPABILITIES:
            _blocked("unknown capability")
        if not self.capabilities.get(capability, False):
            _blocked("capability disabled")
        if (
            not isinstance(target, tuple)
            or len(target) != 3
            or not all(isinstance(v, str) for v in target)
            or target not in self.targets
        ):
            _blocked("target not approved")
        # A repository flag is intent, not trusted approval. No enabling bypass.
        _blocked("capability unsupported pending trusted approval and execution controls")


def require(capability):
    """Legacy entry-point gate: no repository policy can enable these paths."""
    Policy().require(capability)


def redact(value, secrets=()):
    text = str(value)
    values = list(secrets) + [
        v
        for k, v in os.environ.items()
        if any(word in k.upper() for word in ("TOKEN", "SECRET", "PASSWORD", "API_KEY"))
    ]
    for secret in sorted((v for v in values if isinstance(v, str) and v), key=len, reverse=True):
        variants = {secret, json.dumps(secret)[1:-1], repr(secret)[1:-1]}
        for variant in sorted(variants, key=len, reverse=True):
            text = text.replace(variant, "[REDACTED]")
    return re.sub(
        r"https?://[^\s/@]+(?::[^\s/@]*)?@", "https://[REDACTED]@", text, flags=re.IGNORECASE
    )


def relative_path(value):
    if not isinstance(value, str) or not value or len(value) > 240:
        _blocked("invalid path")
    if "\\" in value or PureWindowsPath(value).drive or value.startswith("/"):
        _blocked("absolute or Windows path")
    parts = value.split("/")
    next_dynamic_route = re.fullmatch(r"src/app/[a-z][a-z0-9_]*/\[id\]/edit/page\.tsx", value)
    for part in parts:
        if part == "[id]" and next_dynamic_route:
            continue
        if (
            part in {"", ".", ".."}
            or part.endswith((".", " "))
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
            or part.startswith("-")
        ):
            _blocked("unsafe path component")
        if part.split(".")[0].upper() in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            _blocked("reserved path component")
    return parts


def protected(value):
    parts = [p.lower() for p in relative_path(value)]
    return "forgestra" in parts or any(_control_component(part) for part in parts)


def _control_component(part):
    part = part.lower()
    return part in PROTECTED_PARTS or any(
        word in part for word in ("permission", "approval", "credential", "secret")
    )


def validate_diff(changes):
    if not isinstance(changes, list):
        _blocked("invalid diff manifest")
    destinations = set()
    for change in changes:
        if not isinstance(change, dict):
            _blocked("invalid diff entry")
        operation = change.get("operation")
        if not isinstance(operation, str) or operation not in {"add", "modify", "delete", "rename"}:
            _blocked("invalid diff operation")
        expected = (
            {"operation", "path", "source"} if operation == "rename" else {"operation", "path"}
        )
        if set(change) != expected:
            _blocked("ambiguous diff entry")
        relative_path(change["path"])
        key = change["path"].casefold()
        if key in destinations:
            _blocked("conflicting diff destinations")
        destinations.add(key)
        if operation == "rename":
            relative_path(change["source"])
            if change["source"].casefold() == key:
                _blocked("ambiguous rename")
    return changes


def classify_diff(changes):
    """0 = text-only review, 1 = review, 2 = privileged review. Never merge."""
    tier = 1  # Empty/unknown evidence requires review too.
    if changes is None or changes == []:
        return tier
    try:
        validate_diff(changes)
    except Blocked:
        return 2
    tiers = []
    for change in changes:
        if not isinstance(change, dict) or set(change) - {"operation", "path", "source"}:
            return 2
        operation = change.get("operation")
        if (
            not isinstance(operation, str)
            or operation not in {"add", "modify", "delete", "rename"}
            or "path" not in change
        ):
            return 2
        paths = [change["path"]]
        if operation == "rename":
            if "source" not in change:
                return 2
            paths.append(change["source"])
        elif "source" in change:
            return 2
        for path in paths:
            try:
                parts = relative_path(path)
                lower = path.lower()
                if (
                    protected(path)
                    or any(
                        k in lower
                        for k in (
                            "auth",
                            "payment",
                            "deploy",
                            "docker",
                            "production",
                            "terraform",
                            "requirements",
                            "package",
                            "lock",
                            "prompt",
                        )
                    )
                    or Path(path).suffix.lower() in {".yaml", ".yml", ".json", ".toml", ".ini"}
                ):
                    tiers.append(2)
                elif operation in {"delete", "rename"}:
                    tiers.append(1)
                elif (parts[0] == "docs" or len(parts) == 1) and Path(path).suffix.lower() in {
                    ".md",
                    ".txt",
                }:
                    tiers.append(0)
                else:
                    tiers.append(1)
            except Blocked:
                return 2
    return max(tiers)


def validate_manifest(files):
    if not isinstance(files, list) or not files:
        _blocked("empty or invalid file manifest")
    seen: set[str] = set()
    result = []
    for item in files:
        if (
            not isinstance(item, dict)
            or set(item) != {"path", "content"}
            or not isinstance(item["content"], str)
        ):
            _blocked("unsupported file operation or manifest field")
        path = item["path"]
        relative_path(path)
        if protected(path):
            _blocked("protected destination")
        key = path.casefold()
        if key in seen or any(key.startswith(p + "/") or p.startswith(key + "/") for p in seen):
            _blocked("conflicting destinations")
        if redact(item["content"]) != item["content"] or redact(path) != path:
            _blocked("credential in generated content")
        if Path(path).name.lower().startswith(".env") and Path(path).name != ".env.example":
            _blocked("runtime environment file forbidden")
        if Path(path).name == ".env.example" and item["content"] != ENV_EXAMPLE:
            _blocked("only the placeholder environment example is supported")
        seen.add(key)
        result.append((path, item["content"]))
    return result


def write_new_tree(destination, files):
    """Atomic new-tree output inside the active private_output_workspace only.

    Existing repositories, renames/deletions, hostile concurrent filesystem mutation
    and updates are unsupported. This is a local primitive, not runtime approval.
    """
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        _blocked("kill switch active")
    manifest = validate_manifest(files)  # Complete batch before any filesystem write.
    destination = Path(destination).absolute()
    parent = _LOCAL_OUTPUT_PARENT.get()
    if parent is None or destination.parent != parent:
        _blocked("destination is not in the trusted private workspace")
    relative_path(destination.name)
    if protected(destination.name):
        _blocked("protected output root")
    for ancestor in [destination, *destination.parents]:
        if _control_component(ancestor.name):
            _blocked("protected output ancestor")
        if ancestor.is_symlink() or (hasattr(ancestor, "is_junction") and ancestor.is_junction()):
            _blocked("symlink or junction destination")
    if destination.exists() or not destination.parent.is_dir():
        _blocked("destination exists or parent missing")
    try:
        stage = Path(tempfile.mkdtemp(prefix=".forgestra-stage-", dir=destination.parent))
    except OSError:
        raise Blocked("BLOCKED: private staging unavailable") from None
    try:
        for path, content in manifest:
            if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
                _blocked("kill switch active")
            output = stage / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8", newline="\n")
        if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0" or destination.exists():
            _blocked("publication cancelled or destination conflict")
        stage.rename(destination)
    except Exception:
        # Never surface raw OS/subprocess/provider messages or generated content.
        raise Blocked("BLOCKED: local output not published") from None
    finally:
        try:
            if stage.exists():
                shutil.rmtree(stage)
        except OSError:
            raise Blocked("BLOCKED: private staging cleanup needs reconciliation") from None
    return {"status": "LOCAL_OUTPUT_WRITTEN", "files": len(manifest), "integration": "NOT_RUN"}
