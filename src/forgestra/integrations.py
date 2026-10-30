"""Honest integration capabilities and bounded read-only optional adapters."""

import os
from pathlib import Path
import subprocess
import sys

from forgestra_safety import Blocked, CAPABILITIES, strict_json_loads

TOOLS = {
    "factory_status": "Local capability catalogue; no providers or remote status.",
    "inspect_workspace": "Bounded metadata-only inspection of the startup-selected root.",
    "sales_demo": "Explicit fictional sales demo; no discovery, consent claim or outreach.",
}


def error(code):
    return {
        "status": "ERROR",
        "error": {"code": code},
        "execution": "DISABLED",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }


def catalogue():
    return {
        "status": "AVAILABLE_LOCAL",
        "mode": "READ_ONLY",
        "privileged_capabilities": {n: "DISABLED" for n in sorted(CAPABILITIES)},
        "integrations": {
            "mcp": {"status": "OPTIONAL_READ_ONLY", "activation": "EXPLICIT_STDIO_ONLY"},
            "workik": {"status": "PLANNED", "live": "DISABLED"},
            "lovable": {"status": "PLANNED", "live": "DISABLED"},
            "mobile": {"status": "PLANNED", "live": "DISABLED"},
            "sales": {"status": "DEMO_ONLY", "live": "DISABLED"},
        },
        "live_provider": "NOT_RUN",
        "publication": "BLOCKED",
        "side_effects": [],
    }


def sales_demo():
    return {
        "status": "DEMO",
        "is_mock": True,
        "source": "FICTIONAL_LITERAL",
        "prospects": [{"name": "Example Fictional Company", "email": "demo@example.invalid"}],
        "outreach": "DISABLED",
        "provider_result_id": None,
        "side_effects": [],
    }


def root_inventory(root):
    root = Path(root).absolute()
    for p in (root, *root.parents):
        if p.is_symlink() or p.is_junction():
            raise Blocked("BLOCKED: linked optional adapter root")
    if not root.is_dir():
        raise Blocked("BLOCKED: optional adapter root unavailable")
    stack, seen, files = [(root, 0)], 0, 0
    while stack:
        directory, depth = stack.pop()
        if depth > 16:
            raise Blocked("BLOCKED: optional adapter depth limit")
        for path in directory.iterdir():
            seen += 1
            if seen > 4096:
                raise Blocked("BLOCKED: optional adapter entry limit")
            if path.name in {".git", ".tools", ".venv", "node_modules", "__pycache__"}:
                continue
            if path.is_symlink() or path.is_junction():
                raise Blocked("BLOCKED: linked optional adapter content")
            if path.is_dir():
                stack.append((path, depth + 1))
            elif path.is_file():
                files += 1
            else:
                raise Blocked("BLOCKED: special optional adapter content")
    return root.resolve(), files


def child_environment():
    allowed = {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL"}
    return {k: v for k, v in os.environ.items() if k.upper() in allowed}


def inspect_workspace(root):
    root, count = root_inventory(root)
    command = [sys.executable, "-I", "-m", "forgestra", "inspect", str(root)]
    try:
        child = subprocess.run(
            command,
            cwd=root,
            env=child_environment(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return error("TIMEOUT")
    except OSError:
        return error("PROCESS_UNAVAILABLE")
    if type(child.returncode) is not int or child.returncode != 0:
        return error("PROCESS_FAILED")
    try:
        result = strict_json_loads(child.stdout)
        expected = {
            "status": "INSPECTED_LOCAL",
            "files": count,
            "risk_tier": 1,
            "auto_merge": False,
            "provider": "NOT_RUN",
            "remote": "NOT_RUN",
        }
        if (
            result != expected
            or type(result["files"]) is not int
            or type(result["risk_tier"]) is not int
            or result["auto_merge"] is not False
            or child.stderr
            or root_inventory(root) != (root, count)
        ):
            return error("INVALID_RESULT")
        return result
    except (ValueError, TypeError, OSError, Blocked):
        return error("INVALID_RESULT")


def dispatch(name, arguments, root):
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        return error("KILL_SWITCH")
    if not isinstance(name, str) or not isinstance(arguments, dict) or arguments:
        return error("INVALID_ARGUMENTS")
    if name not in TOOLS:
        return error(
            "WORKFLOW_UNAVAILABLE" if name == "derive_product" else "UNSUPPORTED_OPERATION"
        )
    try:
        if name == "factory_status":
            return catalogue()
        if name == "sales_demo":
            return sales_demo()
        return inspect_workspace(root)
    except (OSError, ValueError, TypeError, Blocked):
        return error("INVALID_ROOT")


def client_config(python, root):
    python = Path(python)
    root, _ = root_inventory(root)
    if (
        not python.is_absolute()
        or not python.is_file()
        or any(p.is_symlink() or p.is_junction() for p in (python, *python.parents))
        or python.name not in {"python", "python.exe"}
    ):
        raise Blocked("BLOCKED: explicit optional environment Python required")
    return {
        "mcpServers": {
            "forgestra-local-readonly": {
                "command": str(python),
                "args": ["-I", "-m", "forgestra_mcp", "--root", str(root)],
                "env": {},
            }
        }
    }
