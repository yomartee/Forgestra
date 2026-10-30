"""Static local setup/result contracts. Validation never imports target code."""

import ast
from pathlib import Path
import re
import tomllib
import json
import platform
import sys

from forgestra import __version__
from forgestra_safety import Blocked, strict_json_loads

DEV_PACKAGES = {
    "black": "26.10.1",
    "flake8": "7.4.1",
    "mypy": "2.4.0",
    "ast-serialize": "0.13.1",
    "click": "8.5.0",
    "librt": "0.16.0",
    "mccabe": "0.7.0",
    "mypy-extensions": "1.1.0",
    "packaging": "26.3",
    "pathspec": "1.1.1",
    "platformdirs": "4.13.5",
    "pycodestyle": "2.15.0",
    "pyflakes": "4.0.3",
    "pytokens": "0.4.1",
    "typing-extensions": "4.16.0",
}


def supported_runtime() -> bool:
    return sys.version_info[:2] == (3, 14) and platform.python_implementation() == "CPython"


BLACK_CONFIG = "[tool.black]\nline-length = 100\n"
SETUPTOOLS_HASH = "5231689c6ac8156cd155cfb98c3fd6fb252c3e7e9bd3d78b64d3c55f132624c9"
REQUIRED_SOURCE: tuple[str, ...] = (
    "pyproject.toml",
    "requirements/core.lock",
    "requirements/build.lock",
    "requirements/dev.lock",
    "config/pr01-black.toml",
    ".github/workflows/safety-regressions.yml",
    "scripts/bootstrap.py",
    "scripts/forgestra_cli.py",
    "scripts/acquire_tools.py",
    "scripts/ci.py",
    "scripts/record_pr02_evidence.py",
    "scripts/record_pr03_evidence.py",
    "scripts/record_pr04_evidence.py",
    "scripts/record_pr05_evidence.py",
    "scripts/record_pr06_evidence.py",
    "scripts/pr06_web_validation.py",
    "scripts/pr07_creation_validation.py",
    "scripts/pr08_sync_validation.py",
    "scripts/record_pr08_evidence.py",
    "src/forgestra/maintenance.py",
    "scripts/pr09_maintenance_validation.py",
    "scripts/record_pr09_evidence.py",
    "src/forgestra/integrations.py",
    "scripts/pr10_mcp_validation.py",
    "scripts/record_pr10_evidence.py",
    "scripts/record_pr11_evidence.py",
    "scripts/public_contract.py",
    "scripts/public_checks.py",
    "scripts/private_evidence.py",
    "scripts/build_distribution.py",
    "tests/fixtures/public/containment.json",
    "config/public-source.json",
    "MANIFEST.in",
    "scripts/pr11_release_validation.py",
    "src/forgestra/release.py",
    "requirements/mcp.lock",
    "config/pr10-mcp-tools.json",
    "integrations/mcp/pyproject.toml",
    "integrations/mcp/src/forgestra_mcp/__init__.py",
    "integrations/mcp/src/forgestra_mcp/__main__.py",
    "integrations/mcp/src/forgestra_mcp/server.py",
    "scripts/record_pr07_evidence.py",
    "scripts/check_safety.py",
    "scripts/check_workflows.py",
    "scripts/run_safety_isolated.py",
    "scripts/forgestra_safety.py",
    "scripts/inspect_local.py",
    "scripts/pr01_validation.py",
    "src/forgestra/__init__.py",
    "src/forgestra/__main__.py",
    "src/forgestra/cli.py",
    "src/forgestra/configuration.py",
    "src/forgestra/workspaces.py",
    "src/forgestra/verification.py",
    "src/forgestra/providers.py",
    "src/forgestra/assessment.py",
    "src/forgestra/repair.py",
    "src/forgestra/adoption.py",
    "src/forgestra/web.py",
    "src/forgestra/creation.py",
    "src/forgestra/synchronization.py",
    "src/forgestra/sync_control.py",
    "src/forgestra/component_registry.py",
)

WEB_ASSETS = (
    "api.txt",
    "browser.txt",
    "catalog.json",
    "contract.txt",
    "custom.txt",
    "docker.txt",
    "dockerignore.txt",
    "eslint.txt",
    "fixture.txt",
    "hasura.txt",
    "home.txt",
    "layout.txt",
    "next.txt",
    "package-lock.json",
    "package.json",
    "provider.txt",
    "providers.txt",
    "resource.txt",
    "server.txt",
    "setup.txt",
    "style.txt",
    "tsconfig.json",
)
REQUIRED_SOURCE += tuple("src/forgestra/web_assets/" + name for name in WEB_ASSETS)


def bounded_file(path: Path, limit=2_000_000) -> bytes:
    for entry in [path, *path.parents]:
        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
            raise Blocked("BLOCKED: linked input unsupported")
    if not path.is_file():
        raise FileNotFoundError("required input missing")
    if path.stat().st_size > limit:
        raise Blocked("BLOCKED: oversized input")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise Blocked("BLOCKED: oversized input")
    return payload


def plain_file(path: Path, limit=2_000_000) -> str:
    return bounded_file(path, limit).decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")


def lock_entries(path: Path) -> dict[str, tuple[str, set[str]]]:
    """Parse the deliberately restricted wheel-lock grammar; never pip directives."""
    text = plain_file(path)
    text = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    entries = {}
    for line in text.replace("\\\n", " ").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(
            r"\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)((?:\s+--hash=sha256:[0-9a-f]{64})+)\s*",
            line,
        )
        if not match:
            raise Blocked("BLOCKED: invalid wheel lock")
        name = re.sub(r"[-_.]+", "-", match[1]).lower()
        if name in entries:
            raise Blocked("BLOCKED: duplicate locked distribution")
        entries[name] = (match[2], set(re.findall(r"sha256:([0-9a-f]{64})", match[3])))
    return entries


def validate_source(root: Path) -> None:
    contents = {name: plain_file(root / name) for name in REQUIRED_SOURCE}
    validate_optional(root)
    asset_root = root / "src/forgestra/web_assets"
    if {p.name for p in asset_root.iterdir()} != set(WEB_ASSETS):
        raise Blocked("BLOCKED: unreviewed web asset")
    hashes = strict_json_loads(contents["src/forgestra/web_assets/catalog.json"])
    if not isinstance(hashes, dict) or set(hashes) != set(WEB_ASSETS) - {"catalog.json"}:
        raise Blocked("BLOCKED: invalid web asset catalog")
    import hashlib

    if any(
        hashlib.sha256(bounded_file(asset_root / name)).hexdigest() != value
        for name, value in hashes.items()
    ):
        raise Blocked("BLOCKED: changed web asset")
    for name in REQUIRED_SOURCE:
        if name.endswith(".py"):
            ast.parse(contents[name], filename=name)
    expected_modules = {
        Path(name).name
        for name in REQUIRED_SOURCE
        if Path(name).parent.as_posix() == "src/forgestra"
    }
    if {p.name for p in (root / "src/forgestra").glob("*.py")} != expected_modules:
        raise Blocked("BLOCKED: unreviewed package module")
    if contents["config/pr01-black.toml"] != BLACK_CONFIG:
        raise Blocked("BLOCKED: unapproved formatter configuration")
    for name in ("setup.py", "setup.cfg"):
        if (root / name).exists() or (root / name).is_symlink():
            raise Blocked("BLOCKED: additional build hooks unsupported")
    # An exact declarative sdist allowlist is reviewed data, never a build hook.
    public = strict_json_loads(contents["config/public-source.json"])
    if (
        not isinstance(public, dict)
        or set(public) != {"profile", "paths"}
        or public["profile"] != "FORGESTRA_PUBLIC_PRODUCT_V1"
        or not isinstance(public["paths"], list)
        or any(not isinstance(n, str) for n in public["paths"])
        or public["paths"] != sorted(set(public["paths"]))
        or any(
            n.startswith(("docs/engineering/", "docs/audit/", ".tools/", ".git/"))
            or ".." in n.split("/")
            or "\\" in n
            or ":" in n
            or n.startswith("/")
            for n in public["paths"]
        )
        or contents["MANIFEST.in"] != "".join("include " + n + "\n" for n in public["paths"])
        or hashlib.sha256(bounded_file(root / "tests/fixtures/public/containment.json")).hexdigest()
        != "ad067bade757cc9fe00388aaba39a084e36aca4847fc91fea8f4e38955c04576"
    ):
        raise Blocked("BLOCKED: public fixture/distribution input contract")
    project = tomllib.loads(contents["pyproject.toml"])
    if set(project) != {"build-system", "project", "tool"} or project["build-system"] != {
        "requires": ["setuptools==84.1.0"],
        "build-backend": "setuptools.build_meta",
    }:
        raise Blocked("BLOCKED: unapproved build backend")
    metadata = project["project"]
    expected = {
        "name": "forgestra",
        "version": __version__,
        "requires-python": ">=3.14,<3.15",
        "dependencies": [],
        "scripts": {"forgestra": "forgestra.cli:main"},
        "optional-dependencies": {"dev": ["black==26.10.1", "flake8==7.4.1", "mypy==2.4.0"]},
    }
    if (
        not isinstance(metadata, dict)
        or set(metadata) != set(expected) | {"description"}
        or not isinstance(metadata.get("description"), str)
        or any(metadata.get(k) != v for k, v in expected.items())
    ):
        raise Blocked("BLOCKED: unapproved core packaging contract")
    expected_tools = {
        "black": {"line-length": 100},
        "setuptools": {
            "packages": ["forgestra"],
            "py-modules": ["forgestra_safety", "inspect_local"],
            "include-package-data": False,
            "package-dir": {"": "scripts", "forgestra": "src/forgestra"},
            "package-data": {"forgestra": ["web_assets/*.txt", "web_assets/*.json"]},
        },
    }
    if json.dumps(project["tool"], sort_keys=True) != json.dumps(expected_tools, sort_keys=True):
        raise Blocked("BLOCKED: unapproved package selection or plugins")
    if lock_entries(root / "requirements/core.lock"):
        raise Blocked("BLOCKED: core must remain stdlib-only")
    if lock_entries(root / "requirements/build.lock") != {
        "setuptools": ("84.1.0", {SETUPTOOLS_HASH})
    }:
        raise Blocked("BLOCKED: build lock does not match backend")
    dev = lock_entries(root / "requirements/dev.lock")
    if {name: entry[0] for name, entry in dev.items()} != DEV_PACKAGES:
        raise Blocked("BLOCKED: development locks do not match doctor")
    workflow = strict_json_loads(contents[".github/workflows/safety-regressions.yml"])
    # Read the reviewed gate's literal contract as data; never import source from --source.
    tree = ast.parse(contents["scripts/check_workflows.py"])
    expected_workflow = next(
        (
            ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "SAFETY_WORKFLOW" for t in node.targets)
        ),
        None,
    )
    if not isinstance(expected_workflow, dict) or json.dumps(
        workflow, sort_keys=True
    ) != json.dumps(expected_workflow, sort_keys=True):
        raise Blocked("BLOCKED: invalid required workflow")


def ready_offline(document) -> bool:
    return (
        isinstance(document, dict)
        and set(document)
        == {
            "status",
            "issues",
            "configuration",
            "connectivity",
            "optional_integrations",
            "privileged_automation",
            "version",
        }
        and document["status"] == "READY_OFFLINE"
        and document["issues"] == []
        and document["configuration"] == "VALID"
        and document["connectivity"] == "NOT_RUN"
        and document["optional_integrations"] == document["privileged_automation"] == "DISABLED"
        and document["version"] == __version__
    )


def validate_optional(root):
    """Validate separate optional packaging/locks before any build or installation."""
    from urllib.parse import urlsplit

    base = root / "integrations/mcp"
    project = tomllib.loads(plain_file(base / "pyproject.toml"))
    expected = {
        "build-system": {
            "requires": ["setuptools==84.1.0"],
            "build-backend": "setuptools.build_meta",
        },
        "project": {
            "name": "forgestra-mcp",
            "version": __version__,
            "description": (
                "Explicit stdio-only read-only Forgestra adapter; " "privileged operations disabled"
            ),
            "requires-python": ">=3.14,<3.15",
            "dependencies": ["forgestra==" + __version__, "mcp==2.3.0"],
            "scripts": {"forgestra-mcp": "forgestra_mcp.server:main"},
        },
        "tool": {
            "setuptools": {
                "packages": ["forgestra_mcp"],
                "package-dir": {"": "src"},
                "include-package-data": False,
            }
        },
    }
    if project != expected:
        raise Blocked("BLOCKED: unreviewed optional package contract")
    names = {
        "pyproject.toml",
        "src/forgestra_mcp/__init__.py",
        "src/forgestra_mcp/__main__.py",
        "src/forgestra_mcp/server.py",
    }
    if {p.relative_to(base).as_posix() for p in base.rglob("*") if p.is_file()} != names:
        raise Blocked("BLOCKED: additional optional build hooks or files")
    for name in names:
        plain_file(base / name)
    config = strict_json_loads(plain_file(root / "config/pr10-mcp-tools.json", 100000))
    if (
        set(config) != {"schema_version", "sdk", "python", "platforms", "metadata"}
        or type(config["schema_version"]) is not int
        or config["schema_version"] != 1
        or config["sdk"] != "mcp==2.3.0"
        or config["python"] != "3.14"
        or set(config["platforms"]) != {"windows", "linux"}
    ):
        raise Blocked("BLOCKED: unsupported optional SDK tooling")
    packages: dict[str, str] = {}
    for platform_name, entries in config["platforms"].items():
        if not isinstance(entries, list) or not 1 <= len(entries) <= 64:
            raise Blocked("BLOCKED: optional dependency count")
        seen = set()
        for e in entries:
            if (
                not isinstance(e, dict)
                or set(e) != {"name", "version", "filename", "url", "sha256"}
                or not all(isinstance(v, str) for v in e.values())
                or not re.fullmatch(r"[A-Za-z0-9_-]+", e["name"])
                or not re.fullmatch(r"[0-9][A-Za-z0-9.+-]*", e["version"])
                or not re.fullmatch(r"[A-Za-z0-9_.+-]+[.]whl", e["filename"])
                or not re.fullmatch(r"[0-9a-f]{64}", e["sha256"])
            ):
                raise Blocked("BLOCKED: invalid optional wheel specification")
            url = urlsplit(e["url"])
            if (
                url.scheme != "https"
                or url.netloc != "files.pythonhosted.org"
                or url.query
                or url.fragment
                or not url.path.startswith("/packages/")
                or url.path.rsplit("/", 1)[1] != e["filename"]
                or e["name"] in seen
            ):
                raise Blocked("BLOCKED: unreviewed optional wheel origin")
            seen.add(e["name"])
            if e["name"] in packages and packages[e["name"]] != e["version"]:
                raise Blocked("BLOCKED: cross-platform optional version mismatch")
            packages[e["name"]] = e["version"]
        selected = {e["name"].lower(): e["version"] for e in entries}
        if selected.get("mcp") != "2.3.0" or selected.get("mcp-types") != "2.3.0":
            raise Blocked("BLOCKED: missing pinned official SDK")
        if ("pywin32" in selected) != (platform_name == "windows"):
            raise Blocked("BLOCKED: optional platform marker mismatch")
    lines = []
    for e in config["platforms"]["windows"]:
        hashes = sorted(
            {
                v["sha256"]
                for entries in config["platforms"].values()
                for v in entries
                if v["name"] == e["name"]
            }
        )
        marker = '; sys_platform == "win32"' if e["name"].lower() == "pywin32" else ""
        lines.append(
            e["name"]
            + "=="
            + e["version"]
            + marker
            + " "
            + " ".join("--hash=sha256:" + h for h in hashes)
        )
    expected_lock = (
        "# Optional MCP SDK only; core stays stdlib. CPython 3.14 Windows/Linux x86_64.\n"
        + "\n".join(lines)
        + "\n"
    )
    if plain_file(root / "requirements/mcp.lock") != expected_lock:
        raise Blocked("BLOCKED: optional lock differs from wheel provenance")
    return config
