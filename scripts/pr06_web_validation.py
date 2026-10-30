"""Reviewed local web tool acquisition and authored-project acceptance only.

No arbitrary project path/command, customer build or provider transport is accepted.
Network package acquisition requires the explicit --acquire --download invocation.
"""

from contextlib import AbstractContextManager, nullcontext
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]

CACHE = ROOT / ".tools/pr06-npm"
TOOLCHAIN = ROOT / ".tools/pr06-toolchain"
BROWSERS = ROOT / ".tools/pr06-browsers"
SCRIPTS = {
    "dev": "next dev --hostname 127.0.0.1",
    "build": "next build --webpack",
    "start": "next start --hostname 127.0.0.1",
    "typecheck": "next typegen && tsc --noEmit",
    "lint": "eslint src tests",
    "test": "node --test --test-reporter=tap tests/contract.test.mjs",
    "test:browser": "node tests/browser.mjs",
}
BROWSER_CHECKS = {
    "root-to-list",
    "create-through-ui",
    "dynamic-edit-through-ui",
    "http-only-session",
    "cross-user-edit-denied",
    "missing-session-denied",
    "delete-through-ui",
    "backend-failure-state",
    "no-external-browser-requests",
}
COMMANDS = ("ci", "typecheck", "lint", "test", "build", "browser")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def dependency_contract(package, lock):
    from forgestra_safety import Blocked

    if (
        not isinstance(package, dict)
        or package.get("private") is not True
        or package.get("scripts") != SCRIPTS
        or package.get("type") != "module"
        or package.get("engines") != {"node": "24.14.0", "npm": "11.9.0"}
        or package.get("packageManager") != "npm@11.9.0"
        or not isinstance(lock, dict)
        or type(lock.get("lockfileVersion")) is not int
        or lock["lockfileVersion"] != 3
        or not isinstance(lock.get("packages"), dict)
    ):
        raise Blocked("BLOCKED: unreviewed generated dependency contract")
    packages = lock["packages"]
    if not isinstance(packages.get(""), dict) or not 2 <= len(packages) <= 1000:
        raise Blocked("BLOCKED: incomplete dependency lock")
    for section in ("dependencies", "devDependencies"):
        declared = package.get(section)
        if not isinstance(declared, dict) or not declared or packages[""].get(section) != declared:
            raise Blocked("BLOCKED: dependency lock disagrees with package")
        if any(
            not isinstance(v, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", v)
            for v in declared.values()
        ):
            raise Blocked("BLOCKED: exact direct dependency versions required")
    for name, entry in packages.items():
        if not name:
            continue
        if not isinstance(entry, dict) or not isinstance(entry.get("version"), str):
            raise Blocked("BLOCKED: malformed dependency lock entry")
        resolved = entry.get("resolved")
        if not isinstance(resolved, str):
            raise Blocked("BLOCKED: malformed dependency resolution")
        uri = urlsplit(resolved)
        if (
            uri.scheme != "https"
            or uri.netloc != "registry.npmjs.org"
            or uri.query
            or uri.fragment
            or not uri.path.endswith(".tgz")
            or entry.get("link") is True
            or not isinstance(entry.get("integrity"), str)
            or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+={0,2}", entry["integrity"])
        ):
            raise Blocked("BLOCKED: untrusted or unhashed dependency resolution")
    return {
        "direct": len(package["dependencies"]) + len(package["devDependencies"]),
        "locked": len(packages) - 1,
    }


def tool_environment(profile):
    from bootstrap import environment
    from acquire_tools import unlinked

    env = environment()
    profile = Path(profile)
    profile.mkdir(parents=True, exist_ok=True)
    for name in ("user.npmrc", "global.npmrc"):
        unlinked(profile / name)
        (profile / name).write_text("", encoding="utf-8")
    env.update(
        HOME=str(profile),
        USERPROFILE=str(profile),
        APPDATA=str(profile),
        LOCALAPPDATA=str(profile),
        NEXT_TELEMETRY_DISABLED="1",
        NPM_CONFIG_IGNORE_SCRIPTS="true",
        NPM_CONFIG_AUDIT="false",
        NPM_CONFIG_FUND="false",
        NPM_CONFIG_USERCONFIG=str(profile / "user.npmrc"),
        NPM_CONFIG_GLOBALCONFIG=str(profile / "global.npmrc"),
        NPM_CONFIG_CACHE=str(CACHE / "cache"),
        PLAYWRIGHT_BROWSERS_PATH=str(BROWSERS),
    )
    return env


def npm_args(profile, offline=True):
    from forgestra_safety import Blocked

    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    if not npm:
        raise Blocked("BLOCKED: npm unavailable")
    return [
        npm,
        "--userconfig",
        str(profile / "user.npmrc"),
        "--globalconfig",
        str(profile / "global.npmrc"),
        "--cache",
        str(CACHE / "cache"),
        "--registry",
        "https://registry.npmjs.org",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        *(["--offline"] if offline else []),
    ]


def browser_path():
    from acquire_tools import unlinked
    from forgestra_safety import Blocked

    unlinked(BROWSERS)
    candidates = [
        p
        for p in BROWSERS.rglob("*")
        if p.name in {"chrome-headless-shell.exe", "chrome-headless-shell"} and p.is_file()
    ]
    if (
        len(candidates) != 1
        or candidates[0].relative_to(BROWSERS).parts[0] != "chromium_headless_shell-1248"
    ):
        raise Blocked("BLOCKED: pinned headless browser unavailable")
    unlinked(candidates[0])
    return candidates[0]


def acquire(download=False):
    from acquire_tools import unlinked
    from forgestra import web
    from forgestra_safety import Blocked, strict_json_loads

    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise Blocked("BLOCKED: kill switch active")
    for path in (CACHE, TOOLCHAIN, BROWSERS):
        unlinked(path)
        if not path.resolve().is_relative_to((ROOT / ".tools").resolve()):
            raise Blocked("BLOCKED: acquisition path outside workspace tools")
    web.load_assets()
    package = strict_json_loads((web.ROOT / "package.json").read_text(encoding="utf-8"))
    lock = strict_json_loads((web.ROOT / "package-lock.json").read_text(encoding="utf-8"))
    count = dependency_contract(package, lock)
    TOOLCHAIN.mkdir(parents=True, exist_ok=True)
    if {p.name for p in TOOLCHAIN.iterdir()} - {
        "package.json",
        "package-lock.json",
        "node_modules",
    }:
        raise Blocked("BLOCKED: unexpected acquisition files")
    unlinked(TOOLCHAIN / "node_modules")
    for name in ("package.json", "package-lock.json"):
        unlinked(TOOLCHAIN / name)
        shutil.copyfile(web.ROOT / name, TOOLCHAIN / name)
    env = tool_environment(CACHE)
    command = subprocess.run(
        npm_args(CACHE, not download) + ["ci", "--strict-peer-deps"],
        cwd=TOOLCHAIN,
        env=env,
        capture_output=True,
        timeout=500,
        check=False,
    )
    if command.returncode:
        raise Blocked("BLOCKED: reviewed dependency acquisition failed")
    if download:
        command = subprocess.run(
            [
                "node",
                str(TOOLCHAIN / "node_modules/playwright-core/cli.js"),
                "install",
                "chromium",
                "--only-shell",
            ],
            cwd=TOOLCHAIN,
            env=env,
            capture_output=True,
            timeout=500,
            check=False,
        )
        if command.returncode:
            raise Blocked("BLOCKED: pinned browser acquisition failed")
    browser = browser_path()
    record = {
        "status": "ACQUIRED_LOCAL",
        "registry": "https://registry.npmjs.org",
        "lifecycle_scripts": "DISABLED",
        "package_lock_sha256": sha((web.ROOT / "package-lock.json").read_bytes()),
        "browser_revision": "1248",
        "browser_sha256": sha(browser.read_bytes()),
        **count,
    }
    (CACHE / "provenance.json").write_text(web.encode(record), encoding="utf-8")
    return record


def test_counts(stdout):
    from forgestra_safety import Blocked

    expected = {
        "tests": 21,
        "suites": 0,
        "pass": 21,
        "fail": 0,
        "cancelled": 0,
        "skipped": 0,
        "todo": 0,
    }
    lines = stdout.splitlines()
    for name, value in expected.items():
        matches = [line for line in lines if line.startswith("# " + name + " ")]
        if matches != [f"# {name} {value}"]:
            raise Blocked("BLOCKED: inconsistent generated test counts")
    ids = [int(match.group(1)) for line in lines if (match := re.match(r"ok ([0-9]+) - ", line))]
    if (
        ids != list(range(1, 22))
        or lines.count("1..21") != 1
        or any(line.startswith("not ok ") for line in lines)
    ):
        raise Blocked("BLOCKED: incomplete generated test run")
    return expected


def valid_web(record):
    from forgestra import web
    from forgestra_safety import Blocked

    try:
        if not isinstance(record, dict):
            return False
        commands = record["commands"]
        if not isinstance(record.get("browser"), dict) or not isinstance(
            record.get("canary_scan"), dict
        ):
            return False
        emitted = web.render(web.FIXTURE_SCHEMA)
        if (
            record["schema_sha256"] != sha(web.encode(web.FIXTURE_SCHEMA).encode())
            or record["template_catalog_sha256"] != sha((web.ROOT / "catalog.json").read_bytes())
            or set(record["generated_files"]) != {f["path"] for f in emitted}
            or any(
                record["generated_files"][f["path"]] != sha(f["content"].encode())
                for f in emitted
                if f["path"] != "next-env.d.ts"
            )
        ):
            return False
        installed = record["installed_cli"]["checks"]
        if (
            not isinstance(installed, list)
            or len(installed) != 2
            or type(installed[0]["exit_code"]) is not int
            or installed[0]["exit_code"] != 0
            or installed[0]["result"] != web.inspect(web.FIXTURE_SCHEMA)
            or type(installed[1]["exit_code"]) is not int
            or installed[1]["exit_code"] != 1
            or installed[1]["result"]["status"] != "BLOCKED"
            or any(c["status"] != "PASSED" for c in installed)
        ):
            return False
        return (
            record["status"] == "PASSED_LOCAL"
            and record["mode"] == "AUTHORED_WEB_FIXTURE"
            and isinstance(commands, list)
            and [c["name"] for c in commands] == list(COMMANDS)
            and all(
                isinstance(c, dict)
                and isinstance(c.get("stdout"), str)
                and type(c["exit_code"]) is int
                and c["exit_code"] == 0
                and c["status"] == "PASSED"
                and sha(c["stdout"].encode()) == c["stdout_sha256"]
                for c in commands
            )
            and record["test_counts"]
            == test_counts(next(c["stdout"] for c in commands if c["name"] == "test"))
            and record["browser"]["status"] == "PASSED_LOCAL"
            and len(record["browser"]["checks"]) == len(BROWSER_CHECKS)
            and set(record["browser"]["checks"]) == BROWSER_CHECKS
            and record["browser"]["mode"] == "AUTHORED_GRAPHQL_PROTOCOL_FIXTURE"
            and record["browser"]["real_hasura"] == record["browser"]["container"] == "NOT_RUN"
            and record["browser"]["external_requests"] == []
            and type(record["browser"]["admin_headers"]) is int
            and record["browser"]["admin_headers"] == 0
            and record["source_unchanged_except_compiler_declarations"] is True
            and record["canary_scan"]["status"] == "PASSED"
            and type(record["canary_scan"]["matches"]) is int
            and record["canary_scan"]["matches"] == 0
            and type(record["canary_scan"]["files"]) is int
            and record["canary_scan"]["files"] > 0
            and record["canary_scan"]["image_layers"] == "NOT_RUN"
            and record["container"] == "NOT_RUN"
            and record["real_hasura"] == "NOT_RUN"
            and record["live_provider"] == "NOT_RUN"
            and record["publication"] == "BLOCKED"
            and record["privileged_automation"] == "DISABLED"
            and record["installed_cli"]["status"] == "PASSED_LOCAL"
        )
    except (KeyError, TypeError, ValueError, StopIteration, Blocked):
        return False


def web_acceptance(product=None):
    from bootstrap import environment
    from acquire_tools import unlinked
    from forgestra import web
    from forgestra_safety import Blocked, private_output_workspace, strict_json_loads, redact

    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise Blocked("BLOCKED: kill switch active")
    browser = browser_path()
    provenance = strict_json_loads((CACHE / "provenance.json").read_text(encoding="utf-8"))
    if provenance.get("package_lock_sha256") != sha(
        (web.ROOT / "package-lock.json").read_bytes()
    ) or provenance.get("browser_sha256") != sha(browser.read_bytes()):
        raise Blocked("BLOCKED: web tool provenance changed")
    package = strict_json_loads((web.ROOT / "package.json").read_text(encoding="utf-8"))
    lock = strict_json_loads((web.ROOT / "package-lock.json").read_text(encoding="utf-8"))
    dependency_contract(package, lock)
    result: dict[str, Any] = {
        "status": "RUNNING",
        "mode": "AUTHORED_WEB_FIXTURE",
        "commands": [],
        "container": "NOT_RUN",
        "real_hasura": "NOT_RUN",
        "live_provider": "NOT_RUN",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "provenance": provenance,
    }
    result.update(
        schema_sha256=sha(web.encode(web.FIXTURE_SCHEMA).encode()),
        template_catalog_sha256=sha((web.ROOT / "catalog.json").read_bytes()),
    )
    parent_scope: AbstractContextManager[Path]
    if product is not None:
        from forgestra import creation
        from forgestra_safety import _LOCAL_OUTPUT_PARENT

        ledger, approval = product
        creation.authorized(creation.FIXTURE_SPEC, approval)
        ledger.claim(creation.FIXTURE_SPEC, approval)
        issued_parent = _LOCAL_OUTPUT_PARENT.get()
        if issued_parent is None:
            raise Blocked("BLOCKED: missing creation fixture workspace")
        parent_scope = nullcontext(issued_parent)
    else:
        parent_scope = private_output_workspace()
    receipt = None
    with parent_scope as parent:
        project = parent / "web-candidate"
        emitted = web.render(web.FIXTURE_SCHEMA)
        if product is None:
            web.write_project(project, web.FIXTURE_SCHEMA)
        else:
            from forgestra_safety import write_new_tree

            write_new_tree(project, creation.files(creation.FIXTURE_SPEC))
        env = tool_environment(parent / "profile")
        env["FORGESTRA_BROWSER"] = str(browser)
        canaries = ["pr06-canary-" + secrets.token_hex(20) for _ in range(3)]
        env.update(
            HASURA_ADMIN_SECRET=canaries[0],
            FACTORY_ADMIN_TOKEN=canaries[1],
            PROVIDER_API_KEY=canaries[2],
        )
        env.pop("HASURA_GRAPHQL_ENDPOINT", None)
        base = npm_args(parent / "profile")
        for name in COMMANDS:
            argv = base + (
                ["ci", "--strict-peer-deps"]
                if name == "ci"
                else ["run", "test:browser" if name == "browser" else name]
            )
            child = subprocess.run(
                argv,
                cwd=project,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
            )
            stdout = redact(child.stdout, canaries)
            result["commands"].append(
                {
                    "name": name,
                    "argv": argv,
                    "exit_code": child.returncode,
                    "status": "PASSED" if child.returncode == 0 else "FAILED",
                    "stdout": stdout,
                    "stdout_sha256": sha(stdout.encode()),
                    "stderr": redact(child.stderr, canaries),
                }
            )
            if child.returncode:
                result["status"] = "FAILED"
                if product is not None:
                    ledger.finish(creation.FIXTURE_SPEC, approval, "FAILED_VALIDATION")
                    return result, None
                return result
            if name == "ci" and product is not None:
                from pr07_creation_validation import verify_components

                verify_components(project)
            if name == "test":
                result["test_counts"] = test_counts(child.stdout)
        result["browser"] = strict_json_loads(
            (project / "browser-result.json").read_text(encoding="utf-8")
        )
        result["screenshot_sha256"] = sha((project / "browser.png").read_bytes())
        output = ROOT / ".tools/pr06-web-results"
        unlinked(output)
        output.mkdir(parents=True, exist_ok=True)
        unlinked(output / "browser.png")
        shutil.copyfile(project / "browser.png", output / "browser.png")
        result["source_unchanged_except_compiler_declarations"] = all(
            (project / f["path"]).read_bytes() == f["content"].encode()
            for f in emitted
            if f["path"] != "next-env.d.ts"
        )
        result["generated_files"] = {
            f["path"]: sha((project / f["path"]).read_bytes()) for f in emitted
        }
        count, matches = 0, 0
        for file in project.rglob("*"):
            if file.is_symlink() or file.is_junction() or not file.is_file():
                continue
            count += 1
            data = file.read_bytes()
            if any(token.encode() in data for token in canaries):
                matches += 1
        result["canary_scan"] = {
            "status": "PASSED" if matches == 0 else "FAILED",
            "matches": matches,
            "files": count,
            "image_layers": "NOT_RUN",
            "canary_hashes": [sha(c.encode()) for c in canaries],
        }
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        domain = parent / "schema.json"
        domain.write_text(web.encode(web.FIXTURE_SCHEMA), encoding="utf-8")
        checks = []
        for content, expected in ((web.FIXTURE_SCHEMA, "PLANNED_LOCAL"), ({}, "BLOCKED")):
            domain.write_text(web.encode(content), encoding="utf-8")
            child = subprocess.run(
                [str(python), "-I", "-m", "forgestra", "web", "--schema", str(domain)],
                cwd=parent,
                env=environment(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            document = strict_json_loads(child.stdout)
            checks.append(
                {
                    "status": (
                        "PASSED"
                        if child.returncode == (0 if expected == "PLANNED_LOCAL" else 1)
                        and document["status"] == expected
                        else "FAILED"
                    ),
                    "exit_code": child.returncode,
                    "result": document,
                }
            )
        result["installed_cli"] = {
            "status": "PASSED_LOCAL" if all(c["status"] == "PASSED" for c in checks) else "FAILED",
            "checks": checks,
        }
        result["status"] = "PASSED_LOCAL"
        if not valid_web(result):
            result["status"] = "FAILED"
        if product is not None:
            from pr07_creation_validation import finalize

            receipt = finalize(
                project, creation.files(creation.FIXTURE_SPEC), result, ledger, approval
            )
    return (result, receipt) if product is not None else result


def main():
    from forgestra_safety import Blocked

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--download", action="store_true")
    args = parser.parse_args()
    try:
        if args.download and not args.acquire:
            raise Blocked("BLOCKED: download requires explicit acquisition mode")
        result = acquire(args.download) if args.acquire else web_acceptance()
        print(json.dumps(result))
        return 0 if result["status"] in {"ACQUIRED_LOCAL", "PASSED_LOCAL"} else 1
    except (OSError, ValueError, TypeError, Blocked, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "privileged_automation": "DISABLED",
                    "live_provider": "NOT_RUN",
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
