"""Fixed PR 07 local fixture verification; never a customer executor/publisher."""

import hashlib
import hmac
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]


def git_tree(contents, commit):
    lines = []
    for name, text in sorted(contents.items()):
        data = text.encode()
        digest = hashlib.sha1 if len(commit) == 40 else hashlib.sha256
        blob = digest(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        lines.append("100644 blob " + blob + "\t" + name)
    return lines


def valid_product(product, web_result):
    from forgestra import creation

    try:
        if not isinstance(product, dict) or set(product) != {
            "commit",
            "files",
            "git_commands",
            "remote",
            "compiler_declarations",
        }:
            return False
        sha, files, commands = product["commit"], product["files"], product["git_commands"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
            return False
        emitted = creation.files(creation.FIXTURE_SPEC)
        contents = {f["path"]: f["content"] for f in emitted}
        declarations = product["compiler_declarations"]
        if not isinstance(declarations, str) or len(declarations) > 2000:
            return False
        contents["next-env.d.ts"] = declarations
        if (
            not isinstance(files, dict)
            or files != {n: creation.digest(s.encode()) for n, s in contents.items()}
            or product["remote"] != "NOT_CONFIGURED"
            or any(files.get(n) != h for n, h in web_result["generated_files"].items())
        ):
            return False
        expected = [
            ["init", "--template=", "--initial-branch=fixture-product"],
            ["add", "--", *sorted(files)],
            ["commit", "--no-verify", "-m", "Verified authored PR 07 product fixture"],
            ["rev-parse", "HEAD"],
            ["ls-tree", "-r", "--full-tree", "HEAD"],
        ]
        return (
            isinstance(commands, list)
            and len(commands) == len(expected)
            and all(
                isinstance(c, dict)
                and set(c) == {"argv", "exit_code", "stdout"}
                and c["argv"] == argv
                and type(c["exit_code"]) is int
                and c["exit_code"] == 0
                and isinstance(c["stdout"], str)
                for c, argv in zip(commands, expected)
            )
            and commands[3]["stdout"].strip() == sha
            and commands[4]["stdout"].splitlines() == git_tree(contents, sha)
        )
    except (KeyError, TypeError, ValueError, creation.safety.Blocked):
        return False


def verify_components(project):
    from forgestra.creation import canonical, digest, registry
    from forgestra.verification import bounded_file
    from forgestra_safety import Blocked, strict_json_loads

    lock = strict_json_loads(bounded_file(project / "package-lock.json"))
    result = {}
    for name, expected in registry().items():
        root = project / "node_modules" / name
        pending, files, total, entries = [root], {}, 0, 0
        while pending:
            directory = pending.pop()
            if directory.is_symlink() or directory.is_junction():
                raise Blocked("BLOCKED: linked component source")
            for path in directory.iterdir():
                entries += 1
                if entries > 3000 or path.is_symlink() or path.is_junction():
                    raise Blocked("BLOCKED: linked or oversized component source")
                if path.is_dir():
                    pending.append(path)
                elif path.is_file():
                    data = bounded_file(path, 32_000_000)
                    total += len(data)
                    if total > 150_000_000:
                        raise Blocked("BLOCKED: oversized component source")
                    files[path.relative_to(root).as_posix()] = digest(data)
                else:
                    raise Blocked("BLOCKED: unsupported component source")
        # Reject changed bytes before parsing metadata from the candidate package.
        if (
            len(files) != expected["source_files"]
            or digest(canonical(files).encode()) != expected["source_tree_sha256"]
        ):
            raise Blocked("BLOCKED: component source tree mismatch")
        package = strict_json_loads(bounded_file(root / "package.json"))
        entry = lock["packages"]["node_modules/" + name]
        if (
            len(files) != expected["source_files"]
            or digest(canonical(files).encode()) != expected["source_tree_sha256"]
            or files["package.json"] != expected["package_sha256"]
            or files["LICENSE"] != expected["license_sha256"]
            or package["version"] != expected["version"]
            or package["license"] != expected["license"]
            or package["repository"] != expected["upstream"]
            or entry["version"] != expected["version"]
            or entry["resolved"] != expected["resolved"]
            or entry["integrity"] != expected["integrity"]
        ):
            raise Blocked("BLOCKED: component source/version/license/provenance mismatch")
        result[name] = {**expected, "files": files, "status": "SOURCE_VERIFIED_LOCAL"}
    return result


def commit_candidate(project, emitted, tested_hashes):
    """Commit only exact tested source paths in the owned, remote-free fixture."""
    from forgestra import creation
    from forgestra.repair import environment
    from forgestra.verification import bounded_file
    from forgestra_safety import Blocked, _LOCAL_OUTPUT_PARENT

    creation.checkpoint()
    parent = _LOCAL_OUTPUT_PARENT.get()
    if (
        parent is None
        or project != parent / "web-candidate"
        or emitted != creation.files(creation.FIXTURE_SPEC)
        or (project / ".git").exists()
        or (project / ".git").is_symlink()
        or (project / ".git").is_junction()
    ):
        raise Blocked("BLOCKED: fresh private product required")
    executable = "C:/Program Files/Git/cmd/git.exe" if os.name == "nt" else shutil.which("git")
    if not executable:
        raise Blocked("BLOCKED: Git unavailable")
    hashes = {f["path"]: creation.digest(bounded_file(project / f["path"])) for f in emitted}
    if any(hashes.get(n) != h for n, h in tested_hashes.items()):
        raise Blocked("BLOCKED: committed files disagree with tested web snapshot")
    # next-env is the single compiler-owned declaration file from the web contract.
    if any(
        hashes[f["path"]] != creation.digest(f["content"].encode())
        for f in emitted
        if f["path"] != "next-env.d.ts"
    ):
        raise Blocked("BLOCKED: product changed after validation")
    env = environment(parent / "git-profile")
    prefix = [
        executable,
        "--no-optional-locks",
        "-c",
        "core.hooksPath=" + str(parent / "no-hooks"),
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.autocrlf=false",
        "-c",
        "commit.gpgSign=false",
        "-c",
        "core.attributesFile=" + os.devnull,
    ]
    commands = [
        ["init", "--template=", "--initial-branch=fixture-product"],
        ["add", "--", *sorted(hashes)],
        ["commit", "--no-verify", "-m", "Verified authored PR 07 product fixture"],
        ["rev-parse", "HEAD"],
        ["ls-tree", "-r", "--full-tree", "HEAD"],
    ]
    results: list[dict[str, Any]] = []
    for args in commands:
        creation.checkpoint()
        child = subprocess.run(
            prefix + args,
            cwd=project,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if child.returncode:
            raise Blocked("BLOCKED: local product commit failed")
        results.append({"argv": args, "exit_code": 0, "stdout": child.stdout})
    sha = results[3]["stdout"].strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", sha):
        raise Blocked("BLOCKED: invalid local product commit")
    declarations = bounded_file(project / "next-env.d.ts").decode("utf-8")
    contents = {f["path"]: f["content"] for f in emitted}
    contents["next-env.d.ts"] = declarations
    expected_tree = git_tree(contents, sha)
    if results[4]["stdout"].splitlines() != expected_tree:
        raise Blocked("BLOCKED: unexpected committed product files")
    # Git add/commit cannot change the exact source snapshot being attested.
    if any(creation.digest(bounded_file(project / n)) != h for n, h in hashes.items()):
        raise Blocked("BLOCKED: tested source changed during commit")
    return {
        "commit": sha,
        "files": hashes,
        "git_commands": results,
        "remote": "NOT_CONFIGURED",
        "compiler_declarations": declarations,
    }


def finalize(project, emitted, web_result, ledger, approval):
    from forgestra import creation
    from forgestra_safety import Blocked
    from pr06_web_validation import valid_web

    creation.authorized(creation.FIXTURE_SPEC, approval)
    ledger.require_executing(creation.FIXTURE_SPEC, approval)
    if not valid_web(web_result):
        ledger.finish(creation.FIXTURE_SPEC, approval, "FAILED_VALIDATION")
        raise Blocked("BLOCKED: generated product did not pass validation")
    components = verify_components(project)
    web_hash = creation.digest(creation.canonical(web_result).encode())
    for component in components.values():
        component.update(
            acceptance_status="PASSED_LOCAL",
            acceptance_evidence_sha256=web_hash,
            acceptance_scope="GENERATED_APP_INTEGRATION_NOT_UPSTREAM_SUITE",
        )
    committed = commit_candidate(project, emitted, web_result["generated_files"])
    body = {
        "status": "READY_FOR_LOCAL_REVIEW",
        "mode": "AUTHORED_PRODUCT_FIXTURE",
        "plan_sha256": creation.digest(
            creation.canonical(creation.plan(creation.FIXTURE_SPEC)).encode()
        ),
        "request_id": creation.FIXTURE_SPEC["request_id"],
        "repository": creation.FIXTURE_SPEC["repository"],
        "frontend": creation.FIXTURE_SPEC["frontend"],
        "product": committed,
        "components": components,
        "web_evidence_sha256": web_hash,
        "review_proposal": {
            "status": "LOCAL_ONLY",
            "head_sha": committed["commit"],
            "remote_pr": "NOT_RUN",
        },
        "publication": "BLOCKED",
        "frontend_events": [],
        "privileged_automation": "DISABLED",
    }
    key = creation._AUTHORITY.get()
    if key is None:
        raise Blocked("BLOCKED: fixture control expired")
    body["proof"] = hmac.new(key, creation.canonical(body).encode(), hashlib.sha256).hexdigest()
    ledger.finish(creation.FIXTURE_SPEC, approval, "READY_FOR_LOCAL_REVIEW", body)
    ledger.close()
    # Reopen the actual database: duplicate approval cannot generate another product.
    restarted = creation.Ledger()
    try:
        duplicate = restarted.reserve(creation.FIXTURE_SPEC, approval)
        if duplicate["status"] != "DUPLICATE" or duplicate["receipt"] != body:
            raise Blocked("BLOCKED: creation replay disagrees")
        body = {**body, "restart_replay": "DUPLICATE_NO_EXECUTION", "products": 1}
    finally:
        restarted.close()
    return body


def valid_creation(record, web_result):
    from forgestra import creation
    from pr06_web_validation import valid_web

    try:
        if not isinstance(web_result, dict):
            return False
        web_result = {
            k: v for k, v in web_result.items() if k not in {"run_id", "tested_manifest_sha256"}
        }
        return (
            isinstance(record, dict)
            and valid_web(web_result)
            and record["status"] == "READY_FOR_LOCAL_REVIEW"
            and record["mode"] == "AUTHORED_PRODUCT_FIXTURE"
            and record["plan_sha256"]
            == creation.digest(creation.canonical(creation.plan(creation.FIXTURE_SPEC)).encode())
            and record["request_id"] == creation.FIXTURE_SPEC["request_id"]
            and record["repository"] == creation.FIXTURE_SPEC["repository"]
            and record["frontend"] == creation.FIXTURE_SPEC["frontend"]
            and record["web_evidence_sha256"]
            == creation.digest(creation.canonical(web_result).encode())
            and type(record["products"]) is int
            and record["products"] == 1
            and record["restart_replay"] == "DUPLICATE_NO_EXECUTION"
            and record["publication"] == "BLOCKED"
            and record["frontend_events"] == []
            and record["privileged_automation"] == "DISABLED"
            and record["review_proposal"]
            == {
                "status": "LOCAL_ONLY",
                "head_sha": record["product"]["commit"],
                "remote_pr": "NOT_RUN",
            }
            and valid_product(record["product"], web_result)
            and set(record["product"]["files"])
            == {f["path"] for f in creation.files(creation.FIXTURE_SPEC)}
            and all(
                record["product"]["files"][f["path"]] == creation.digest(f["content"].encode())
                for f in creation.files(creation.FIXTURE_SPEC)
                if f["path"] != "next-env.d.ts"
            )
            and set(record["components"]) == set(creation.COMPONENTS)
            and all(
                {k: c[k] for k in expected} == expected
                and c["status"] == "SOURCE_VERIFIED_LOCAL"
                and c["acceptance_status"] == "PASSED_LOCAL"
                and c["acceptance_evidence_sha256"] == record["web_evidence_sha256"]
                and c["acceptance_scope"] == "GENERATED_APP_INTEGRATION_NOT_UPSTREAM_SUITE"
                and len(c["files"]) == expected["source_files"]
                and creation.digest(creation.canonical(c["files"]).encode())
                == expected["source_tree_sha256"]
                for name, expected in creation.registry().items()
                for c in [record["components"][name]]
            )
        )
    except (KeyError, TypeError, ValueError, creation.safety.Blocked):
        return False


def acceptance():
    from forgestra import creation
    from forgestra_safety import private_output_workspace, strict_json_loads
    from bootstrap import environment
    from pr06_web_validation import web_acceptance

    with private_output_workspace():
        with creation.fixture_authority():
            ledger = creation.Ledger()
            approval = creation.approve_fixture(creation.FIXTURE_SPEC)
            try:
                reserved = ledger.reserve(creation.FIXTURE_SPEC, approval)
                if reserved["status"] != "RESERVED":
                    raise ValueError("fresh fixture reservation required")
                web_result, receipt = web_acceptance(product=(ledger, approval))
            finally:
                ledger.close()
    result: dict[str, Any] = {"status": "FAILED", "web": web_result, "creation": receipt}
    with private_output_workspace() as parent:
        path = parent / "specification.json"
        path.write_text(creation.canonical(creation.FIXTURE_SPEC), encoding="utf-8")
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        checks = []
        for args, expected in (
            (["create", "--spec", str(path)], "PLANNED_LOCAL"),
            (["create"], "BLOCKED"),
        ):
            child = subprocess.run(
                [str(python), "-I", "-m", "forgestra", *args],
                cwd=parent,
                env=environment(),
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            document = strict_json_loads(child.stdout)
            checks.append({"exit_code": child.returncode, "result": document})
            if (
                child.returncode != (0 if expected == "PLANNED_LOCAL" else 1)
                or document["status"] != expected
            ):
                return result
        result["installed_cli"] = checks
    result["status"] = "PASSED_LOCAL" if valid_creation(receipt, web_result) else "FAILED"
    return result


def valid_acceptance(record, web_result):
    from forgestra import creation

    try:
        checks = record["installed_cli"]
        return (
            record["status"] == "PASSED_LOCAL"
            and valid_creation(record["creation"], web_result)
            and isinstance(checks, list)
            and len(checks) == 2
            and type(checks[0]["exit_code"]) is int
            and checks[0]["exit_code"] == 0
            and checks[0]["result"] == creation.plan(creation.FIXTURE_SPEC)
            and type(checks[1]["exit_code"]) is int
            and checks[1]["exit_code"] == 1
            and checks[1]["result"] == creation.runtime_create()
        )
    except (KeyError, TypeError, ValueError, creation.safety.Blocked):
        return False
