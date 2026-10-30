"""Authored private synchronization candidate, preservation and Git acceptance."""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]

CONFIG: dict[str, Any] = {
    "schema_version": 1,
    "mapping_id": "08100000-0000-4000-8000-000000000001",
    "source_repository": "yomartee/sync-fixture-upstream",
    "target_repository": "yomartee/sync-fixture-downstream",
    "opted_in": True,
    "paths": [{"source": "template", "target": "app"}],
}
BASE = {
    "template/guide.txt": b"Shared original\n",
    "template/removed.txt": b"Remove only owned unchanged file\n",
}
HEAD = {
    "template/guide.txt": b"Reviewed upstream revision\n",
    "template/new.txt": b"New upstream text\n",
}
CUSTOM = {
    ".github/workflows/customer.yml": b"name: Preserved customer workflow\non: workflow_dispatch\n",
    "CLAUDE.md": b"Preserved customer instructions\r\n",
    "config/customer.json": b'{"customer":true}\n',
    "binary.dat": bytes([0, 255, 13, 10]),
    "app/custom.txt": b"Downstream only\n",
}
RUN_ID = "08100000-0000-4000-8000-000000000008"


def write_fixture(root, files):
    from forgestra.synchronization import checkpoint
    from forgestra_safety import _LOCAL_OUTPUT_PARENT, Blocked

    parent = _LOCAL_OUTPUT_PARENT.get()
    if parent is None or root.parent != parent or root.exists():
        raise Blocked("BLOCKED: new authored fixture root required")
    allowed = {
        "sync-source": BASE,
        "sync-target": {
            **CUSTOM,
            **{n.replace("template/", "app/", 1): d for n, d in BASE.items()},
        },
        "sync-candidate": {
            **CUSTOM,
            **{n.replace("template/", "app/", 1): d for n, d in HEAD.items()},
        },
    }
    if (
        root.name not in allowed
        or files != allowed[root.name]
        or root.is_symlink()
        or root.is_junction()
    ):
        raise Blocked("BLOCKED: fixed authored fixture bytes required")
    root.mkdir()
    for name, data in files.items():
        checkpoint()
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def git_snapshot(root, files):
    from forgestra.repair import environment
    from forgestra.synchronization import checkpoint, digest
    from forgestra_safety import _LOCAL_OUTPUT_PARENT, Blocked

    parent = _LOCAL_OUTPUT_PARENT.get()
    if parent is None or root != parent / "sync-candidate" or (root / ".git").exists():
        raise Blocked("BLOCKED: private authored Git root required")
    from forgestra.adoption import read_tree

    expected = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in HEAD.items()}}
    if files != expected or read_tree(root)["files"] != expected:
        raise Blocked("BLOCKED: fixed authored Git bytes required")
    executable = "C:/Program Files/Git/cmd/git.exe" if os.name == "nt" else shutil.which("git")
    if not executable:
        raise Blocked("BLOCKED: Git unavailable")
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
    results: list[dict[str, Any]] = []
    for args in (
        ["init", "--template=", "--initial-branch=fixture-sync"],
        ["add", "--", *sorted(files)],
        ["commit", "--no-verify", "-m", "Verified authored PR 08 synchronization fixture"],
        ["rev-parse", "HEAD"],
        ["ls-tree", "-r", "--full-tree", "HEAD"],
    ):
        checkpoint()
        child = subprocess.run(
            prefix + args,
            cwd=root,
            env=environment(parent / "git-profile"),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        if child.returncode:
            raise Blocked("BLOCKED: local sync Git validation failed")
        results.append({"argv": args, "exit_code": child.returncode, "stdout": child.stdout})
    sha = results[3]["stdout"].strip()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise Blocked("BLOCKED: invalid Git commit")
    tree = [
        "100644 blob "
        + hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        + "\t"
        + name
        for name, data in sorted(files.items())
    ]
    if results[4]["stdout"].splitlines() != tree:
        raise Blocked("BLOCKED: committed blob bytes differ from candidate")
    if any(digest((root / n).read_bytes()) != digest(data) for n, data in files.items()):
        raise Blocked("BLOCKED: source changed during fixture commit")
    return {"commit": sha, "commands": results, "tree": tree, "remote": "NOT_CONFIGURED"}


def acceptance():
    from forgestra import synchronization as sync, sync_control as control
    from forgestra_safety import private_output_workspace, Blocked
    from bootstrap import environment

    with private_output_workspace() as parent, control.fixture_control():
        source, target = parent / "sync-source", parent / "sync-target"
        write_fixture(source, BASE)
        target_seed = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in BASE.items()}}
        write_fixture(target, target_seed)
        previous = sync.baseline(source, CONFIG)
        baseline_path = parent / "source-baseline.json"
        baseline_path.write_bytes(sync.encoded(previous))
        for name in BASE:
            (source / name).unlink()
        for name, data in HEAD.items():
            (source / name).write_bytes(data)
        before_source, before_target = sync.read_tree(source), sync.read_tree(target)
        proposal = sync.plan(source, target, CONFIG, json.loads(baseline_path.read_bytes()))
        proof = control.approval(proposal)
        journal = control.Journal()
        try:
            if journal.reserve(RUN_ID, proposal, proof) != {"status": "RESERVED"}:
                raise Blocked("BLOCKED: unexpected fresh sync reservation")
            journal.claim(RUN_ID, proposal, proof)
            candidate_files = dict(before_target["files"])
            for change in proposal["changes"]:
                if change["operation"] == "delete":
                    del candidate_files[change["path"]]
                else:
                    candidate_files[change["path"]] = before_source["files"][change["source"]]
            candidate = parent / "sync-candidate"
            journal.require_executing(RUN_ID, proposal, proof)
            if proposal != sync.plan(source, target, CONFIG, previous):
                raise Blocked("BLOCKED: changed sync inputs")
            # Only this literal authored candidate may preserve protected customer bytes.
            expected = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in HEAD.items()}}
            if candidate_files != expected:
                raise Blocked("BLOCKED: unexpected authored candidate")
            write_fixture(candidate, candidate_files)
            after = sync.read_tree(candidate)
            checks = {
                "exact_candidate": after["files"] == expected,
                "customer_preserved": all(after["files"][n] == d for n, d in CUSTOM.items()),
                "owned_deletion_only": "app/removed.txt" not in after["files"],
                "upstream_unchanged": before_source == sync.read_tree(source),
                "target_unchanged": before_target == sync.read_tree(target),
                "plan_unchanged": proposal == sync.plan(source, target, CONFIG, previous),
                "expected_diff": sorted(c["operation"] for c in proposal["changes"])
                == ["add", "delete", "update"],
            }
            if not all(checks.values()):
                journal.finish(RUN_ID, proposal, proof, "FAILED")
                raise Blocked("BLOCKED: authored sync validation failed")
            git = git_snapshot(candidate, expected)
            # Advance only a private baseline after verified output; input baseline stays unchanged.
            next_baseline = sync.baseline(source, CONFIG)
            next_path = parent / "next-baseline.json"
            next_path.write_bytes(sync.encoded(next_baseline))
            repeat = sync.plan(source, candidate, CONFIG, json.loads(next_path.read_bytes()))
            checks["advanced_baseline_noop"] = repeat["changes"] == repeat["conflicts"] == []
            if not all(checks.values()):
                raise Blocked("BLOCKED: repeated sync not a no-op")
            receipt = {
                "status": "READY_FOR_LOCAL_REVIEW",
                "run_id": RUN_ID,
                "plan_sha256": control.fingerprint(proposal),
                "candidate_sha256": sync.tree_hash(after),
                "checks": checks,
                "git": git,
                "publication": "BLOCKED",
            }
            receipt["verification_proof"] = control.signature(receipt)
            journal.finish(RUN_ID, proposal, proof, "READY_FOR_LOCAL_REVIEW", receipt)
        finally:
            journal.close()
        reopened = control.Journal()
        try:
            duplicate = reopened.reserve(RUN_ID, proposal, proof)
            if duplicate["status"] != "DUPLICATE" or duplicate["receipt"] != receipt:
                raise Blocked("BLOCKED: sync receipt replay mismatch")
        finally:
            reopened.close()
        inputs = {"mapping": CONFIG, "baseline": previous, "next_baseline": next_baseline}
        paths = {}
        for name, document in inputs.items():
            path = parent / (name + ".json")
            path.write_bytes(sync.encoded(document))
            paths[name] = path
        python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        cli = []
        for args, expected_result, code in (
            (
                [
                    "sync",
                    "--source",
                    str(source),
                    "--target",
                    str(target),
                    "--mapping",
                    str(paths["mapping"]),
                    "--baseline",
                    str(paths["baseline"]),
                ],
                proposal,
                0,
            ),
            (["sync"], sync.runtime_sync(), 1),
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
            actual = json.loads(child.stdout)
            if child.returncode != code or actual != expected_result:
                raise Blocked("BLOCKED: installed sync CLI disagrees with source")
            cli.append({"argv": args, "exit_code": child.returncode, "result": actual})
        return {
            "status": "PASSED_LOCAL",
            "mode": "AUTHORED_SYNC_FIXTURE",
            "plan": proposal,
            "inputs": inputs,
            "receipt": receipt,
            "restart_replay": "DUPLICATE_NO_EXECUTION",
            "candidate_files": {n: sync.digest(d) for n, d in expected.items()},
            "installed_cli": cli,
            "privileged_automation": "DISABLED",
            "publication": "BLOCKED",
            "remote_pr": "NOT_RUN",
            "live_provider": "NOT_RUN",
            "target_execution": "DISABLED",
        }


def valid_sync(record):
    from forgestra import synchronization as sync, sync_control as control

    try:
        expected = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in HEAD.items()}}
        receipt, proposal = record["receipt"], record["plan"]

        def tree(files):
            directories = {p.as_posix() for n in files for p in Path(n).parents if str(p) != "."}
            return {"files": files, "directories": sorted(directories)}

        base_tree, head_tree = tree(BASE), tree(HEAD)
        target_seed = {**CUSTOM, **{n.replace("template/", "app/", 1): d for n, d in BASE.items()}}
        previous = sync.baseline_tree(base_tree, CONFIG)
        expected_plan = sync.compare_trees(
            proposal["source_root"],
            proposal["target_root"],
            head_tree,
            tree(target_seed),
            CONFIG,
            previous,
        )
        expected_commands = [
            ["init", "--template=", "--initial-branch=fixture-sync"],
            ["add", "--", *sorted(expected)],
            ["commit", "--no-verify", "-m", "Verified authored PR 08 synchronization fixture"],
            ["rev-parse", "HEAD"],
            ["ls-tree", "-r", "--full-tree", "HEAD"],
        ]
        git = receipt["git"]
        return (
            record["status"] == "PASSED_LOCAL"
            and record["mode"] == "AUTHORED_SYNC_FIXTURE"
            and proposal == expected_plan
            and record["inputs"]
            == {
                "mapping": CONFIG,
                "baseline": previous,
                "next_baseline": sync.baseline_tree(head_tree, CONFIG),
            }
            and receipt["candidate_sha256"] == sync.tree_hash(tree(expected))
            and receipt["publication"] == "BLOCKED"
            and isinstance(receipt["verification_proof"], str)
            and re.fullmatch(r"[0-9a-f]{64}", receipt["verification_proof"]) is not None
            and proposal["status"] == "PLANNED_LOCAL"
            and proposal["mapping"] == CONFIG
            and proposal["conflicts"] == []
            and sorted(c["operation"] for c in proposal["changes"]) == ["add", "delete", "update"]
            and record["restart_replay"] == "DUPLICATE_NO_EXECUTION"
            and record["candidate_files"] == {n: sync.digest(d) for n, d in expected.items()}
            and receipt["status"] == "READY_FOR_LOCAL_REVIEW"
            and receipt["run_id"] == RUN_ID
            and receipt["plan_sha256"] == control.fingerprint(proposal)
            and set(receipt["checks"])
            == {
                "exact_candidate",
                "customer_preserved",
                "owned_deletion_only",
                "upstream_unchanged",
                "target_unchanged",
                "plan_unchanged",
                "expected_diff",
                "advanced_baseline_noop",
            }
            and all(v is True for v in receipt["checks"].values())
            and re.fullmatch(r"[0-9a-f]{40}", git["commit"]) is not None
            and git["remote"] == "NOT_CONFIGURED"
            and len(git["commands"]) == 5
            and all(
                c["argv"] == argv
                and isinstance(c["stdout"], str)
                and type(c["exit_code"]) is int
                and c["exit_code"] == 0
                for c, argv in zip(git["commands"], expected_commands)
            )
            and git["commands"][3]["stdout"].strip() == git["commit"]
            and git["tree"]
            == [
                "100644 blob "
                + hashlib.sha1(b"blob " + str(len(d)).encode() + b"\0" + d).hexdigest()
                + "\t"
                + n
                for n, d in sorted(expected.items())
            ]
            and git["commands"][4]["stdout"].splitlines() == git["tree"]
            and len(record["installed_cli"]) == 2
            and type(record["installed_cli"][0]["exit_code"]) is int
            and record["installed_cli"][0]["exit_code"] == 0
            and record["installed_cli"][0]["result"] == proposal
            and type(record["installed_cli"][1]["exit_code"]) is int
            and record["installed_cli"][1]["exit_code"] == 1
            and record["installed_cli"][1]["result"] == sync.runtime_sync()
            and record["privileged_automation"] == "DISABLED"
            and record["publication"] == "BLOCKED"
            and record["remote_pr"] == record["live_provider"] == "NOT_RUN"
            and record["target_execution"] == "DISABLED"
        )
    except (KeyError, TypeError, ValueError, OSError, sync.safety.Blocked):
        return False
