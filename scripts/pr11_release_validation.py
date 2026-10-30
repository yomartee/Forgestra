"""Authored clean-copy quickstart, local rollback and blocked release assessment."""

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
QUICKSTART = (
    ("help", ["--help"], 0, None),
    ("doctor", ["doctor", "--source", "."], 0, "READY_OFFLINE"),
    ("inspect", ["inspect", "."], 0, "INSPECTED_LOCAL"),
    ("workspace", ["workspace", "."], 0, "PLANNED_LOCAL"),
    ("config", ["config", "--config", "config/forgestra.example.json"], 0, "VALID"),
    ("integrations", ["integrations"], 0, "AVAILABLE_LOCAL"),
    ("release", ["release", "--gate", "A"], 1, "BLOCKED"),
)


def acceptance():
    from bootstrap import environment
    from forgestra.verification import REQUIRED_SOURCE, validate_source
    from forgestra.release import readiness, files, sbom
    from forgestra_safety import private_output_workspace, strict_json_loads, write_new_tree, redact

    validate_source(ROOT)
    documented = (
        (ROOT / "docs/QUICKSTART.md")
        .read_text(encoding="utf-8")
        .split("```powershell\n", 1)[1]
        .split("```", 1)[0]
        .splitlines()
    )
    expected = [
        "python -I -B scripts/forgestra_cli.py " + " ".join(args) for _, args, _, _ in QUICKSTART
    ]
    if documented != expected:
        raise ValueError("documented quickstart drift")
    commands = []
    with private_output_workspace() as parent:
        source = parent / "clean-factory"
        names = sorted(set(REQUIRED_SOURCE) | {"config/forgestra.example.json"})
        for name in names:
            target = source / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)
        before = files(source, names)
        env = environment()
        profile = parent / "profile"
        profile.mkdir()
        env.update(
            HOME=str(profile),
            USERPROFILE=str(profile),
            APPDATA=str(profile),
            LOCALAPPDATA=str(profile),
        )
        for name, args, code, status in QUICKSTART:
            argv = [sys.executable, "-I", "-B", "scripts/forgestra_cli.py", *args]
            child = subprocess.run(
                argv,
                cwd=source,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
                check=False,
            )
            if child.returncode != code or child.stderr:
                raise ValueError("clean quickstart failed: " + name)
            stdout = redact(child.stdout).replace(str(parent).replace("\\", "\\\\"), "<fixture>")
            result = strict_json_loads(stdout) if status else None
            if status and (not isinstance(result, dict) or result["status"] != status):
                raise ValueError("quickstart result mismatch: " + name)
            if name == "release" and result != readiness("A"):
                raise ValueError("release falsely cleared")
            commands.append(
                {
                    "name": name,
                    "argv": argv,
                    "exit_code": code,
                    "expected_exit_code": code,
                    "result": result,
                    "stdout": stdout,
                    "stdout_sha256": hashlib.sha256(stdout.encode()).hexdigest(),
                }
            )
        if files(source, names) != before:
            raise ValueError("quickstart mutated source")
        # Review candidates are immutable versions; rollback selects retained prior bytes.
        previous = parent / "previous"
        candidate = parent / "candidate"
        write_new_tree(previous, [{"path": "app.txt", "content": "retained previous version\n"}])
        write_new_tree(candidate, [{"path": "app.txt", "content": "unapproved candidate\n"}])
        previous_hash = files(previous, ["app.txt"])
        candidate_hash = files(candidate, ["app.txt"])
        if previous_hash == candidate_hash:
            raise ValueError("rollback fixture did not change")
        selected = previous
        if files(selected, ["app.txt"]) != previous_hash:
            raise ValueError("rollback did not retain original")
        record = {
            "status": "PASSED_LOCAL",
            "mode": "AUTHORED_RELEASE_READINESS_ONLY",
            "quickstart": commands,
            "source_files": before,
            "source_preserved": True,
            "rollback": {
                "status": "PASSED_LOCAL",
                "mode": "RESELECT_RETAINED_PRIVATE_VERSION",
                "previous": previous_hash,
                "candidate": candidate_hash,
                "selected": previous_hash,
                "customer_mutation": "NOT_RUN",
            },
            "readiness": readiness("A"),
            "sbom": sbom(ROOT),
            "publication": "BLOCKED",
            "privileged_automation": "DISABLED",
            "hosted_clean_room": "NOT_RUN",
            "live_provider": "NOT_RUN",
        }
    if not valid_release(record):
        raise ValueError("release evidence contract mismatch")
    return record


def valid_release(record):
    from forgestra.release import readiness, files, sbom
    from forgestra.verification import REQUIRED_SOURCE
    from forgestra_safety import Blocked, strict_json_loads
    from forgestra.verification import ready_offline
    from forgestra.integrations import catalogue
    from forgestra.workspaces import plan
    from forgestra.configuration import load
    from forgestra_safety import classify_diff

    try:
        commands = record["quickstart"]
        names = sorted(set(REQUIRED_SOURCE) | {"config/forgestra.example.json"})

        def same(a, b):
            return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)

        return (
            record["status"] == "PASSED_LOCAL"
            and record["source_preserved"] is True
            and record["mode"] == "AUTHORED_RELEASE_READINESS_ONLY"
            and record["publication"] == "BLOCKED"
            and record["privileged_automation"] == "DISABLED"
            and record["hosted_clean_room"] == record["live_provider"] == "NOT_RUN"
            and same(record["readiness"], readiness("A"))
            and same(record["sbom"], sbom(ROOT))
            and record["source_files"] == files(ROOT, names)
            and len(commands) == len(QUICKSTART)
            and ready_offline(commands[1]["result"])
            and same(
                commands[2]["result"],
                {
                    "status": "INSPECTED_LOCAL",
                    "files": len(names),
                    "risk_tier": classify_diff(None),
                    "auto_merge": False,
                    "provider": "NOT_RUN",
                    "remote": "NOT_RUN",
                },
            )
            and same(commands[3]["result"], plan(ROOT, load(None)))
            and same(
                commands[4]["result"], {"status": "VALID", "privileged_automation": "DISABLED"}
            )
            and same(commands[5]["result"], catalogue())
            and same(commands[6]["result"], readiness("A"))
            and all(
                c["name"] == n
                and type(c["exit_code"]) is int
                and c["exit_code"] == code
                and c["expected_exit_code"] == code
                and type(c["expected_exit_code"]) is int
                and hashlib.sha256(c["stdout"].encode()).hexdigest() == c["stdout_sha256"]
                and bool(c["stdout"])
                and (
                    same(strict_json_loads(c["stdout"]), c["result"])
                    if status
                    else c["result"] is None and "release" in c["stdout"]
                )
                and c["argv"] == [sys.executable, "-I", "-B", "scripts/forgestra_cli.py", *args]
                and (not status or c["result"]["status"] == status)
                for c, (n, args, code, status) in zip(commands, QUICKSTART)
            )
            and record["rollback"]
            == {
                "status": "PASSED_LOCAL",
                "mode": "RESELECT_RETAINED_PRIVATE_VERSION",
                "previous": {"app.txt": hashlib.sha256(b"retained previous version\n").hexdigest()},
                "candidate": {"app.txt": hashlib.sha256(b"unapproved candidate\n").hexdigest()},
                "selected": {"app.txt": hashlib.sha256(b"retained previous version\n").hexdigest()},
                "customer_mutation": "NOT_RUN",
            }
        )
    except (KeyError, TypeError, ValueError, OSError, Blocked):
        return False


if __name__ == "__main__":
    print(json.dumps(acceptance(), indent=2))
