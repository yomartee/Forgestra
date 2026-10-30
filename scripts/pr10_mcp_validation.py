"""Optional MCP acquisition and fresh offline SDK/stdio acceptance. No live providers."""

import argparse
import hashlib
from importlib import import_module
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "src")]
FIXTURE = {
    "README.md": b"Authored read-only MCP fixture\n",
    "hook.py": b"raise RuntimeError('This target must never execute')\n",
}
OPTIONAL_FILES = ("__init__.py", "__main__.py", "server.py")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def acquire(download=False):
    from acquire_tools import unlinked
    from forgestra.verification import validate_optional
    from forgestra_safety import Blocked

    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise Blocked("BLOCKED: kill switch active")
    config = validate_optional(ROOT)
    platform = "windows" if os.name == "nt" else "linux"
    cache = ROOT / ".tools/pr10-wheels"
    unlinked(cache)
    cache.mkdir(exist_ok=True)
    for item in config["platforms"][platform]:
        path = cache / item["filename"]
        unlinked(path)
        if not path.is_file():
            if not download:
                raise Blocked(
                    "BLOCKED: optional SDK wheel unavailable; explicit acquisition required"
                )
            with urllib.request.urlopen(item["url"], timeout=30) as r:
                data = r.read(50_000_001)
            if len(data) > 50_000_000 or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise Blocked("BLOCKED: optional SDK download hash mismatch")
            path.write_bytes(data)
        if digest(path) != item["sha256"]:
            raise Blocked("BLOCKED: optional SDK wheel changed")
    return config["platforms"][platform]


async def protocol(root):
    """Runs inside a fresh optional environment; its parent filters credentials."""
    import asyncio
    from forgestra.integrations import (
        catalogue,
        sales_demo,
        TOOLS,
        error,
        child_environment,
        client_config,
    )

    Client = import_module("mcp").Client
    Parameters = import_module("mcp.client.stdio").StdioServerParameters
    env = child_environment()
    env.update(
        OTEL_SDK_DISABLED="true",
        OTEL_TRACES_EXPORTER="none",
        OTEL_METRICS_EXPORTER="none",
        OTEL_LOGS_EXPORTER="none",
    )
    config = client_config(Path(sys.executable).absolute(), root)["mcpServers"][
        "forgestra-local-readonly"
    ]
    params = Parameters(command=config["command"], args=config["args"], cwd=str(root), env=env)
    results = {}
    executed = 0
    async with Client(params, read_timeout_seconds=15, mode="legacy") as client:
        listed = await asyncio.wait_for(client.list_tools(), 20)
        tools = listed.tools if hasattr(listed, "tools") else listed
        inventory = [t.model_dump(mode="json", exclude_none=True) for t in tools]
        assert {t.name for t in tools} == set(TOOLS)
        executed += 1
        expected = {
            "factory_status": catalogue(),
            "sales_demo": sales_demo(),
            "inspect_workspace": {
                "status": "INSPECTED_LOCAL",
                "files": 2,
                "risk_tier": 1,
                "auto_merge": False,
                "provider": "NOT_RUN",
                "remote": "NOT_RUN",
            },
        }
        calls: list[tuple[str, dict[str, Any], dict[str, Any]]] = [
            (n, {}, v) for n, v in expected.items()
        ]
        calls += [
            ("derive_product", {}, error("WORKFLOW_UNAVAILABLE")),
            ("trigger_sync", {}, error("UNSUPPORTED_OPERATION")),
            ("inspect_workspace", {"root": "../outside"}, error("INVALID_ARGUMENTS")),
        ]
        for name, args, want in calls:
            response = await asyncio.wait_for(client.call_tool(name, args), 20)
            assert response.structured_content == want
            assert response.is_error is (want["status"] == "ERROR")
            assert json.loads(response.content[0].text) == want
            executed += 1
            results[name + ("_bad_args" if args else "")] = {
                "result": response.structured_content,
                "is_error": response.is_error,
            }
    from unittest.mock import patch

    server = import_module("forgestra_mcp.server").build_server(root)
    async with Client(server, read_timeout_seconds=15, mode="legacy") as client:
        for name, value, want in (
            (
                "inspect_timeout",
                subprocess.TimeoutExpired(["fixed-core-cli"], 10),
                error("TIMEOUT"),
            ),
            (
                "inspect_nonzero",
                subprocess.CompletedProcess([], 1, "synthetic-not-for-output", "private-error"),
                error("PROCESS_FAILED"),
            ),
        ):
            option = (
                {"side_effect": value} if isinstance(value, Exception) else {"return_value": value}
            )
            with patch("forgestra.integrations.subprocess.run", **option):
                response = await client.call_tool("inspect_workspace", {})
            assert response.structured_content == want and response.is_error is True
            results[name] = {"result": response.structured_content, "is_error": response.is_error}
            executed += 1
    return {
        "status": "PASSED_LOCAL",
        "transport": "SDK_STDIO_SUBPROCESS",
        "fault_transport": "SDK_IN_MEMORY",
        "tests": {
            "status": "PASSED",
            "collected": 9,
            "tests": executed,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "expected_failures": 0,
            "unexpected_successes": 0,
        },
        "inventory": inventory,
        "calls": results,
        "sdk_version": import_module("importlib.metadata").version("mcp"),
    }


def acceptance():
    from bootstrap import environment
    from forgestra.verification import validate_source, REQUIRED_SOURCE
    from forgestra_safety import private_output_workspace, strict_json_loads, redact

    validate_source(ROOT)
    wheels = acquire()
    build_python = ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    commands = []
    with private_output_workspace() as parent:
        profile = parent / "profile"
        profile.mkdir()
        env = environment()
        env.update(
            HOME=str(profile),
            USERPROFILE=str(profile),
            APPDATA=str(profile),
            LOCALAPPDATA=str(profile),
            SOURCE_DATE_EPOCH="946684800",
            PIP_CONFIG_FILE=os.devnull,
            OTEL_SDK_DISABLED="true",
            OTEL_TRACES_EXPORTER="none",
            OTEL_METRICS_EXPORTER="none",
            OTEL_LOGS_EXPORTER="none",
        )

        def run(name, argv, cwd=parent):
            child = subprocess.run(
                [str(a) for a in argv],
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                check=False,
            )
            log = redact(child.stdout + child.stderr).replace(str(parent), "<fixture>")
            commands.append(
                {
                    "name": name,
                    "argv": [str(a).replace(str(parent), "<fixture>") for a in argv],
                    "exit_code": child.returncode,
                    "log": log,
                    "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
                }
            )
            output = ROOT / ".tools/pr10-mcp-results"
            from acquire_tools import unlinked

            unlinked(output)
            output.mkdir(exist_ok=True)
            unlinked(output / (name + ".log"))
            (output / (name + ".log")).write_text(log, encoding="utf-8")
            if child.returncode != 0:
                # Retain failure bytes separately: a later diagnostic session
                # must not overwrite the only explanation for a failed build.
                failure = output / (
                    "failed-" + name + "-" + hashlib.sha256(log.encode()).hexdigest() + ".log"
                )
                unlinked(failure)
                failure.write_text(log, encoding="utf-8")
                raise ValueError("optional MCP fixture command failed: " + name)
            return child.stdout

        source = parent / "factory-source"
        for name in REQUIRED_SOURCE:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, path)
        sdk_wheels = parent / "sdk-wheels"
        sdk_wheels.mkdir()
        for wheel in wheels:
            shutil.copyfile(
                ROOT / ".tools/pr10-wheels" / wheel["filename"], sdk_wheels / wheel["filename"]
            )
        core_wheels: list[Path] = []
        optional_wheels: list[Path] = []
        for index in (1, 2):
            for label, project, output in (
                ("core", source, core_wheels),
                ("optional", source / "integrations/mcp", optional_wheels),
            ):
                dest = parent / (label + "-wheel-" + str(index))
                run(
                    label + "-wheel-" + str(index),
                    [
                        build_python,
                        "-I",
                        "-m",
                        "pip",
                        "--isolated",
                        "--no-cache-dir",
                        "wheel",
                        "--no-index",
                        "--no-deps",
                        "--no-build-isolation",
                        "--wheel-dir",
                        dest,
                        project,
                    ],
                )
                output.append(next(dest.glob("*.whl")))
        if digest(core_wheels[0]) != digest(core_wheels[1]) or digest(optional_wheels[0]) != digest(
            optional_wheels[1]
        ):
            raise ValueError("optional/core wheels are not reproducible")
        with zipfile.ZipFile(optional_wheels[0]) as z:
            expected = {
                "forgestra_mcp/" + name for name in ("__init__.py", "__main__.py", "server.py")
            }
            expected |= {
                "forgestra_mcp-0.2.0.dev0.dist-info/" + name
                for name in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")
            }
            payload_hashes = {
                n: hashlib.sha256(z.read("forgestra_mcp/" + n)).hexdigest() for n in OPTIONAL_FILES
            }
            if payload_hashes != {
                n: digest(ROOT / "integrations/mcp/src/forgestra_mcp" / n) for n in OPTIONAL_FILES
            }:
                raise ValueError("optional wheel differs from reviewed source")
            if set(z.namelist()) != expected:
                raise ValueError("unreviewed optional wheel payload")
        venv = parent / "optional-env"
        python = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        run("optional-venv", [sys.executable, "-I", "-m", "venv", "--copies", venv])
        run(
            "optional-dependencies",
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-index",
                "--only-binary=:all:",
                "--require-hashes",
                "--find-links",
                sdk_wheels,
                "-r",
                ROOT / "requirements/mcp.lock",
            ],
        )
        run(
            "optional-wheel-install",
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "install",
                "--no-index",
                "--no-deps",
                core_wheels[0],
                optional_wheels[0],
            ],
        )
        run("pip-check", [python, "-I", "-m", "pip", "--isolated", "check"])
        target = parent / "fixture"
        target.mkdir()
        fixture = FIXTURE
        for n, data in fixture.items():
            (target / n).write_bytes(data)
        before = {n: digest(target / n) for n in fixture}
        # Copy only this reviewed harness, never target-provided client code.
        harness = parent / "protocol.py"
        harness.write_bytes(Path(__file__).read_bytes())
        result = strict_json_loads(
            run("sdk-stdio-protocol", [python, "-I", harness, "--protocol", target])
        )
        if {n: digest(target / n) for n in fixture} != before or set(
            p.name for p in target.iterdir()
        ) != set(fixture):
            raise ValueError("MCP fixture changed")
        installed = strict_json_loads(
            run("installed-catalogue", [python, "-I", "-m", "forgestra", "integrations"])
        )
        from forgestra.integrations import catalogue

        if installed != catalogue():
            raise ValueError("installed catalogue mismatch")
        record = {
            "status": "PASSED_LOCAL",
            "mode": "OPTIONAL_READ_ONLY_MCP",
            "protocol": result,
            "commands": commands,
            "wheel_sha256": digest(optional_wheels[0]),
            "core_wheel_sha256": digest(core_wheels[0]),
            "reproducible": True,
            "dependency_wheels": {w["filename"]: w["sha256"] for w in wheels},
            "optional_payload_sha256": payload_hashes,
            "fixture_files": before,
            "original_preserved": True,
            "installed_catalogue": installed,
            "active_configuration": strict_json_loads(
                (ROOT / "mcp.json").read_text(encoding="utf-8")
            ),
            "privileged_automation": "DISABLED",
            "live_provider": "NOT_RUN",
            "publication": "BLOCKED",
            "remote_pr": "NOT_RUN",
        }
    if not valid_mcp(record):
        raise ValueError("optional MCP evidence mismatch")
    return record


def valid_mcp(record):
    from forgestra.integrations import TOOLS, catalogue, sales_demo, error
    from forgestra_safety import Blocked, strict_json_loads

    def same_json(left, right):
        # Python equality conflates JSON booleans with 0/1, including nested fields.
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)

    try:
        protocol = record["protocol"]
        inventory = protocol["inventory"]
        calls = protocol["calls"]
        expected = {
            "factory_status": catalogue(),
            "sales_demo": sales_demo(),
            "inspect_workspace": {
                "status": "INSPECTED_LOCAL",
                "files": 2,
                "risk_tier": 1,
                "auto_merge": False,
                "provider": "NOT_RUN",
                "remote": "NOT_RUN",
            },
            "derive_product": error("WORKFLOW_UNAVAILABLE"),
            "trigger_sync": error("UNSUPPORTED_OPERATION"),
            "inspect_workspace_bad_args": error("INVALID_ARGUMENTS"),
            "inspect_timeout": error("TIMEOUT"),
            "inspect_nonzero": error("PROCESS_FAILED"),
        }
        commands = record["commands"]
        optional_python = "<fixture>/optional-env/" + (
            "Scripts/python.exe" if os.name == "nt" else "bin/python"
        )
        # Recorded paths use native separators, preserving the actual argv.
        optional_python = str(Path(optional_python))
        protocol_argv = [
            optional_python,
            "-I",
            str(Path("<fixture>/protocol.py")),
            "--protocol",
            str(Path("<fixture>/fixture")),
        ]
        return (
            record["status"] == "PASSED_LOCAL"
            and record["mode"] == "OPTIONAL_READ_ONLY_MCP"
            and record["privileged_automation"] == "DISABLED"
            and record["publication"] == "BLOCKED"
            and record["live_provider"] == record["remote_pr"] == "NOT_RUN"
            and record["active_configuration"] == {"mcpServers": {}}
            and record["reproducible"] is True
            and record["original_preserved"] is True
            and record["installed_catalogue"] == catalogue()
            and protocol["status"] == "PASSED_LOCAL"
            and protocol["sdk_version"] == "2.3.0"
            and protocol["transport"] == "SDK_STDIO_SUBPROCESS"
            and protocol["fault_transport"] == "SDK_IN_MEMORY"
            and protocol["tests"]
            == {
                "status": "PASSED",
                "collected": 9,
                "tests": 9,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "expected_failures": 0,
                "unexpected_successes": 0,
            }
            and all(type(v) is int for k, v in protocol["tests"].items() if k != "status")
            and len(inventory) == len(TOOLS)
            and {t["name"] for t in inventory} == set(TOOLS)
            and all(
                t["description"] == TOOLS[t["name"]]
                and t["output_schema"] == {"type": "object"}
                and same_json(
                    t["annotations"],
                    {
                        "read_only_hint": True,
                        "destructive_hint": False,
                        "idempotent_hint": True,
                        "open_world_hint": False,
                    },
                )
                and same_json(
                    t["input_schema"],
                    {"type": "object", "properties": {}, "additionalProperties": False},
                )
                and t["annotations"]["read_only_hint"] is True
                for t in inventory
            )
            and same_json(
                calls,
                {n: {"result": v, "is_error": v["status"] == "ERROR"} for n, v in expected.items()},
            )
            and record["fixture_files"]
            == {n: hashlib.sha256(v).hexdigest() for n, v in FIXTURE.items()}
            and record["optional_payload_sha256"]
            == {n: digest(ROOT / "integrations/mcp/src/forgestra_mcp" / n) for n in OPTIONAL_FILES}
            and re.fullmatch(r"[0-9a-f]{64}", record["wheel_sha256"]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", record["core_wheel_sha256"]) is not None
            and [c["name"] for c in commands]
            == [
                "core-wheel-1",
                "optional-wheel-1",
                "core-wheel-2",
                "optional-wheel-2",
                "optional-venv",
                "optional-dependencies",
                "optional-wheel-install",
                "pip-check",
                "sdk-stdio-protocol",
                "installed-catalogue",
            ]
            and len(commands) == 10
            and all(
                type(c["exit_code"]) is int
                and c["exit_code"] == 0
                and isinstance(c["argv"], list)
                and bool(c["argv"])
                and all(isinstance(a, str) and a for a in c["argv"])
                and hashlib.sha256(c["log"].encode()).hexdigest() == c["log_sha256"]
                for c in commands
            )
            and commands[8]["argv"] == protocol_argv
            and commands[9]["argv"] == [optional_python, "-I", "-m", "forgestra", "integrations"]
            and same_json(strict_json_loads(commands[8]["log"]), protocol)
            and same_json(strict_json_loads(commands[9]["log"]), record["installed_catalogue"])
            and record["dependency_wheels"] == {w["filename"]: w["sha256"] for w in acquire()}
        )
    except (KeyError, TypeError, ValueError, OSError, Blocked):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acquire", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--protocol", type=Path)
    args = parser.parse_args()
    if args.protocol:
        import asyncio

        print(json.dumps(asyncio.run(protocol(args.protocol)), sort_keys=True))
    elif args.acquire:
        print(json.dumps({"status": "AVAILABLE_OFFLINE", "wheels": len(acquire(args.download))}))
    elif args.download:
        parser.error("--download requires --acquire")
    else:
        print(json.dumps(acceptance(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
