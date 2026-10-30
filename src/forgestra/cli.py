"""The supported offline CLI. No provider SDK, target command or network request runs."""

import argparse
import importlib.metadata
import json
from pathlib import Path
import sys

from forgestra import __version__
from forgestra.configuration import load
from forgestra.workspaces import plan
from forgestra_safety import Blocked, strict_json_loads, validate_diff
from forgestra.providers import sanitized
from inspect_local import inspect

from forgestra.verification import DEV_PACKAGES, validate_source, supported_runtime


def doctor(configuration, development=False, connectivity=False, source=None):
    issues = []
    if not supported_runtime():
        issues.append("UNSUPPORTED_RUNTIME")
    if development:
        for name, version in DEV_PACKAGES.items():
            try:
                installed = importlib.metadata.version(name)
            except importlib.metadata.PackageNotFoundError:
                installed = None
            if installed != version:
                issues.append("MISSING_OR_INCOMPATIBLE_DEPENDENCY:" + name)
    if connectivity:
        issues.append("CONNECTIVITY_UNSUPPORTED")
    if source is not None:
        try:
            validate_source(source)
        except OSError:
            issues.append("MISSING_SOURCE_COMMAND_OR_WORKFLOW")
        except (ValueError, TypeError, KeyError, SyntaxError, Blocked):
            issues.append("INVALID_SOURCE_CONTRACT")

    return {
        "status": "BLOCKED" if issues else "READY_OFFLINE",
        "issues": issues,
        "configuration": "VALID",
        "connectivity": "NOT_RUN",
        "optional_integrations": "DISABLED",
        "privileged_automation": "DISABLED",
        "version": __version__,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in (
        "doctor",
        "inspect",
        "workspace",
        "config",
        "assess",
        "audit",
        "improve",
        "repair",
        "adopt",
        "install",
        "web",
        "create",
        "sync",
        "sync-baseline",
        "sync-targets",
        "maintain",
        "integrations",
        "release",
    ):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path)
        if name in {"inspect", "workspace", "assess", "audit", "improve", "adopt"}:
            command.add_argument("root", nargs="?", type=Path, default=Path("."))
        if name == "adopt":
            command.add_argument(
                "--action", choices=("install", "upgrade", "uninstall"), default="install"
            )
            command.add_argument("--factory-version", default="0.2.0.dev0")
        if name == "sync":
            for flag in ("source", "target", "mapping", "baseline"):
                command.add_argument("--" + flag, type=Path)
        if name == "sync-baseline":
            command.add_argument("--source", required=True, type=Path)
            command.add_argument("--mapping", required=True, type=Path)
        if name == "sync-targets":
            command.add_argument("--manifest", required=True, type=Path)
        if name == "integrations":
            command.add_argument("--client-python", type=Path)
            command.add_argument("--root", type=Path, default=Path("."))
        if name == "release":
            command.add_argument("--gate", choices=("A", "B", "C"), required=True)
        if name == "maintain":
            command.add_argument("--evidence", type=Path)
        if name == "create":
            command.add_argument("--spec", type=Path)
        if name == "web":
            command.add_argument("--schema", required=True, type=Path)
        if name == "inspect":
            command.add_argument("--changes-json", type=Path)
        if name in {"assess", "audit", "improve"}:
            command.add_argument("--replay", type=Path, help="Explicit offline provider fixture")
            command.add_argument("--provider-config", type=Path)
        if name == "doctor":
            command.add_argument("--development", action="store_true")
            command.add_argument("--connectivity", action="store_true")
            command.add_argument(
                "--source", type=Path, help="Check factory source command inventory"
            )
    args = parser.parse_args(argv)
    try:
        if args.command != "doctor" and not supported_runtime():
            print(
                json.dumps(
                    {
                        "status": "BLOCKED",
                        "reason_code": "UNSUPPORTED_RUNTIME",
                        "connectivity": "NOT_RUN",
                    }
                )
            )
            return 1
        if args.config is not None and not args.config.is_file():
            print(
                json.dumps(
                    {
                        "status": "BLOCKED",
                        "reason_code": "MISSING_CONFIGURATION",
                        "connectivity": "NOT_RUN",
                    }
                )
            )
            return 1
        configuration = load(args.config)
        if args.command == "doctor":
            result = doctor(configuration, args.development, args.connectivity, args.source)
        elif args.command == "inspect":
            changes = (
                validate_diff(strict_json_loads(args.changes_json.read_text(encoding="utf-8")))
                if args.changes_json
                else None
            )
            result = inspect(args.root, changes)
        elif args.command in {"assess", "audit", "improve"}:
            from forgestra.assessment import assess, Improver
            from forgestra.verification import plain_file
            from forgestra.providers import configuration as provider_configuration

            fixture = strict_json_loads(plain_file(args.replay)) if args.replay else None
            provider = (
                provider_configuration(strict_json_loads(plain_file(args.provider_config)))
                if args.provider_config
                else provider_configuration()
            )
            result = (
                Improver().run(args.root, fixture, provider)
                if args.command == "improve"
                else assess(args.root, fixture, provider)
            )
        elif args.command == "workspace":
            result = plan(args.root, configuration)
        elif args.command == "release":
            from forgestra.release import readiness

            result = readiness(args.gate)
        elif args.command == "integrations":
            from forgestra.integrations import catalogue, client_config

            result = (
                {
                    "status": "PLANNED_LOCAL",
                    "activation": "NOT_APPLIED",
                    "client_configuration": client_config(args.client_python, args.root),
                    "privileged_automation": "DISABLED",
                }
                if args.client_python
                else catalogue()
            )
        elif args.command == "maintain":
            from forgestra.maintenance import review, runtime_maintenance
            from forgestra.verification import plain_file

            result = (
                review(strict_json_loads(plain_file(args.evidence, 64000)))
                if args.evidence
                else runtime_maintenance()
            )
        elif args.command == "repair":
            from forgestra.repair import runtime_repair

            result = runtime_repair()
        elif args.command in {"adopt", "install"}:
            from forgestra.adoption import plan as adoption_plan, runtime_install

            result = (
                adoption_plan(args.root, args.action, args.factory_version, configuration)
                if args.command == "adopt"
                else runtime_install()
            )
        elif args.command in {"sync", "sync-baseline", "sync-targets"}:
            from forgestra import synchronization as sync
            from forgestra.verification import plain_file

            if args.command == "sync-targets":
                result = sync.enumerate_targets(strict_json_loads(plain_file(args.manifest, 32000)))
            elif args.command == "sync-baseline":
                result = sync.baseline(
                    args.source, strict_json_loads(plain_file(args.mapping, 32000))
                )
            elif all(
                getattr(args, name) is not None
                for name in ("source", "target", "mapping", "baseline")
            ):
                result = sync.plan(
                    args.source,
                    args.target,
                    strict_json_loads(plain_file(args.mapping, 32000)),
                    strict_json_loads(plain_file(args.baseline, 200000)),
                )
            else:
                result = sync.runtime_sync()
        elif args.command == "create":
            from forgestra.creation import plan as creation_plan, runtime_create
            from forgestra.verification import plain_file

            result = (
                creation_plan(strict_json_loads(plain_file(args.spec, 32000)))
                if args.spec
                else runtime_create()
            )
        elif args.command == "web":
            from forgestra.web import inspect as web_inspect
            from forgestra.verification import plain_file

            result = web_inspect(strict_json_loads(plain_file(args.schema, 32000)))
        else:
            result = {"status": "VALID", "privileged_automation": "DISABLED"}
        print(json.dumps(sanitized(result), sort_keys=True))
        if args.command == "sync-baseline":
            return 0
        return (
            1
            if result["status"]
            in {"BLOCKED", "ERROR", "UNKNOWN", "REVIEW_REQUIRED", "CONFLICT", "ESCALATED"}
            else 0
        )
    except (OSError, ValueError, TypeError, Blocked, RecursionError):
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "reason": "Invalid or unavailable local input",
                    "reason_code": "INVALID_INPUT_OR_CONFIGURATION",
                    "connectivity": "NOT_RUN",
                }
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
