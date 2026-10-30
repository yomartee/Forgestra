"""Read-only evidence sampling and schema-validated advisory assessment/plans."""

import hashlib
import json
from itertools import islice
from pathlib import Path

from forgestra.providers import ProviderConfig, Status, live, replay, sanitized
from forgestra.verification import bounded_file
from forgestra_safety import Blocked, relative_path

EXCLUDED = {".git", ".tools", ".venv", "node_modules", "__pycache__", "build", "dist"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sample(root: Path, max_bytes=200_000, max_file_bytes=32_000):
    """Inventory hashes describe a snapshot, never an attested Git commit."""
    if type(max_bytes) is not int or not 0 <= max_bytes <= 2_000_000:
        raise Blocked("BLOCKED: invalid sampling budget")
    if type(max_file_bytes) is not int or not 1 <= max_file_bytes <= 200_000:
        raise Blocked("BLOCKED: invalid file budget")
    root = root.absolute()
    if not root.is_dir():
        raise Blocked("BLOCKED: unavailable root")
    for entry in (root, *root.parents):
        if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
            raise Blocked("BLOCKED: linked root")
    inventory, used, entries = [], 0, 0

    def walk(directory, depth=0):
        nonlocal used, entries
        if depth > 100:
            raise Blocked("BLOCKED: directory depth limit exceeded")
        try:
            children = list(islice(directory.iterdir(), 10001 - entries))
        except OSError:
            if directory == root:
                raise Blocked("BLOCKED: root unreadable") from None
            inventory.append(
                {
                    "path": directory.relative_to(root).as_posix(),
                    "status": "EXCLUDED",
                    "reason": "UNREADABLE_DIRECTORY",
                }
            )
            return
        if len(children) + entries > 10000:
            raise Blocked("BLOCKED: inventory limit exceeded")
        for path in sorted(children, key=lambda p: p.name):
            entries += 1
            if entries > 10000:
                raise Blocked("BLOCKED: inventory limit exceeded")
            name = path.relative_to(root).as_posix()
            record = {"path": name, "status": "EXCLUDED", "reason": ""}
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                record["reason"] = "LINK"
            elif path.name in EXCLUDED or path.name.endswith(".egg-info"):
                record["reason"] = "EXCLUDED_SUBTREE"
            elif path.is_dir():
                walk(path, depth + 1)
                continue
            elif not path.is_file():
                record["reason"] = "SPECIAL_FILE"
            elif path.name.lower().startswith(".env") or path.name.lower().endswith(
                (".pem", ".key", ".p12", ".pfx")
            ):
                record["reason"] = "SENSITIVE_FILE"
            elif path.stat().st_size > max_file_bytes:
                record["reason"] = "FILE_LIMIT"
            elif used + path.stat().st_size > max_bytes:
                record["reason"] = "CONTEXT_LIMIT"
            else:
                try:
                    raw = bounded_file(path, max_file_bytes)
                    if len(raw) > max_file_bytes or used + len(raw) > max_bytes:
                        raise ValueError("changed size")
                    text = raw.decode("utf-8")
                    record.update(
                        status="INCLUDED",
                        reason="",
                        sha256=digest(raw),
                        bytes=len(raw),
                        lines=len(text.splitlines()),
                    )
                    used += len(raw)
                except (OSError, UnicodeError, ValueError, Blocked):
                    record["reason"] = "UNREADABLE_OR_BINARY"
            inventory.append(record)

    walk(root)
    encoded = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    return {
        "identity": {"git_commit": None, "kind": "SAMPLED_SNAPSHOT", "sha256": digest(encoded)},
        "files": inventory,
        "included_bytes": used,
        "limits": {"total_bytes": max_bytes, "file_bytes": max_file_bytes},
        "limitations": [
            "Excluded directories are recorded as subtrees; their descendants are unreviewed.",
            "No Git commit or complete repository coverage is attested.",
            "No target tests or code were executed; source text is not test evidence.",
            "Public report paths may be redacted; snapshot identity hashes the original inventory.",
        ],
    }


def text(value, limit=4000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError("invalid text")


def validate_assessment(document, coverage):
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "findings", "limitations"}
        or type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or not isinstance(document["findings"], list)
        or len(document["findings"]) > 100
        or not isinstance(document["limitations"], list)
        or len(document["limitations"]) > 100
    ):
        raise ValueError("invalid assessment")
    included = {f["path"]: f for f in coverage["files"] if f["status"] == "INCLUDED"}

    def evidence(refs):
        if not isinstance(refs, list) or not 1 <= len(refs) <= 100:
            raise ValueError("missing evidence")
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) != {"path", "sha256", "start", "end"}:
                raise ValueError("invalid evidence")
            path = "/".join(relative_path(ref["path"]))
            record = included.get(path)
            if (
                record is None
                or ref["sha256"] != record["sha256"]
                or type(ref["start"]) is not int
                or type(ref["end"]) is not int
                or not 1 <= ref["start"] <= ref["end"] <= record["lines"]
            ):
                raise ValueError("unverified evidence")

    ids = set()
    for finding in document["findings"]:
        if not isinstance(finding, dict) or set(finding) != {
            "id",
            "title",
            "severity",
            "evidence",
            "details",
        }:
            raise ValueError("invalid finding")
        text(finding["id"], 100)
        text(finding["title"])
        if finding["id"] in ids or finding["severity"] not in {"LOW", "MEDIUM", "HIGH"}:
            raise ValueError("duplicate or invalid finding")
        ids.add(finding["id"])
        evidence(finding["evidence"])
        details = finding["details"]
        if not isinstance(details, dict) or set(details) != {"summary", "scope_gaps"}:
            raise ValueError("invalid nested details")
        text(details["summary"])
        if not isinstance(details["scope_gaps"], list) or len(details["scope_gaps"]) > 100:
            raise ValueError("invalid gaps")
        for gap in details["scope_gaps"]:
            if not isinstance(gap, dict) or set(gap) != {"description", "evidence"}:
                raise ValueError("invalid gap")
            text(gap["description"])
            evidence(gap["evidence"])
    for limitation in document["limitations"]:
        text(limitation)
    return document


def assess(root, fixture=None, config=None):
    config = config if config is not None else ProviderConfig()
    config.validate()
    if config.provider != "offline":
        live(config)
    coverage = sample(Path(root))
    result = {
        "schema_version": 1,
        "status": Status.BLOCKED,
        "reason_code": "LIVE_PROVIDER_DISABLED",
        "provider": "NOT_RUN" if fixture is None else "OFFLINE_REPLAY",
        "live_provider": "NOT_RUN",
        "coverage": sanitized(coverage),
        "assessment": None,
        "completion_percentage": None,
        "target_tests": "UNTESTED",
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }
    if fixture is None:
        return result
    status, document, reason = replay(fixture)
    if status is None:
        try:
            validated = sanitized(validate_assessment(document, coverage))
            validate_assessment(validated, coverage)
            result["assessment"] = validated
            status = Status.FINDINGS if document["findings"] else Status.EMPTY
        except (ValueError, TypeError, KeyError, Blocked):
            status, reason = Status.ERROR, "INVALID_ASSESSMENT_SCHEMA"
    result.update(status=status, reason_code=reason)
    return result


class Improver:
    """Planning only: a finding, document or issue cannot earn implementation progress."""

    def run(self, root, fixture=None, config=None):
        result = assess(root, fixture, config)
        result["operation"] = "IMPROVEMENT_PLAN"
        result["applied_changes"] = []
        result["work_items"] = []
        result["publication"] = "BLOCKED"
        if result["assessment"] is not None:
            for finding in result["assessment"]["findings"]:
                material = {"source": result["coverage"]["identity"], "finding": finding}
                key = digest(json.dumps(material, sort_keys=True).encode())
                result["work_items"].append(
                    {"key": key, "finding_id": finding["id"], "status": "PROPOSED"}
                )
        return result
