"""Read-only three-way synchronization. Baseline data never grants write authority."""

import hashlib
import json
from pathlib import Path
import re
import uuid

import forgestra_safety as safety
from forgestra.adoption import checkpoint, read_tree, tree_hash


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mapping(value):
    checkpoint()
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schema_version",
            "mapping_id",
            "source_repository",
            "target_repository",
            "opted_in",
            "paths",
        }
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["mapping_id"], str)
        or str(uuid.UUID(value["mapping_id"])) != value["mapping_id"]
        or type(value["opted_in"]) is not bool
    ):
        raise safety.Blocked("BLOCKED: invalid versioned synchronization mapping")
    for key in ("source_repository", "target_repository"):
        if not isinstance(value[key], str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,38}/[a-z][a-z0-9-]{0,62}", value[key]
        ):
            raise safety.Blocked("BLOCKED: invalid repository identity")
    if value["source_repository"] == value["target_repository"]:
        raise safety.Blocked("BLOCKED: distinct repositories required")
    paths = value["paths"]
    if not isinstance(paths, list) or not 1 <= len(paths) <= 8:
        raise safety.Blocked("BLOCKED: explicit bounded paths required")
    seen: dict[str, list[str]] = {"source": [], "target": []}
    for pair in paths:
        if not isinstance(pair, dict) or set(pair) != {"source", "target"}:
            raise safety.Blocked("BLOCKED: invalid path mapping")
        for key in seen:
            name = pair[key]
            safety.relative_path(name)
            if safety.protected(name) or any(
                name.casefold() == old
                or name.casefold().startswith(old + "/")
                or old.startswith(name.casefold() + "/")
                for old in seen[key]
            ):
                raise safety.Blocked("BLOCKED: protected or overlapping mapping")
            seen[key].append(name.casefold())
    if safety.redact(encoded(value).decode()) != encoded(value).decode():
        raise safety.Blocked("BLOCKED: sensitive mapping")
    return json.loads(encoded(value))


def translated(name, config):
    for pair in config["paths"]:
        if name.startswith(pair["source"] + "/"):
            return pair["target"] + name.removeprefix(pair["source"])
    return None


def selected(tree, config):
    result = {}
    for pair in config["paths"]:
        if pair["source"] not in tree["directories"]:
            raise safety.Blocked("BLOCKED: source mapping directory missing")
    for name, data in tree["files"].items():
        target = translated(name, config)
        if target is not None:
            if safety.protected(name) or safety.protected(target):
                raise safety.Blocked("BLOCKED: protected mapped source")
            if safety.redact(data.decode("utf-8", errors="replace")) != data.decode(
                "utf-8", errors="replace"
            ):
                raise safety.Blocked("BLOCKED: sensitive mapped content")
            result[name] = data
    return result


def baseline(source, config):
    """Emit a persisted-baseline document for review; never writes its own input."""
    config = mapping(config)
    return baseline_tree(read_tree(source), config)


def baseline_tree(tree, config):
    files = selected(tree, config)
    body = {
        "schema_version": 1,
        "mapping_sha256": digest(encoded(config)),
        "source_snapshot_sha256": tree_hash(tree),
        "source_commit": None,
        "commit_verification": "NOT_RUN",
        "ownership_authority": "DECLARATION_ONLY",
        "files": {n: digest(data) for n, data in sorted(files.items())},
        "ownership": {translated(n, config): n for n in sorted(files)},
    }
    return {**body, "baseline_sha256": digest(encoded(body))}


def validate_baseline(value, config):
    keys = {
        "schema_version",
        "mapping_sha256",
        "source_snapshot_sha256",
        "source_commit",
        "commit_verification",
        "ownership_authority",
        "files",
        "ownership",
        "baseline_sha256",
    }
    if not isinstance(value, dict) or set(value) != keys:
        raise safety.Blocked("BLOCKED: missing or invalid source baseline")
    body = {k: v for k, v in value.items() if k != "baseline_sha256"}
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["mapping_sha256"] != digest(encoded(config))
        or value["baseline_sha256"] != digest(encoded(body))
        or value["source_commit"] is not None
        or value["commit_verification"] != "NOT_RUN"
        or value["ownership_authority"] != "DECLARATION_ONLY"
        or not isinstance(value["files"], dict)
        or len(value["files"]) > 512
        or not isinstance(value["source_snapshot_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["source_snapshot_sha256"])
    ):
        raise safety.Blocked("BLOCKED: baseline identity or checksum mismatch")
    folded: set[str] = set()
    for name, sha in value["files"].items():
        safety.relative_path(name)
        target = translated(name, config)
        if (
            target is None
            or safety.protected(name)
            or safety.protected(target)
            or any(
                name.casefold() == n
                or name.casefold().startswith(n + "/")
                or n.startswith(name.casefold() + "/")
                for n in folded
            )
            or not isinstance(sha, str)
            or not re.fullmatch(r"[0-9a-f]{64}", sha)
        ):
            raise safety.Blocked("BLOCKED: invalid baseline ownership")
        folded.add(name.casefold())
    if value["ownership"] != {translated(n, config): n for n in value["files"]}:
        raise safety.Blocked("BLOCKED: baseline ownership disagrees with mapping")
    return value


def roots(source, target):
    source, target = Path(source).absolute(), Path(target).absolute()
    # Validate ancestors/links before resolving; never normalize a link into acceptance.
    left, right = read_tree(source), read_tree(target)
    source, target = source.resolve(), target.resolve()
    if source == target or source.is_relative_to(target) or target.is_relative_to(source):
        raise safety.Blocked("BLOCKED: source and target roots overlap")
    return source, target, left, right


def plan(source, target, config, previous):
    checkpoint()
    config = mapping(config)
    previous = validate_baseline(previous, config)
    source, target, left, right = roots(source, target)
    return compare_trees(source, target, left, right, config, previous)


def compare_trees(source, target, left, right, config, previous):
    current = selected(left, config)
    changes, conflicts, preserved, unchanged = [], [], [], []
    target_names = set(right["files"]) | set(right["directories"])
    sources = set(previous["files"]) | set(current)
    managed_targets = {translated(n, config) for n in sources}
    for name in sorted(sources):
        destination = translated(name, config)
        old = previous["files"].get(name)
        upstream = digest(current[name]) if name in current else None
        downstream = digest(right["files"][destination]) if destination in right["files"] else None
        if old is None:
            if downstream is not None:
                conflicts.append({"path": destination, "reason": "UNOWNED_DESTINATION"})
                continue
            action = "add"
        elif upstream == downstream:
            unchanged.append(destination)
            continue
        elif upstream == old:
            preserved.append({"path": destination, "reason": "DOWNSTREAM_ONLY_CHANGE"})
            continue
        elif downstream == old:
            action = "delete" if upstream is None else "update"
        else:
            conflicts.append({"path": destination, "reason": "DIVERGENT_THREE_WAY_CHANGE"})
            continue
        collision = any(
            entry.casefold() == destination.casefold()
            and entry != destination
            or entry.casefold() == destination.casefold()
            and entry in right["directories"]
            or destination.casefold().startswith(entry.casefold() + "/")
            and entry in right["files"]
            or destination.casefold().startswith(entry.casefold() + "/")
            and not destination.startswith(entry + "/")
            or entry.casefold().startswith(destination.casefold() + "/")
            for entry in target_names
        )
        if collision or safety.protected(destination):
            conflicts.append({"path": destination, "reason": "UNSAFE_DESTINATION_COLLISION"})
            continue
        changes.append(
            {
                "path": destination,
                "source": name,
                "operation": action,
                "before_sha256": downstream,
                "after_sha256": upstream,
            }
        )
    for name in sorted(set(right["files"]) - managed_targets):
        preserved.append({"path": name, "reason": "UNOWNED_TARGET_FILE"})
    from forgestra.sync_control import policy_hash

    result = {
        "policy_sha256": policy_hash(),
        "status": "CONFLICT" if conflicts else "PLANNED_LOCAL",
        "schema_version": 1,
        "mapping": config,
        "baseline_sha256": previous["baseline_sha256"],
        "source_root": str(source),
        "target_root": str(target),
        "source_snapshot_sha256": tree_hash(left),
        "target_snapshot_sha256": tree_hash(right),
        "source_commit": None,
        "commit_verification": "NOT_RUN",
        "changes": changes,
        "conflicts": conflicts,
        "preserved": preserved,
        "unchanged": unchanged,
        "review_required": True,
        "risk_tier": safety.classify_diff(
            [
                {
                    "path": c["path"],
                    "operation": "modify" if c["operation"] == "update" else c["operation"],
                }
                for c in changes
            ]
        ),
        "target_execution": "DISABLED",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }
    if safety.redact(encoded(result).decode()) != encoded(result).decode():
        raise safety.Blocked("BLOCKED: sensitive plan metadata")
    return result


def enumerate_targets(value):
    checkpoint()
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "targets"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or not isinstance(value["targets"], list)
        or len(value["targets"]) > 32
    ):
        raise safety.Blocked("BLOCKED: invalid target manifest")
    configs = [mapping(v) for v in value["targets"]]
    for key in ("mapping_id", "target_repository"):
        if len({c[key] for c in configs}) != len(configs):
            raise safety.Blocked("BLOCKED: duplicate synchronization target")
    return {
        "status": "PLANNED_LOCAL",
        "targets": [c for c in configs if c["opted_in"]],
        "execution": "DISABLED",
        "publication": "BLOCKED",
        "side_effects": [],
    }


def runtime_sync():
    return {
        "status": "BLOCKED",
        "reason_code": "RUNTIME_SYNCHRONIZATION_DISABLED",
        "privileged_automation": "DISABLED",
        "publication": "BLOCKED",
        "side_effects": [],
    }
