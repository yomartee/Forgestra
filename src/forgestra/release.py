"""Read-only release assessment. No input can authorize publication or grant rights."""

import hashlib
import json
from pathlib import Path, PurePosixPath
import re

from forgestra_safety import Blocked, CAPABILITIES
from forgestra.verification import bounded_file

GATES = {
    "A": "EXPERIMENTAL",
    "B": "PRODUCTION_CORE",
    "C": "PRODUCTION_GENERATORS_FLEET",
}
BLOCKERS = (
    "OWNER_RIGHTS_AND_LICENSE_APPROVAL",
    "FULL_HISTORY_TAG_RELEASE_LOG_REVIEW",
    "PRIVATE_DISCLOSURE_ROUTE_TEST",
    "THIRD_PARTY_RIGHTS_AND_ADVISORY_REVIEW",
    "LIVE_REQUIRED_REVIEWS_AND_APP_PERMISSIONS",
    "HOSTED_CLEAN_ROOM_ACCEPTANCE",
    "TESTED_RELEASE_TAG_AND_ARTIFACT_BINDING",
    "MAINTAINER_PUBLICATION_APPROVAL",
)


def readiness(gate="A"):
    if not isinstance(gate, str) or gate not in GATES:
        raise Blocked("BLOCKED: explicit known release gate required")
    return {
        "status": "BLOCKED",
        "mode": "READ_ONLY_RELEASE_ASSESSMENT",
        "gate": gate,
        "target": GATES[gate],
        "blockers": list(BLOCKERS)
        + (["REAL_SANDBOX_RUNTIME_AND_RECOVERY_ACCEPTANCE"] if gate != "A" else []),
        "license": "OWNER_DECISION_REQUIRED",
        "publication": "BLOCKED",
        "privileged_automation": "DISABLED",
        "capabilities": {n: "DISABLED" for n in sorted(CAPABILITIES)},
        "live_checks": "NOT_RUN",
        "side_effects": [],
    }


def files(root, names):
    """Hash a literal inventory, rejecting ambiguous paths/links/oversized files."""
    root = Path(root).absolute()
    if not isinstance(names, list) or not names or len(names) > 4096:
        raise Blocked("BLOCKED: invalid release inventory")
    result = {}
    seen = set()
    for name in names:
        if (
            not isinstance(name, str)
            or not name
            or "\\" in name
            or ":" in name
            or any(p in {"", ".", ".."} for p in name.split("/"))
            or PurePosixPath(name).is_absolute()
            or name.casefold() in seen
        ):
            raise Blocked("BLOCKED: ambiguous release path")
        result[name] = hashlib.sha256(bounded_file(root / name, 8_000_000)).hexdigest()
        seen.add(name.casefold())
    return result


def scan(root, names):
    """Limited high-signal snapshot scan; never returns matched values or lines."""
    hashes = files(root, names)
    patterns = {
        "PRIVATE_KEY": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "GITHUB_TOKEN": rb"gh[pousr]_[A-Za-z0-9]{30,255}",
        "AWS_ACCESS_KEY_ID": rb"AKIA[0-9A-Z]{16}",
    }
    findings = []
    for name in hashes:
        data = bounded_file(Path(root) / name, 8_000_000)
        if hashlib.sha256(data).hexdigest() != hashes[name]:
            raise Blocked("BLOCKED: release scan input changed")
        for kind, pattern in patterns.items():
            if re.search(pattern, data):
                # Even a sensitive filename is represented only by its digest.
                findings.append(
                    {
                        "path_sha256": hashlib.sha256(name.encode()).hexdigest(),
                        "kind": kind,
                        "file_sha256": hashes[name],
                    }
                )
    return {
        "status": "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCHES",
        "files": len(hashes),
        "scanned_manifest_sha256": hashlib.sha256(
            json.dumps(hashes, sort_keys=True).encode()
        ).hexdigest(),
        "findings": findings,
        "coverage": "LIMITED_HIGH_SIGNAL_CURRENT_SNAPSHOT_ONLY",
        "history_tags_assets_logs": "NOT_RUN",
        "confidentiality_clearance": "NOT_GRANTED",
    }


def sbom(root):
    """CycloneDX inventory of locked inputs; not advisory or license clearance."""
    root = Path(root)
    components = []
    for name in ("build", "dev", "mcp"):
        text = (
            bounded_file(root / ("requirements/" + name + ".lock")).decode().replace("\r\n", "\n")
        )
        for line in text.replace("\\\n", " ").splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            match = re.match(r"([A-Za-z0-9_.-]+)==([^ ;]+)", line)
            digests = re.findall(r"--hash=sha256:([0-9a-f]{64})", line)
            if not match or not digests:
                raise Blocked("BLOCKED: unpinned SBOM Python input")
            package, version = match.groups()
            components.append(
                {
                    "type": "library",
                    "name": package,
                    "version": version,
                    "bom-ref": name + ":" + package,
                    "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(set(digests))],
                    "properties": [{"name": "forgestra:scope", "value": name}],
                }
            )
    lock = json.loads(bounded_file(root / "src/forgestra/web_assets/package-lock.json"))
    for path, value in sorted(lock["packages"].items()):
        if not path:
            continue
        if not value.get("version") or not value.get("integrity", "").startswith("sha512-"):
            raise Blocked("BLOCKED: unpinned web SBOM input")
        components.append(
            {
                "type": "library",
                "name": path.rsplit("node_modules/", 1)[-1],
                "version": value["version"],
                "bom-ref": "web:" + path,
                "properties": [{"name": "forgestra:npm-integrity", "value": value["integrity"]}],
            }
        )
    toolchain = json.loads(bounded_file(root / "config/toolchain.json"))
    for runtime in ("python", "node"):
        components.append(
            {
                "type": "application",
                "name": runtime,
                "version": toolchain[runtime],
                "bom-ref": "runtime:" + runtime,
            }
        )
    for name, item in toolchain["actions"].items():
        components.append(
            {
                "type": "application",
                "name": name,
                "version": item["sha"],
                "bom-ref": "action:" + name,
            }
        )
    for platform, tools in toolchain["native"].items():
        for name, item in tools.items():
            components.append(
                {
                    "type": "application",
                    "name": name,
                    "bom-ref": "native:" + platform + ":" + name,
                    "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
                }
            )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": components,
        "metadata": {
            "properties": [
                {
                    "name": "forgestra:coverage",
                    "value": (
                        "locked Python tooling/optional SDK and authored web fixture; "
                        "runtime/native/action pins; core runtime dependencies empty"
                    ),
                },
                {"name": "forgestra:advisory-review", "value": "NOT_RUN"},
                {"name": "forgestra:license-clearance", "value": "NOT_GRANTED"},
            ]
        },
    }
