"""Public product inputs and finite upload schema, never publication authority."""

import hashlib
import json
import base64
import csv
import io
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
import posixpath
import re
from urllib.parse import unquote, urlsplit
import tarfile
import zipfile

from forgestra_safety import Blocked, strict_json_loads
from forgestra.verification import bounded_file

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = "FORGESTRA_PUBLIC_PRODUCT_V1"
UPLOAD = ("summary.json", "artifacts.json", "sbom.json")
FIXTURE_SHA = "ad067bade757cc9fe00388aaba39a084e36aca4847fc91fea8f4e38955c04576"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def relative(name):
    if (
        not isinstance(name, str)
        or not name
        or "\\" in name
        or ":" in name
        or PurePosixPath(name).is_absolute()
        or any(p in {"", ".", ".."} for p in name.split("/"))
        or any(ord(c) < 32 or ord(c) == 127 for c in name)
    ):
        raise Blocked("BLOCKED: public relative path")
    return name


def containment(root=ROOT):
    data = bounded_file(Path(root) / "tests/fixtures/public/containment.json")
    if hashlib.sha256(data).hexdigest() != FIXTURE_SHA:
        raise Blocked("BLOCKED: public fixture integrity")
    value = strict_json_loads(data.decode())
    if value["origin"] != "AUTHORED_ENTRYPOINT_TEST_INVENTORY_NOT_HISTORICAL_EVIDENCE":
        raise Blocked("BLOCKED: public fixture origin")
    return value["inventory"]


def source_paths(root=ROOT):
    value = strict_json_loads(bounded_file(Path(root) / "config/public-source.json").decode())
    if (
        not isinstance(value, dict)
        or set(value) != {"profile", "paths"}
        or value["profile"] != PUBLIC
    ):
        raise Blocked("BLOCKED: public source profile")
    names = value["paths"]
    if not isinstance(names, list) or not names or len(names) > 4096:
        raise Blocked("BLOCKED: public source inventory")
    if (
        any(not isinstance(n, str) for n in names)
        or names != sorted(set(names))
        or len({n.casefold() for n in names}) != len(names)
    ):
        raise Blocked("BLOCKED: ambiguous public inventory")
    for name in names:
        relative(name)
        folded = name.casefold()
        if (
            folded.startswith(
                ("docs/engineering/", "docs/audit/", "docs/archive/", ".tools/", ".git/")
            )
            or "owner_decisions" in folded
            or any(c in name for c in "*?[]")
            or any(
                p in {".env", "node_modules", "__pycache__", ".venv", "build", "dist"}
                or p.endswith(".egg-info")
                for p in folded.split("/")
            )
        ):
            raise Blocked("BLOCKED: private input in public inventory")
    return names


def inventory(root=ROOT):
    root = Path(root)
    names = source_paths(root)
    discovered = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            if path.is_symlink() or path.is_junction():
                raise Blocked("BLOCKED: linked public source")
            if path.name == "__pycache__" or path == root / "scripts/forgestra.egg-info":
                continue
            if path.parent == root and path.name in {".git", ".tools", ".venv", "build", "dist"}:
                continue
            if path.is_dir():
                pending.append(path)
            elif path.is_file():
                discovered.add(path.relative_to(root).as_posix())
    if discovered != set(names):
        raise Blocked("BLOCKED: public tree differs from positive inventory")
    return {
        name: {
            "sha256": hashlib.sha256(bounded_file(root / name, 8_000_000)).hexdigest(),
            "size": (root / name).stat().st_size,
            "mode": "100644",
            "type": "blob",
        }
        for name in names
    }


def inspect_distributions(root, wheel, sdist):
    """Exact authored source payload, finite generated metadata and wheel RECORD."""
    root = Path(root)
    names = source_paths(root)
    source = {n: bounded_file(root / n, 8_000_000) for n in names}
    prefix = "forgestra-0.2.0.dev0.dist-info/"
    expected = {
        n.removeprefix("src/"): data for n, data in source.items() if n.startswith("src/forgestra/")
    }
    expected.update(
        {n: source["scripts/" + n] for n in ("forgestra_safety.py", "inspect_local.py")}
    )
    expected[prefix + "licenses/LICENSE"] = source["LICENSE"]
    metadata = {
        prefix + n for n in ("METADATA", "WHEEL", "entry_points.txt", "top_level.txt", "RECORD")
    }

    def bounded_members(items):
        if (
            len(items) > 4096
            or sum(i.file_size if hasattr(i, "file_size") else i.size for i in items) > 32_000_000
        ):
            raise Blocked("BLOCKED: oversized distribution")

    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        bounded_members(members)
        if (
            len(members) != len({i.filename for i in members})
            or {i.filename for i in members} != set(expected) | metadata
        ):
            raise Blocked("BLOCKED: wheel member set")
        payload = {}
        for item in members:
            relative(item.filename)
            if (
                item.is_dir()
                or (item.external_attr >> 16) & 0o170000 == 0o120000
                or item.file_size > 8_000_000
            ):
                raise Blocked("BLOCKED: unsafe wheel member")
            payload[item.filename] = archive.read(item)
        if any(payload[n] != data for n, data in expected.items()):
            raise Blocked("BLOCKED: wheel source bytes")
        rows = list(csv.reader(io.StringIO(payload[prefix + "RECORD"].decode("utf-8"))))
        if (
            len(rows) != len(payload)
            or any(len(r) != 3 for r in rows)
            or {r[0] for r in rows} != set(payload)
        ):
            raise Blocked("BLOCKED: wheel RECORD inventory")
        for name, digest, size in rows:
            if name == prefix + "RECORD":
                if digest or size:
                    raise Blocked("BLOCKED: wheel RECORD self hash")
            elif digest != "sha256=" + base64.urlsafe_b64encode(
                hashlib.sha256(payload[name]).digest()
            ).decode().rstrip("=") or size != str(len(payload[name])):
                raise Blocked("BLOCKED: wheel RECORD hash")
        package = BytesParser().parsebytes(payload[prefix + "METADATA"])
        if (
            package.get_all("Name") != ["forgestra"]
            or package.get_all("Version") != ["0.2.0.dev0"]
            or package.get_all("Requires-Python") != ["<3.15,>=3.14"]
            or sorted(package.get_all("Requires-Dist", []))
            != [
                'black==26.10.1; extra == "dev"',
                'flake8==7.4.1; extra == "dev"',
                'mypy==2.4.0; extra == "dev"',
            ]
        ):
            raise Blocked("BLOCKED: wheel runtime metadata")
    generated = {"PKG-INFO", "setup.cfg"} | {
        "scripts/forgestra.egg-info/" + n
        for n in (
            "PKG-INFO",
            "SOURCES.txt",
            "dependency_links.txt",
            "entry_points.txt",
            "requires.txt",
            "top_level.txt",
        )
    }
    with tarfile.open(sdist) as source_archive:
        entries = source_archive.getmembers()
        bounded_members(entries)
        if len(entries) != len({i.name for i in entries}):
            raise Blocked("BLOCKED: duplicate sdist member")
        files = {}
        for entry in entries:
            relative(entry.name)
            parts = entry.name.split("/")
            if (
                parts[0] != "forgestra-0.2.0.dev0"
                or not (entry.isdir() or entry.isfile())
                or entry.size > 8_000_000
            ):
                raise Blocked("BLOCKED: unsafe sdist member")
            if entry.isfile():
                name = "/".join(parts[1:])
                if name not in set(source) | generated:
                    raise Blocked("BLOCKED: unexpected sdist member")
                stream = source_archive.extractfile(entry)
                if stream is None:
                    raise Blocked("BLOCKED: unreadable sdist member")
                files[name] = stream.read(8_000_001)
        if set(files) != set(source) | generated or any(
            files[n] != data for n, data in source.items()
        ):
            raise Blocked("BLOCKED: missing or altered sdist source")
        if (
            files["setup.cfg"].replace(b"\r\n", b"\n")
            != b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
        ):
            raise Blocked("BLOCKED: generated sdist config")
    return {"wheel_members": sorted(payload), "sdist_members": sorted(i.name for i in entries)}


def absent_private(root=ROOT):
    root = Path(root)
    if any(
        (root / n).exists()
        for n in ("docs/engineering/evidence", "docs/audit", "OWNER_DECISIONS.md")
    ):
        raise Blocked("BLOCKED: clean public profile requires private archives absent")


def slug(text):
    text = re.sub(r"[`*_]", "", text).strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


def links(root, names):
    """Resolve every local Markdown link/case/heading against the projected tree."""
    root = Path(root)
    names = set(names)
    errors, count = [], 0
    for name in sorted(names):
        if not name.endswith(".md"):
            continue
        text = bounded_file(root / name).decode()
        text = re.sub(r"```.*?```", "", text, flags=re.S)
        for value in re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text):
            value = value.strip().strip("<>")
            parsed = urlsplit(value)
            if parsed.scheme:
                if parsed.scheme not in {"https", "mailto"}:
                    errors.append({"source": name, "reason": "UNSAFE_LINK_SCHEME"})
                continue
            count += 1
            target = (
                posixpath.normpath(posixpath.join(posixpath.dirname(name), unquote(parsed.path)))
                if parsed.path
                else name
            )
            if target not in names or parsed.path.startswith("/"):
                errors.append(
                    {"source": name, "target": target, "reason": "MISSING_OR_CASE_MISMATCH"}
                )
                continue
            if parsed.fragment:
                body = bounded_file(root / target).decode()
                headings = [slug(h) for h in re.findall(r"^#{1,6}\s+(.+?)\s*#*\s*$", body, re.M)]
                seen: dict[str, int] = {}
                anchors: set[str] = set()
                for heading in headings:
                    number = seen.get(heading, 0)
                    anchors.add(heading + ("-" + str(number) if number else ""))
                    seen[heading] = number + 1
                if unquote(parsed.fragment) not in anchors:
                    errors.append({"source": name, "target": target, "reason": "MISSING_ANCHOR"})
    return {"status": "PASSED" if not errors else "FAILED", "checked": count, "errors": errors}


def valid_summary(value):
    try:
        return (
            set(value)
            == {
                "profile",
                "status",
                "source_sha256",
                "tests",
                "checks",
                "publication",
                "private_replay",
                "live",
                "reason",
            }
            and value["profile"] == PUBLIC
            and value["status"] in {"PASSED_LOCAL", "FAILED"}
            and re.fullmatch(r"[0-9a-f]{64}", value["source_sha256"]) is not None
            and value["publication"] == "BLOCKED"
            and value["private_replay"] == value["live"] == "NOT_RUN"
            and value["reason"] in {"NONE", "PUBLIC_CHECK_FAILED"}
            and isinstance(value["checks"], list)
            and all(
                set(c) == {"name", "status"}
                and c["name"] in CHECKS
                and c["status"] in {"PASSED", "FAILED"}
                for c in value["checks"]
            )
            and len({c["name"] for c in value["checks"]}) == len(value["checks"])
            and type(value["tests"]) is int
            and value["tests"] >= 0
            and (
                value["status"] != "PASSED_LOCAL"
                or (
                    value["tests"] > 0
                    and {c["name"] for c in value["checks"]} == set(CHECKS)
                    and all(c["status"] == "PASSED" for c in value["checks"])
                    and value["reason"] == "NONE"
                )
            )
        )
    except (KeyError, TypeError, ValueError):
        return False


CHECKS = (
    "inner-ci",
    "packages",
    "installed-cli",
    "repair",
    "adoption",
    "web-creation",
    "sync",
    "maintenance",
    "mcp",
    "release",
    "links",
)

EMPTY_BOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [],
    "metadata": {"properties": [{"name": "forgestra:status", "value": "NOT_RUN"}]},
}


def validate_payloads(summary, artifacts, bom):
    from forgestra.release import sbom

    if not valid_summary(summary):
        raise Blocked("BLOCKED: public summary schema")
    if (
        not isinstance(artifacts, dict)
        or set(artifacts) != {"profile", "files", "license_approval"}
        or artifacts["profile"] != PUBLIC
        or artifacts["license_approval"] != "PENDING"
        or not isinstance(artifacts["files"], dict)
    ):
        raise Blocked("BLOCKED: public artifact schema")
    if summary["status"] == "PASSED_LOCAL" and set(artifacts["files"]) != {
        "core.whl",
        "source.tar.gz",
    }:
        raise Blocked("BLOCKED: missing built artifacts")
    for name, value in artifacts["files"].items():
        if (
            name not in {"core.whl", "source.tar.gz"}
            or not isinstance(value, dict)
            or set(value) != {"sha256", "bytes"}
            or not isinstance(value["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None
            or type(value["bytes"]) is not int
            or value["bytes"] <= 0
        ):
            raise Blocked("BLOCKED: public artifact entry")
    if summary["status"] == "FAILED" and canonical(bom) == canonical(EMPTY_BOM):
        return
    if canonical(bom) != canonical(sbom(ROOT)):
        raise Blocked("BLOCKED: public SBOM schema")


def export(directory, summary, artifacts, bom):
    """Only finite structured outputs; raw logs/argv/receipts never enter upload."""
    from acquire_tools import unlinked

    directory = Path(directory)
    unlinked(directory)
    directory.mkdir(parents=True, exist_ok=True)
    if list(directory.iterdir()):
        raise Blocked("BLOCKED: upload directory must be fresh")
    validate_payloads(summary, artifacts, bom)
    for name, value in zip(UPLOAD, (summary, artifacts, bom)):
        (directory / name).write_bytes(canonical(value) + b"\n")
    validate_upload(directory)


def validate_upload(directory):
    directory = Path(directory)
    if {p.name for p in directory.iterdir()} != set(UPLOAD):
        raise Blocked("BLOCKED: unexpected public upload contents")
    for path in directory.iterdir():
        bounded_file(path, 8_000_000)
    values = [
        strict_json_loads(bounded_file(directory / name, 8_000_000).decode()) for name in UPLOAD
    ]
    validate_payloads(*values)
    return list(UPLOAD)
