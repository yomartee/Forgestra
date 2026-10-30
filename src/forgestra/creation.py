"""PR 07 specification planning and trusted authored-fixture control only.

No runtime creator, provider, publisher or event dispatcher is enabled. In-process
fixture authority is a test boundary, not human approval or an OS sandbox.
"""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import uuid
from typing import Any

import forgestra_safety as safety
from forgestra import web
from forgestra.verification import bounded_file

COMPONENTS = ("react", "react-dom", "@refinedev/core")
_AUTHORITY: ContextVar[bytes | None] = ContextVar("creation_fixture_authority", default=None)
_AUTHORITY_PARENT: ContextVar[Path | None] = ContextVar("creation_authority_parent", default=None)
FIXTURE_SPEC: dict[str, Any] = {
    "schema_version": 1,
    "request_id": "07100000-0000-4000-8000-000000000001",
    "repository": "yomartee/forgestra-pr07-fixture",
    "frontend": {"repository": "yomartee/forgestra-pr07-fixture", "path": "."},
    "components": list(COMPONENTS),
    "domain": web.FIXTURE_SCHEMA,
}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def checkpoint():
    if os.environ.get("FORGESTRA_KILL_SWITCH", "0") != "0":
        raise safety.Blocked("BLOCKED: kill switch active")


def registry():
    from forgestra.component_registry import REGISTRY

    # A literal reviewed registry, not the illustrative YAML or caller configuration.
    return json.loads(canonical(REGISTRY))


def specification(value):
    checkpoint()
    keys = {"schema_version", "request_id", "repository", "frontend", "components", "domain"}
    if not isinstance(value, dict) or set(value) != keys:
        raise safety.Blocked("BLOCKED: explicit product specification required")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise safety.Blocked("BLOCKED: unsupported specification version")
    request = value["request_id"]
    if not isinstance(request, str) or str(uuid.UUID(request)) != request:
        raise safety.Blocked("BLOCKED: canonical request UUID required")
    repository = value["repository"]
    if (
        not isinstance(repository, str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,38}/[a-z][a-z0-9-]{0,62}", repository)
        or repository.split("/")[1].endswith(".git")
        or value["frontend"] != {"repository": repository, "path": "."}
        or value["components"] != list(COMPONENTS)
    ):
        raise safety.Blocked("BLOCKED: unsupported repository mapping or components")
    domain = web.schema(value["domain"])
    if safety.redact(canonical(value)) != canonical(value):
        raise safety.Blocked("BLOCKED: sensitive specification")
    return {**json.loads(canonical(value)), "domain": domain}


def files(value):
    spec = specification(value)
    emitted = web.render(spec["domain"])
    manifest = {
        "schema_version": 1,
        "request_id": spec["request_id"],
        "repository": spec["repository"],
        "components": registry(),
        "verification": "REQUIRED_BEFORE_LOCAL_REVIEW",
        "factory_schedules": "EXCLUDED",
        "distribution_rights": "NOT_CLEARED",
    }
    emitted.append({"path": "forgestra-components.json", "content": web.encode(manifest)})
    safety.validate_manifest(emitted)
    return emitted


def policy_hash():
    paths = (Path(__file__), Path(safety.__file__), Path(web.__file__))
    return digest(
        canonical(
            {"source": [digest(bounded_file(p)) for p in paths], "registry": registry()}
        ).encode()
    )


def plan(value):
    spec = specification(value)
    manifest = {f["path"]: digest(f["content"].encode()) for f in files(spec)}
    return {
        "status": "PLANNED_LOCAL",
        "schema_version": 1,
        "request_id": spec["request_id"],
        "repository": spec["repository"],
        "frontend": spec["frontend"],
        "specification_sha256": digest(canonical(spec).encode()),
        "files": manifest,
        "policy_sha256": policy_hash(),
        "components_sha256": digest(canonical(registry()).encode()),
        "products": 1,
        "approval": "REQUIRED_FROM_TRUSTED_CONTROL",
        "execution": "DISABLED",
        "publication": "BLOCKED",
        "frontend_events": [],
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }


@contextmanager
def fixture_authority():
    checkpoint()
    if safety._LOCAL_OUTPUT_PARENT.get() is None or _AUTHORITY.get() is not None:
        raise safety.Blocked("BLOCKED: fresh private fixture control required")
    token = _AUTHORITY.set(secrets.token_bytes(32))
    parent_token = _AUTHORITY_PARENT.set(safety._LOCAL_OUTPUT_PARENT.get())
    try:
        yield
    finally:
        _AUTHORITY.reset(token)
        _AUTHORITY_PARENT.reset(parent_token)


def approve_fixture(value):
    """Trusted harness only; cannot approve arbitrary products or runtime writes."""
    checkpoint()
    key = _AUTHORITY.get()
    spec = specification(value)
    if (
        key is None
        or _AUTHORITY_PARENT.get() != safety._LOCAL_OUTPUT_PARENT.get()
        or _AUTHORITY_PARENT.get() is None
        or spec["domain"] != web.FIXTURE_SCHEMA
        or spec["repository"]
        not in {FIXTURE_SPEC["repository"], FIXTURE_SPEC["repository"] + "-second"}
    ):
        raise safety.Blocked("BLOCKED: authored fixture only")
    return hmac.new(key, canonical(plan(spec)).encode(), hashlib.sha256).hexdigest()


def authorized(value, approval):
    expected = approve_fixture(value)
    if not isinstance(approval, str) or not hmac.compare_digest(expected, approval):
        raise safety.Blocked("BLOCKED: approval does not bind current specification and policy")


def verify_receipt(value, receipt):
    key = _AUTHORITY.get()
    if (
        key is None
        or not isinstance(receipt, dict)
        or _AUTHORITY_PARENT.get() != safety._LOCAL_OUTPUT_PARENT.get()
    ):
        raise safety.Blocked("BLOCKED: verification receipt required")
    proof = receipt.get("proof")
    body = {k: v for k, v in receipt.items() if k != "proof"}
    if (
        not isinstance(proof, str)
        or not hmac.compare_digest(
            proof, hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()
        )
        or body.get("plan_sha256") != digest(canonical(plan(value)).encode())
        or body.get("status") != "READY_FOR_LOCAL_REVIEW"
        or body.get("request_id") != value["request_id"]
        or body.get("repository") != value["repository"]
        or body.get("publication") != "BLOCKED"
        or body.get("frontend_events") != []
    ):
        raise safety.Blocked("BLOCKED: untrusted creation receipt")


class Ledger:
    """SQLite single-host fixture reservations. Failed/abandoned attempts stay charged.

    A nonterminal duplicate requires reconciliation and is never executed twice.
    The journal is outside the candidate, inaccessible through generated paths.
    """

    def __init__(self):
        checkpoint()
        parent = safety._LOCAL_OUTPUT_PARENT.get()
        if parent is None or _AUTHORITY.get() is None or _AUTHORITY_PARENT.get() != parent:
            raise safety.Blocked("BLOCKED: private fixture control required")
        self.path = parent / "creation.sqlite"
        if self.path.is_symlink() or self.path.is_junction():
            raise safety.Blocked("BLOCKED: linked journal")
        self.db = sqlite3.connect(self.path, timeout=0.2, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS requests("
            "request_id TEXT PRIMARY KEY, plan TEXT NOT NULL, repository TEXT UNIQUE NOT NULL, "
            "day TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT)"
        )

    def close(self):
        self.db.close()

    def check_scope(self):
        parent = safety._LOCAL_OUTPUT_PARENT.get()
        if parent is None or self.path != parent / "creation.sqlite":
            raise safety.Blocked("BLOCKED: journal outside current fixture")

    def require_reserved(self, value, approval):
        checkpoint()
        authorized(value, approval)
        parent = safety._LOCAL_OUTPUT_PARENT.get()
        if parent is None or self.path != parent / "creation.sqlite":
            raise safety.Blocked("BLOCKED: journal outside current fixture")
        fingerprint = digest(canonical(plan(value)).encode())
        row = self.db.execute(
            "SELECT plan,status FROM requests WHERE request_id=?", (value["request_id"],)
        ).fetchone()
        if row != (fingerprint, "RESERVED"):
            raise safety.Blocked("BLOCKED: active charged reservation required")

    def claim(self, value, approval):
        self.require_reserved(value, approval)
        checkpoint()
        changed = self.db.execute(
            "UPDATE requests SET status='EXECUTING' WHERE request_id=? AND status='RESERVED'",
            (value["request_id"],),
        ).rowcount
        if changed != 1:
            raise safety.Blocked("BLOCKED: creation already claimed")

    def require_executing(self, value, approval):
        checkpoint()
        authorized(value, approval)
        parent = safety._LOCAL_OUTPUT_PARENT.get()
        fingerprint = digest(canonical(plan(value)).encode())
        row = self.db.execute(
            "SELECT plan,status FROM requests WHERE request_id=?", (value["request_id"],)
        ).fetchone()
        if (
            parent is None
            or self.path != parent / "creation.sqlite"
            or row != (fingerprint, "EXECUTING")
        ):
            raise safety.Blocked("BLOCKED: active execution claim required")

    def reserve(self, value, approval):
        checkpoint()
        authorized(value, approval)
        self.check_scope()
        current = plan(value)
        fingerprint = digest(canonical(current).encode())
        day = datetime.now(timezone.utc).date().isoformat()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT plan,status,receipt FROM requests WHERE request_id=?",
                (current["request_id"],),
            ).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise safety.Blocked("BLOCKED: reused request ID with changed plan")
                if row[1] not in {
                    "RESERVED",
                    "EXECUTING",
                    "FAILED_VALIDATION",
                    "CANCELLED",
                    "READY_FOR_LOCAL_REVIEW",
                }:
                    raise safety.Blocked("BLOCKED: unknown persisted creation state")
                receipt = safety.strict_json_loads(row[2]) if row[2] else None
                if row[1] == "READY_FOR_LOCAL_REVIEW":
                    verify_receipt(value, receipt)
                elif receipt is not None:
                    raise safety.Blocked("BLOCKED: unexpected nonterminal receipt")
                self.db.execute("COMMIT")
                return {
                    "status": (
                        "DUPLICATE"
                        if row[1] == "READY_FOR_LOCAL_REVIEW"
                        else "NEEDS_RECONCILIATION"
                    ),
                    "previous_status": row[1],
                    "receipt": receipt,
                }
            charged = self.db.execute(
                "SELECT COUNT(*) FROM requests WHERE day=?", (day,)
            ).fetchone()[0]
            if charged >= 1:
                raise safety.Blocked("BLOCKED: daily creation budget exhausted")
            self.db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,NULL)",
                (current["request_id"], fingerprint, current["repository"], day, "RESERVED"),
            )
            self.db.execute("COMMIT")
            return {"status": "RESERVED", "products": 1, "day": day}
        except (sqlite3.Error, safety.Blocked, ValueError, TypeError):
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise safety.Blocked(
                "BLOCKED: reservation conflict, quota or changed request"
            ) from None

    def finish(self, value, approval, status, receipt=None):
        checkpoint()
        authorized(value, approval)
        self.check_scope()
        if status not in {"FAILED_VALIDATION", "CANCELLED", "READY_FOR_LOCAL_REVIEW"}:
            raise safety.Blocked("BLOCKED: unsupported creation state")
        if status == "READY_FOR_LOCAL_REVIEW":
            self.require_executing(value, approval)
            verify_receipt(value, receipt)
        elif receipt is not None:
            raise safety.Blocked("BLOCKED: receipt requires verified ready state")
        fingerprint = digest(canonical(plan(value)).encode())
        changed = self.db.execute(
            "UPDATE requests SET status=?,receipt=? "
            "WHERE request_id=? AND plan=? AND status IN ('RESERVED','EXECUTING')",
            (status, canonical(receipt) if receipt else None, value["request_id"], fingerprint),
        ).rowcount
        if changed != 1:
            raise safety.Blocked("BLOCKED: absent or terminal reservation")


def runtime_create():
    return {
        "status": "BLOCKED",
        "reason_code": "RUNTIME_CREATION_DISABLED",
        "publication": "BLOCKED",
        "frontend_events": [],
        "privileged_automation": "DISABLED",
        "side_effects": [],
    }


def validate_frontend_event(value, spec, tested_sha):
    """Validate proposed v1 event data; never proves publication or dispatches it.

    A future trusted publisher must independently verify repository/PR/commit IDs.
    Caller-supplied JSON, including a valid event, confers no publication authority.
    """
    spec = specification(spec)
    if not isinstance(tested_sha, str) or not re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}", tested_sha
    ):
        raise safety.Blocked("BLOCKED: tested commit required")
    expected = {
        "schema_version": 1,
        "event_type": "forgestra.product.published.v1",
        "request_id": spec["request_id"],
        "repository": spec["repository"],
        "frontend": spec["frontend"],
        "tested_sha": tested_sha,
        "idempotency_key": digest(
            canonical([spec["request_id"], spec["repository"], tested_sha]).encode()
        ),
    }
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value != expected
    ):
        raise safety.Blocked("BLOCKED: event schema, mapping or idempotency mismatch")
    return {
        "status": "VALID_DATA_ONLY",
        "dispatch": "DISABLED",
        "event_sha256": digest(canonical(value).encode()),
    }


def dispatch_frontend(_receipt=None):
    # No externally supplied receipt can enable a transport in this phase.
    return {
        "status": "BLOCKED",
        "reason_code": "VERIFIED_PUBLICATION_UNAVAILABLE",
        "event_schema_version": 1,
        "frontend_events": [],
        "side_effects": [],
    }
