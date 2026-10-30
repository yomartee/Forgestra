"""Single-host authored-fixture sync journal; never runtime scheduling authority."""

from contextlib import contextmanager
from contextvars import ContextVar
import hmac
import hashlib
from pathlib import Path
import secrets
import sqlite3
import uuid

import forgestra_safety as safety
from forgestra.synchronization import checkpoint, digest, encoded

_CONTROL: ContextVar[tuple[Path, bytes] | None] = ContextVar("sync_fixture_control", default=None)


def key():
    checkpoint()
    control = _CONTROL.get()
    if control is None or control[0] != safety._LOCAL_OUTPUT_PARENT.get():
        raise safety.Blocked("BLOCKED: issued sync control scope required")
    return control[1]


def fingerprint(proposal):
    return digest(encoded(proposal))


def policy_hash():
    from forgestra import synchronization
    from forgestra.verification import bounded_file

    return digest(
        encoded(
            [
                digest(bounded_file(Path(p)))
                for p in (__file__, synchronization.__file__, safety.__file__)
            ]
        )
    )


def signature(document):
    return hmac.new(key(), encoded(document), hashlib.sha256).hexdigest()


@contextmanager
def fixture_control():
    parent = safety._LOCAL_OUTPUT_PARENT.get()
    checkpoint()
    if parent is None or _CONTROL.get() is not None:
        raise safety.Blocked("BLOCKED: fresh private sync scope required")
    token = _CONTROL.set((parent, secrets.token_bytes(32)))
    try:
        yield
    finally:
        _CONTROL.reset(token)


def approval(proposal):
    key()
    if (
        proposal.get("status") != "PLANNED_LOCAL"
        or proposal.get("conflicts") != []
        or proposal.get("mapping", {}).get("opted_in") is not True
        or proposal.get("mapping", {}).get("source_repository") != "yomartee/sync-fixture-upstream"
        or proposal.get("mapping", {}).get("target_repository")
        != "yomartee/sync-fixture-downstream"
    ):
        raise safety.Blocked("BLOCKED: conflict-free opted-in authored fixture required")
    parent = safety._LOCAL_OUTPUT_PARENT.get()
    if parent is None:
        raise safety.Blocked("BLOCKED: private sync parent missing")
    if proposal.get("source_root") != str(parent / "sync-source") or proposal.get(
        "target_root"
    ) != str(parent / "sync-target"):
        raise safety.Blocked("BLOCKED: authored fixture roots required")
    return signature({"plan": fingerprint(proposal), "policy": policy_hash()})


def authorized(proposal, proof):
    if not isinstance(proof, str) or not hmac.compare_digest(approval(proposal), proof):
        raise safety.Blocked("BLOCKED: stale or unapproved sync plan")


class Journal:
    def __init__(self):
        key()
        parent = safety._LOCAL_OUTPUT_PARENT.get()
        if parent is None:
            raise safety.Blocked("BLOCKED: private sync parent missing")
        self.parent = parent
        path = self.parent / "sync.sqlite"
        if path.is_symlink() or path.is_junction():
            raise safety.Blocked("BLOCKED: linked sync journal")
        self.db = sqlite3.connect(path, timeout=0.2, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, plan TEXT UNIQUE NOT NULL, "
            "target TEXT NOT NULL, status TEXT NOT NULL, receipt TEXT, proof TEXT)"
        )
        self.db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS active_target ON runs(target) "
            "WHERE status IN ('RESERVED','EXECUTING')"
        )

    def scope(self):
        key()
        if self.parent != safety._LOCAL_OUTPUT_PARENT.get():
            raise safety.Blocked("BLOCKED: sync journal scope changed")

    def close(self):
        self.db.close()

    def receipt(self, row):
        if row[1] not in {
            "RESERVED",
            "EXECUTING",
            "READY_FOR_LOCAL_REVIEW",
            "NOOP",
            "FAILED",
            "CANCELLED",
        }:
            raise safety.Blocked("BLOCKED: unknown sync status")
        receipt = safety.strict_json_loads(row[2]) if row[2] else None
        if row[1] in {"READY_FOR_LOCAL_REVIEW", "NOOP"}:
            if (
                not isinstance(receipt, dict)
                or receipt.get("plan_sha256") != row[0]
                or receipt.get("status") != row[1]
                or receipt.get("publication") != "BLOCKED"
                or receipt.get("run_id") != row[4]
                or not isinstance(row[3], str)
                or not hmac.compare_digest(signature(receipt), row[3])
            ):
                raise safety.Blocked("BLOCKED: unverified cached sync outcome")
        if row[1] not in {"READY_FOR_LOCAL_REVIEW", "NOOP"} and receipt is not None:
            raise safety.Blocked("BLOCKED: unexpected non-success sync receipt")
        return receipt

    def reserve(self, run_id, proposal, proof):
        self.scope()
        authorized(proposal, proof)
        if not isinstance(run_id, str) or str(uuid.UUID(run_id)) != run_id:
            raise safety.Blocked("BLOCKED: sync run UUID required")
        plan_hash = fingerprint(proposal)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT plan,status,receipt,proof,run_id FROM runs WHERE run_id=?", (run_id,)
            ).fetchone()
            if row and row[0] != plan_hash:
                raise safety.Blocked("BLOCKED: changed plan reused run ID")
            if row is None:
                row = self.db.execute(
                    "SELECT plan,status,receipt,proof,run_id FROM runs WHERE plan=?", (plan_hash,)
                ).fetchone()
            if row:
                receipt = self.receipt(row)
                self.db.execute("COMMIT")
                return {
                    "status": "DUPLICATE" if receipt is not None else "NEEDS_RECONCILIATION",
                    "previous_status": row[1],
                    "receipt": receipt,
                }
            history = self.db.execute(
                "SELECT plan,status,receipt,proof,run_id FROM runs WHERE target=?",
                (proposal["mapping"]["target_repository"],),
            ).fetchmany(65)
            if len(history) >= 64:
                raise safety.Blocked("BLOCKED: sync journal history limit")
            for previous in history:
                self.receipt(previous)
            self.db.execute(
                "INSERT INTO runs VALUES(?,?,?,?,NULL,NULL)",
                (run_id, plan_hash, proposal["mapping"]["target_repository"], "RESERVED"),
            )
            self.db.execute("COMMIT")
            return {"status": "RESERVED"}
        except (sqlite3.Error, safety.Blocked, ValueError, TypeError):
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise safety.Blocked("BLOCKED: duplicate, locked or invalid sync run") from None

    def claim(self, run_id, proposal, proof):
        self.scope()
        authorized(proposal, proof)
        count = self.db.execute(
            "UPDATE runs SET status='EXECUTING' WHERE run_id=? AND plan=? AND status='RESERVED'",
            (run_id, fingerprint(proposal)),
        ).rowcount
        if count != 1:
            raise safety.Blocked("BLOCKED: sync run already claimed or absent")

    def require_executing(self, run_id, proposal, proof):
        self.scope()
        authorized(proposal, proof)
        row = self.db.execute("SELECT plan,status FROM runs WHERE run_id=?", (run_id,)).fetchone()
        if row != (fingerprint(proposal), "EXECUTING"):
            raise safety.Blocked("BLOCKED: active sync claim required")

    def finish(self, run_id, proposal, proof, status, receipt=None):
        self.require_executing(run_id, proposal, proof)
        if status not in {"READY_FOR_LOCAL_REVIEW", "NOOP", "FAILED", "CANCELLED"}:
            raise safety.Blocked("BLOCKED: unsupported terminal sync state")
        receipt_proof = None
        if status in {"READY_FOR_LOCAL_REVIEW", "NOOP"}:
            if (
                not isinstance(receipt, dict)
                or receipt.get("plan_sha256") != fingerprint(proposal)
                or receipt.get("status") != status
                or receipt.get("publication") != "BLOCKED"
                or receipt.get("run_id") != run_id
                or (status == "NOOP") != (proposal.get("changes") == [])
            ):
                raise safety.Blocked("BLOCKED: matching verified sync receipt required")
            verified = receipt.get("verification_proof")
            body = {k: v for k, v in receipt.items() if k != "verification_proof"}
            if not isinstance(verified, str) or not hmac.compare_digest(signature(body), verified):
                raise safety.Blocked("BLOCKED: trusted candidate verification required")
            receipt_proof = signature(receipt)
        elif receipt is not None:
            raise safety.Blocked("BLOCKED: failed/cancelled sync cannot claim success")
        count = self.db.execute(
            "UPDATE runs SET status=?,receipt=?,proof=? "
            "WHERE run_id=? AND plan=? AND status='EXECUTING'",
            (
                status,
                encoded(receipt).decode() if receipt else None,
                receipt_proof,
                run_id,
                fingerprint(proposal),
            ),
        ).rowcount
        if count != 1:
            raise safety.Blocked("BLOCKED: sync claim changed before completion")
