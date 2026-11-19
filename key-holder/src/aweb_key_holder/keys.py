"""Private org keys and the durable signature record; never a sign-bytes port.

Deploy this directory only into the holder process. The calling application
must receive public descriptors/results and no mount or database role here.
"""

from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager
from enum import Enum
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Self, TypedDict
from uuid import uuid4

from approval_service.canonical import canonical, parse
from approval_service.gate import Policy
from awid.controller_signing import (
    ControllerDescriptor,
    ControllerObjectRequest,
    ControllerRequest,
    ControllerSigningContext,
)
from awid.did import did_from_public_key, did_key_from_signing_key, generate_keypair
from awid.signing import sign_message
from nacl.public import PublicKey, SealedBox

from .refusals import Refusal, Refused

if TYPE_CHECKING:
    from awid.controller_signing import ControllerOperation


# Explicit holder rules, not an automatic import of every future SDK operation.
# Destructive key changes and human issuance have separate authority paths.
ROUTINE: frozenset[ControllerOperation] = frozenset(
    {
        "namespace_register",
        "namespace_update",
        "team_register",
        "team_visibility",
        "certificate_register",
        "certificate_revoke",
        "address_register",
        "address_update",
        "address_delete",
        "address_reassign",
        "team_read",
        "certificate_list",
        "member_read",
        "revocations_read",
        "server_publish",
        "team_certificate_issue",
        "team_server_sign",
        "address_replacement",
        "address_claim",
        "address_claim_proof",
        "namespace_id_issue",
    }
)


class StorageKind(Enum):
    FILE = "file"
    DIRECTORY = "directory"


class PolicySource(Enum):
    ABSENT = "absent"
    EXPLICIT = "explicit"


class PriorApproval(Enum):
    UNRECORDED = "unrecorded"
    REQUIRED = "required"


class RetiredPerson(TypedDict):
    person: str
    state: Literal["retired"]


class AuditEntry(TypedDict):
    sequence: int
    operation: str
    actor: str
    approval: str | None
    key: str
    generation: int
    payload: str
    signature: str
    at: int


def _private(path: Path, mode: int, *, kind: StorageKind = StorageKind.FILE) -> None:
    try:
        info = path.lstat()
    except OSError as error:
        raise Refused(Refusal.STORAGE_UNAVAILABLE) from error
    kind_ok = (
        stat.S_ISDIR(info.st_mode)
        if kind is StorageKind.DIRECTORY
        else stat.S_ISREG(info.st_mode)
    )
    if not kind_ok or stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid():
        raise Refused(Refusal.STORAGE_PERMISSIONS)


class KeyStore:
    """Private custody, explicit migrations and an append-only signature audit."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).absolute()

    @classmethod
    def create(cls, directory: str | Path, *, organisation: str) -> Self:
        """Create a private namespace key store and its ordered current schema."""
        seed, public_key = generate_keypair()
        descriptor = ControllerDescriptor(
            "namespace",
            organisation,
            did_from_public_key(public_key),
            uuid4().hex,
            0,
        )
        store = cls(directory)
        try:
            store.directory.mkdir(mode=0o700)
        except FileExistsError as error:
            raise Refused(Refusal.ALREADY_INITIALIZED) from error
        _private(store.directory, 0o700, kind=StorageKind.DIRECTORY)
        database = store.directory / "holder.sqlite"
        fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(database) as db:
            db.executescript(
                files(__package__).joinpath("migrations/001_keys.sql").read_text()
            )
            db.execute(
                "INSERT INTO configuration VALUES (?, ?)",
                (organisation, secrets.token_bytes(32)),
            )
            db.execute(
                "INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?)",
                (
                    descriptor.key_reference,
                    "namespace",
                    "",
                    0,
                    descriptor.did_key,
                    seed,
                ),
            )
        store.migrate()
        return store

    @classmethod
    def open(cls, directory: str | Path) -> Self:
        """Open an initialized, current store without applying migrations."""
        store = cls(directory)
        with store.connection() as db:
            store.require_current_configuration(db)
            if db.execute("PRAGMA user_version").fetchone()[0] != 5:
                raise Refused(Refusal.SCHEMA_UNAVAILABLE)
            if db.execute("SELECT count(*) FROM configuration").fetchone()[0] != 1:
                raise Refused(Refusal.STORAGE_UNAVAILABLE)
        return store

    def migrate(self, *, policy: Policy | None = None) -> None:
        """Apply ordered private-schema migrations under an explicit policy."""
        with self.connection() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 1:
                db.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + files(__package__)
                    .joinpath("migrations/002_enrollment.sql")
                    .read_text()
                    + "\nCOMMIT;"
                )
                version = 2
            if version == 2:
                db.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + files(__package__)
                    .joinpath("migrations/003_issuing.sql")
                    .read_text()
                    + "\nCOMMIT;"
                )
                version = 3
            if version == 3:
                db.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + files(__package__)
                    .joinpath("migrations/004_person_history.sql")
                    .read_text()
                    + "\nCOMMIT;"
                )
                version = 4
            if version == 4:
                approved = (
                    db.execute("SELECT human_issuance FROM configuration").fetchone()[0]
                    == "approved"
                )
                if approved and (
                    policy is None or policy.grade("organisation.human.add") is None
                ):
                    raise Refused(Refusal.POLICY_MIGRATION_REQUIRED)
                db.executescript(
                    "BEGIN IMMEDIATE;\n"
                    + files(__package__)
                    .joinpath("migrations/005_human_approval.sql")
                    .read_text()
                )
                if policy is not None:
                    self.observe_policy(
                        db,
                        policy,
                        prior=PriorApproval.REQUIRED
                        if approved
                        else PriorApproval.UNRECORDED,
                    )
                db.execute("COMMIT")
            elif version != 5:
                raise Refused(Refusal.SCHEMA_UNAVAILABLE)

    @staticmethod
    def require_current_configuration(db: sqlite3.Connection) -> None:
        """Reject a retired policy column instead of silently treating it as off."""
        columns = {row[1] for row in db.execute("PRAGMA table_info(configuration)")}
        if "human_issuance" in columns:
            raise Refused(Refusal.POLICY_MIGRATION_REQUIRED)

    def observe_policy(
        self,
        db: sqlite3.Connection,
        policy: Policy,
        *,
        prior: PriorApproval = PriorApproval.UNRECORDED,
        source: PolicySource = PolicySource.EXPLICIT,
    ) -> None:
        """Audit configuration and refuse an implicit downgrade from its absence.

        The record supplies no approval policy. A previous requirement only
        requires an explicit source, including an explicit empty policy to turn off.
        """
        section = policy.as_section()
        previous = db.execute(
            "SELECT payload FROM signatures WHERE operation='human_approval_change' ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prefix = b"aweb.key-holder.human-approval/1\n"
        before: dict[str, Any] = {"require": {}}
        if previous:
            raw = base64.b64decode(previous["payload"], validate=True)
            if not raw.startswith(prefix):
                raise Refused(Refusal.STORAGE_UNAVAILABLE)
            before = parse(raw[len(prefix) :])["to"]
        elif prior is PriorApproval.REQUIRED:
            before = {"legacy_human_issuance": "approved"}
        if source is PolicySource.ABSENT and before.get("require"):
            raise Refused(Refusal.HUMAN_APPROVAL_SOURCE_REQUIRED)
        if before == section:
            return
        payload = prefix + canonical({"version": 1, "from": before, "to": section})
        self.sign_authorized_payload(
            db,
            self.descriptor_in_transaction(db),
            payload,
            operation="human_approval_change",
            actor="operator",
        )

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Open the private store without creating or migrating a database."""
        _private(self.directory, 0o700, kind=StorageKind.DIRECTORY)
        database = self.directory / "holder.sqlite"
        _private(database, 0o600)
        # Refuse missing files rather than creating an empty replacement store.
        db = sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=1)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA synchronous=FULL")
            yield db
        finally:
            db.close()

    def descriptor_in_transaction(
        self, db: sqlite3.Connection, *, team: str | None = None
    ) -> ControllerDescriptor:
        """Read current controller authority within the caller's transaction."""
        scope = "namespace" if team is None else "team"
        row = db.execute(
            "SELECT * FROM keys WHERE scope=? AND team=? ORDER BY generation DESC LIMIT 1",
            (scope, team or ""),
        ).fetchone()
        if row is None:
            raise Refused(Refusal.KEY_UNAVAILABLE)
        organisation = db.execute("SELECT organisation FROM configuration").fetchone()[
            0
        ]
        return ControllerDescriptor(
            scope,
            organisation,
            row["did_key"],
            row["reference"],
            row["generation"],
            team=team,
        )

    def descriptor(self, *, team: str | None = None) -> ControllerDescriptor:
        """Read the current namespace controller, or the named team controller."""
        with self.connection() as db:
            return self.descriptor_in_transaction(db, team=team)

    def create_team_key(self, name: str) -> ControllerDescriptor:
        """Generate a new named team key without publishing registry authority."""
        # The descriptor validates the actual registry team-name profile.
        root = self.descriptor()
        seed, public_key = generate_keypair()
        descriptor = ControllerDescriptor(
            "team",
            root.domain,
            did_from_public_key(public_key),
            uuid4().hex,
            0,
            team=name,
        )
        with self.connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM keys WHERE scope='team' AND team=?", (name,)
            ).fetchone():
                raise Refused(Refusal.KEY_ALREADY_EXISTS)
            db.execute(
                "INSERT INTO keys VALUES (?, ?, ?, ?, ?, ?)",
                (
                    descriptor.key_reference,
                    "team",
                    name,
                    0,
                    descriptor.did_key,
                    seed,
                ),
            )
        return descriptor

    def sign_controller(
        self, context: ControllerSigningContext, *, actor: str
    ) -> tuple[str, bytes]:
        """Internal SDK callback after the operation's caller authorization.

        It signs only a real typed SDK context and the current owned key. Human
        issuance cannot use this routine path, regardless of caller identity.
        The audit commits before the signature leaves this method.
        """
        if type(context) is not ControllerSigningContext or type(
            context.request
        ) not in (ControllerRequest, ControllerObjectRequest):
            raise Refused(Refusal.OPERATION_INVALID)
        request = context.request
        if request.operation not in ROUTINE:
            raise Refused(Refusal.OPERATION_NOT_SERVED)
        if (
            request.operation == "namespace_id_issue"
            and request.parameters["kind"] == "human"
        ):
            raise Refused(Refusal.HUMAN_APPROVAL_REQUIRED)
        if type(actor) is not str or not actor:
            raise Refused(Refusal.CALLER_REQUIRED)
        with self.connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            expected = self.descriptor_in_transaction(db, team=context.controller.team)
            if context.controller != expected:
                raise Refused(Refusal.CONTROLLER_MISMATCH)
            payload = context.signing_bytes()
            signature = self.sign_authorized_payload(
                db, expected, payload, operation=request.operation, actor=actor
            )
        return expected.did_key, signature

    def sign_authorized_payload(
        self,
        db: sqlite3.Connection,
        descriptor: ControllerDescriptor,
        payload: bytes,
        *,
        operation: str,
        actor: str,
        approval: str | None = None,
    ) -> bytes:
        """Sign and audit a caller-authorized act in its existing transaction.

        README.md's signature-record rule requires the audit to commit before
        a signature leaves the holder. This in-process primitive checks the
        current owned controller; the operation's handler authorizes the act.
        """
        if descriptor != self.descriptor_in_transaction(db, team=descriptor.team):
            raise Refused(Refusal.CONTROLLER_MISMATCH)
        row = db.execute(
            "SELECT seed FROM keys WHERE reference=?", (descriptor.key_reference,)
        ).fetchone()
        if did_key_from_signing_key(row["seed"]) != descriptor.did_key:
            raise Refused(Refusal.KEY_UNAVAILABLE)
        signature = base64.b64decode(
            sign_message(row["seed"], payload) + "==", validate=True
        )
        self._audit(
            db,
            descriptor,
            payload,
            signature,
            operation=operation,
            actor=actor,
            approval=approval,
        )
        return signature

    def _audit(
        self,
        db: sqlite3.Connection,
        descriptor: ControllerDescriptor,
        payload: bytes,
        signature: bytes,
        *,
        operation: str,
        actor: str,
        approval: str | None = None,
    ) -> None:
        db.execute(
            "INSERT INTO signatures(operation,actor,approval,key,generation,payload,signature,at) VALUES (?,?,?,?,?,?,?,?)",
            (
                operation,
                actor,
                approval,
                descriptor.did_key,
                descriptor.generation,
                base64.b64encode(payload).decode(),
                base64.b64encode(signature).decode(),
                int(time.time()),
            ),
        )

    @staticmethod
    def person_revision(db: sqlite3.Connection, person: str) -> int:
        """Read the per-person optimistic concurrency fence."""
        row = db.execute(
            "SELECT value FROM person_revisions WHERE person=?", (person,)
        ).fetchone()
        return row[0] if row else 0

    @staticmethod
    def advance_person(db: sqlite3.Connection, person: str) -> None:
        """Advance only the affected person's concurrency fence."""
        db.execute(
            "INSERT INTO person_revisions VALUES (?,1) ON CONFLICT(person) DO UPDATE SET value=value+1",
            (person,),
        )

    def retire_person(self, person: str) -> RetiredPerson:
        """Withdraw local approval eligibility; keep proofs, nonce and audit history."""
        with self.connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT retired_at FROM enrollments WHERE person=?", (person,)
            ).fetchone()
            if row is None:
                raise Refused(Refusal.ENROLLMENT_UNKNOWN)
            if row[0] is None:
                self.sign_authorized_payload(
                    db,
                    self.descriptor_in_transaction(db),
                    b"aweb.key-holder.retire/1\n" + canonical({"person": person}),
                    operation="retire_person",
                    actor="operator",
                )
                db.execute(
                    "UPDATE enrollments SET active=0,retired_at=? WHERE person=?",
                    (int(time.time()), person),
                )
                self.advance_person(db, person)
            return {"person": person, "state": "retired"}

    def audit(self, *, after: int = 0, limit: int = 1000) -> list[AuditEntry]:
        """Page committed signature records after the given sequence."""
        if after < 0 or not 1 <= limit <= 1000:
            raise Refused(Refusal.AUDIT_PAGE_INVALID)
        with self.connection() as db:
            return [
                AuditEntry(
                    sequence=row["sequence"],
                    operation=row["operation"],
                    actor=row["actor"],
                    approval=row["approval"],
                    key=row["key"],
                    generation=row["generation"],
                    payload=row["payload"],
                    signature=row["signature"],
                    at=row["at"],
                )
                for row in db.execute(
                    "SELECT * FROM signatures WHERE sequence>? ORDER BY sequence LIMIT ?",
                    (after, limit),
                )
            ]

    def encrypted_backup(self, offline_public_key: bytes) -> bytes:
        """Operator command: only ciphertext may leave the holder's storage."""
        public_key = PublicKey(offline_public_key)
        with self.connection() as db, db:
            # One snapshot includes the audit and all private key generations.
            db.execute("BEGIN IMMEDIATE")
            # Serialize the whole snapshot, including every nonce and enrollment.
            return SealedBox(public_key).encrypt(db.serialize())
