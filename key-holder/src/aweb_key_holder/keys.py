"""Private org keys and the durable signature record; never a sign-bytes port.

Deploy this directory only into the holder process. The calling application
must receive public descriptors/results and no mount or database role here.
"""

import base64
import os
import secrets
import sqlite3
import stat
import time
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

from approval_service.canonical import canonical
from approval_service.verify import Refused as ApprovalRefused
from awid.controller_signing import (
    ControllerDescriptor,
    ControllerObjectRequest,
    ControllerRequest,
    ControllerSigningContext,
)
from awid.did import did_from_public_key, did_key_from_signing_key, generate_keypair
from awid.signing import sign_message
from nacl.public import PublicKey, SealedBox


class Refused(ApprovalRefused):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


# Explicit holder rules, not an automatic import of every future SDK operation.
# Destructive key changes and human issuance have separate authority paths.
ROUTINE = frozenset(
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


def _private(path, mode, *, directory=False):
    try:
        info = path.lstat()
    except OSError as error:
        raise Refused("storage_unavailable") from error
    kind_ok = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not kind_ok or stat.S_IMODE(info.st_mode) != mode or info.st_uid != os.getuid():
        raise Refused("storage_permissions")


class KeyStore:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()

    @classmethod
    def create(cls, directory, *, organisation):
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
            raise Refused("already_initialized") from error
        _private(store.directory, 0o700, directory=True)
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
    def open(cls, directory):
        store = cls(directory)
        with store._connection() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 4:
                raise Refused("schema_unavailable")
            if db.execute("SELECT count(*) FROM configuration").fetchone()[0] != 1:
                raise Refused("storage_unavailable")
        return store

    def migrate(self):
        with self._connection() as db:
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
            elif version != 4:
                raise Refused("schema_unavailable")

    def human_issuance(self):
        with self._connection() as db:
            return db.execute("SELECT human_issuance FROM configuration").fetchone()[0]

    def set_human_issuance(self, mode):
        """Private operator setting; never exposed through the HTTP application."""
        if mode not in ("operator", "approved"):
            raise Refused("issuing_setting_invalid")
        with self._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT human_issuance FROM configuration"
            ).fetchone()[0]
            if previous == mode:
                return
            descriptor = self._descriptor(db)
            payload = b"aweb.key-holder.setting/1\n" + canonical(
                {
                    "version": 1,
                    "type": "aweb.holder.setting",
                    "setting": "human_issuance",
                    "from": previous,
                    "to": mode,
                }
            )
            self._sign(
                db,
                descriptor,
                payload,
                operation="human_issuance_change",
                actor="operator",
            )
            db.execute("UPDATE configuration SET human_issuance=?", (mode,))

    @contextmanager
    def _connection(self):
        _private(self.directory, 0o700, directory=True)
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

    def _descriptor(self, db, *, team=None):
        scope = "namespace" if team is None else "team"
        row = db.execute(
            "SELECT * FROM keys WHERE scope=? AND team=? ORDER BY generation DESC LIMIT 1",
            (scope, team or ""),
        ).fetchone()
        if row is None:
            raise Refused("key_unavailable")
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

    def descriptor(self, *, team=None):
        with self._connection() as db:
            return self._descriptor(db, team=team)

    def create_team_key(self, name):
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
        with self._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute(
                "SELECT 1 FROM keys WHERE scope='team' AND team=?", (name,)
            ).fetchone():
                raise Refused("key_already_exists")
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

    def sign_controller(self, context, *, actor):
        """Internal SDK callback after the operation's caller authorization.

        It signs only a real typed SDK context and the current owned key. Human
        issuance cannot use this routine path, regardless of caller identity.
        The audit commits before the signature leaves this method.
        """
        if type(context) is not ControllerSigningContext or type(
            context.request
        ) not in (ControllerRequest, ControllerObjectRequest):
            raise Refused("operation_invalid")
        request = context.request
        if request.operation not in ROUTINE:
            raise Refused("operation_not_served")
        if (
            request.operation == "namespace_id_issue"
            and request.parameters["kind"] == "human"
        ):
            raise Refused("human_approval_required")
        if type(actor) is not str or not actor:
            raise Refused("caller_required")
        with self._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            expected = self._descriptor(db, team=context.controller.team)
            if context.controller != expected:
                raise Refused("controller_mismatch")
            payload = context.signing_bytes()
            signature = self._sign(
                db, expected, payload, operation=request.operation, actor=actor
            )
        return expected.did_key, signature

    def _sign(self, db, descriptor, payload, *, operation, actor, approval=None):
        """Internal effect helper; the caller builds and authorizes the typed act."""
        if descriptor != self._descriptor(db, team=descriptor.team):
            raise Refused("controller_mismatch")
        row = db.execute(
            "SELECT seed FROM keys WHERE reference=?", (descriptor.key_reference,)
        ).fetchone()
        if did_key_from_signing_key(row["seed"]) != descriptor.did_key:
            raise Refused("key_unavailable")
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
        self, db, descriptor, payload, signature, *, operation, actor, approval=None
    ):
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
    def person_revision(db, person):
        row = db.execute(
            "SELECT value FROM person_revisions WHERE person=?", (person,)
        ).fetchone()
        return row[0] if row else 0

    @staticmethod
    def advance_person(db, person):
        db.execute(
            "INSERT INTO person_revisions VALUES (?,1) ON CONFLICT(person) DO UPDATE SET value=value+1",
            (person,),
        )

    def retire_person(self, person):
        """Withdraw local approval eligibility; keep proofs, nonce and audit history."""
        with self._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT retired_at FROM enrollments WHERE person=?", (person,)
            ).fetchone()
            if row is None:
                raise Refused("enrollment_unknown")
            if row[0] is None:
                self._sign(
                    db,
                    self._descriptor(db),
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

    def audit(self, *, after=0, limit=1000):
        if after < 0 or not 1 <= limit <= 1000:
            raise Refused("audit_page_invalid")
        with self._connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM signatures WHERE sequence>? ORDER BY sequence LIMIT ?",
                    (after, limit),
                )
            ]

    def encrypted_backup(self, offline_public_key):
        """Operator command: only ciphertext may leave the holder's storage."""
        public_key = PublicKey(offline_public_key)
        with self._connection() as db, db:
            # One snapshot includes the audit and all private key generations.
            db.execute("BEGIN IMMEDIATE")
            # Serialize the whole snapshot, including every nonce and enrollment.
            return SealedBox(public_key).encrypt(db.serialize())
