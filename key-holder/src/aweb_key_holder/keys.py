"""Private org keys and the durable signature record; never a sign-bytes port.

Deploy this directory only into the holder process. The calling application
must receive public descriptors/results and no mount or database role here.
"""

from contextlib import contextmanager
import base64
from importlib.resources import files
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time
from uuid import uuid4

from nacl.public import PublicKey, SealedBox

from awid.controller_signing import (
    ControllerDescriptor,
    ControllerObjectRequest,
    ControllerRequest,
    ControllerSigningContext,
)
from awid.did import did_from_public_key, did_key_from_signing_key, generate_keypair
from awid.signing import canonical_json_bytes, sign_message


class Refused(ValueError):
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
        return store

    @classmethod
    def open(cls, directory):
        store = cls(directory)
        with store._connection() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise Refused("schema_unavailable")
            if db.execute("SELECT count(*) FROM configuration").fetchone()[0] != 1:
                raise Refused("storage_unavailable")
        return store

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
            row = db.execute(
                "SELECT seed FROM keys WHERE reference=?", (expected.key_reference,)
            ).fetchone()
            if did_key_from_signing_key(row["seed"]) != expected.did_key:
                raise Refused("key_unavailable")
            payload = context.signing_bytes()
            signature = base64.b64decode(
                sign_message(row["seed"], payload) + "==", validate=True
            )
            db.execute(
                "INSERT INTO signatures(operation,actor,approval,key,generation,payload,signature,at) VALUES (?,?,?,?,?,?,?,?)",
                (
                    request.operation,
                    actor,
                    None,
                    expected.did_key,
                    expected.generation,
                    base64.b64encode(payload).decode(),
                    base64.b64encode(signature).decode(),
                    int(time.time()),
                ),
            )
        return expected.did_key, signature

    def audit(self):
        with self._connection() as db:
            return [
                dict(row)
                for row in db.execute("SELECT * FROM signatures ORDER BY sequence")
            ]

    def encrypted_backup(self, offline_public_key):
        """Operator command: only ciphertext may leave the holder's storage."""
        public_key = PublicKey(offline_public_key)
        with self._connection() as db, db:
            # One snapshot includes the audit and all private key generations.
            db.execute("BEGIN IMMEDIATE")
            settings = dict(db.execute("SELECT * FROM configuration").fetchone())
            value = {
                "version": 1,
                "organisation": settings["organisation"],
                "nonce_secret": settings["nonce_secret"].hex(),
                "keys": [
                    {**dict(row), "seed": row["seed"].hex()}
                    for row in db.execute("SELECT * FROM keys ORDER BY reference")
                ],
                "signatures": [
                    dict(row)
                    for row in db.execute("SELECT * FROM signatures ORDER BY sequence")
                ],
            }
            return SealedBox(public_key).encrypt(canonical_json_bytes(value))
