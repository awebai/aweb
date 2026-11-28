"""The holder's first gate: current admitted identities may ask to add a human.

Only an already activated, currently valid person may approve a later human.
The first person is an operator-only controller bootstrap. Credential checks,
receipt checks and trust acquisition come from the shared approval library.
"""

import hashlib
import hmac
import json
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

from approval_service.answers import read_answer
from approval_service.canonical import canonical, parse
from approval_service.definitions import check_definition, definition_ref
from approval_service.encoding import decode, encode
from approval_service.gate import Gate, load_policy
from approval_service.enrollment import PublicIssuer
from approval_service.public import PublicReader, public_errors
from approval_service.requester import AdmittedRequester, admit_enrollment_target
from approval_service.seams import (
    check_activation,
    check_creation_proof,
    commitment,
)
from approval_service.verify import Trust
from approval_service.wire import domain, validate, validate_site
from awid.controller_signing import ControllerSigningContext, parse_controller_object
from awid.did import public_key_from_did, stable_id_from_did_key
from awid.id_certificates import id_certificate_id
from awid.log import require_canonical_server_origin
from awid.registry import DIDKeyNotFoundError
from jsonschema import ValidationError

from .keys import Refused


def now():
    return int(time.time())


def expired_pending(row):
    return (
        row["evidence"] is None
        and json.loads(row["intent"])["intent"]["deadline"] <= now()
    )


class Holder:
    def __init__(
        self,
        store,
        *,
        registry,
        origin,
        approval_origin=None,
        rp_id=None,
        grading=None,
        human_approval_config=None,
    ):
        with store._connection() as db:
            store._refuse_legacy_configuration(db)
        self.human_approval_config = human_approval_config
        policy = load_policy(
            human_approval_config, organisation=store.descriptor().domain
        )
        if policy.service is not None:
            if approval_origin is not None and approval_origin != policy.service:
                raise Refused("human_approval_invalid")
            from approval_service.grading import EnrollmentGrading

            approval_origin = policy.service
            rp_id = rp_id or urlsplit(approval_origin).hostname
            grading = grading or EnrollmentGrading("passkey_only", None)
        if approval_origin is not None or rp_id is not None or grading is not None:
            if not all((approval_origin, rp_id, grading)):
                raise Refused("approval_not_configured")
            validate_site(approval_origin, rp_id)
            try:
                validate_site(origin, urlsplit(origin).hostname)
            except (ValueError, TypeError, ValidationError) as error:
                raise Refused("enforcer_origin_invalid") from error
        require_canonical_server_origin(origin)
        self.store, self.registry = store, registry
        self.origin, self.approval_origin, self.rp_id = origin, approval_origin, rp_id
        self.grading = grading
        self.public = PublicReader(registry)
        with store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            self.gate(db)

    def require_approval(self):
        policy = load_policy(
            self.human_approval_config, organisation=self.store.descriptor().domain
        )
        if policy.service is not None and policy.service != self.approval_origin:
            raise Refused("human_approval_invalid")
        if not all((self.approval_origin, self.rp_id, self.grading)):
            raise Refused("approval_not_configured")

    def gate(self, db=None):
        if db is None:
            with self.store._connection() as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                return self.gate(connection)
        policy = load_policy(
            self.human_approval_config, organisation=self.store.descriptor().domain
        )
        if policy.grade("organisation.human.add") is not None:
            self.require_approval()
            if policy.service != self.approval_origin:
                raise Refused("human_approval_invalid")
            if (
                policy.grade("organisation.human.add") == "certified_hardware"
                and self.grading.mode != "hardware"
            ):
                raise Refused("human_approval_hardware_grading_required")
        if db is not None:
            self.store.observe_policy(
                db, policy, source_configured=self.human_approval_config is not None
            )
        return Gate(
            policy, organisation=self.store.descriptor().domain, audience=self.origin
        )

    def issue_person_certificate(self, person, identity_key):
        """Private operator effect: certificate only, never enrollment or evidence."""
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            if self.gate(db).policy.grade("organisation.human.add") is not None:
                raise Refused("human_approval_required")
            return self._issue_person_certificate(
                db, person, identity_key, actor="operator"
            )

    def _issue_person_certificate(self, db, person, identity_key, *, actor):
        root = self.store._descriptor(db)
        certificate = self._certificate(root, person, identity_key, now())
        operation = parse_controller_object(
            {
                "operation": "namespace_id_issue",
                "domain": root.domain,
                "kind": "human",
                "certificate": certificate,
            }
        )
        signature = self.store._sign(
            db,
            root,
            ControllerSigningContext(operation, root).signing_bytes(),
            operation="namespace_id_issue",
            actor=actor,
        )
        self.store.advance_person(db, person)
        return {
            "state": "issued",
            "person": person,
            "identity_key": identity_key,
            "certificate": {"certificate": certificate, "signature": encode(signature)},
        }

    async def issue_person(self, person, identity_key):
        if self.gate().policy.grade("organisation.human.add") is not None:
            raise Refused("human_approval_required")
        await self._new_identity(person, identity_key)
        return self.issue_person_certificate(person, identity_key)

    async def issue_for_person(self, caller, *, person, identity_key, chain):
        root = self.store.descriptor()
        trust = await self.public.person(
            chain,
            person=caller.identity,
            identity_key=caller.key,
            organisation=root.domain,
        )
        await self._new_identity(person, identity_key)
        caller.check_time()
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            caller.check_time()
            gate = self.gate(db)
            if gate.policy.grade("organisation.human.add") is not None:
                raise Refused("state_changed")
            gate.evaluate("organisation.human.add")
            if (
                self.store._descriptor(db) != root
                or trust.namespace_issuer != root.did_key
                or not 0 <= now() - trust.observed_at <= 60
            ):
                raise Refused("status_unavailable")
            retired = db.execute(
                "SELECT retired_at FROM enrollments WHERE person=?", (caller.identity,)
            ).fetchone()
            if retired is not None and retired["retired_at"] is not None:
                raise Refused("person_retired")
            self._check_enrollment_available(db, person)
            return self._issue_person_certificate(
                db, person, identity_key, actor=caller.key
            )

    def _nonce_keys(self, db):
        return {
            "holder-1": db.execute("SELECT nonce_secret FROM configuration").fetchone()[
                0
            ]
        }

    def _request(
        self, db, *, purpose, operation, requester, approver, target, start, deadline
    ):
        root = self.store._descriptor(db)
        revision = self.store.person_revision(db, target["person"])
        value = {
            "version": 1,
            "purpose": purpose,
            "organisation": root.domain,
            "approver": approver,
            "requester": requester,
            "enforcer": {"audience": self.origin},
            "definition": definition_ref(operation),
            "act": {
                "operation": operation,
                "target": target,
                "expected_revision": revision,
            },
            "not_before": start,
            "deadline": deadline,
            "nonce": {"kid": "holder-1", "value": ""},
        }
        value["nonce"]["value"] = encode(
            hmac.digest(
                self._nonce_keys(db)["holder-1"],
                domain("nonce") + canonical(value),
                "sha256",
            )
        )
        validate("request", value)
        check_definition(value)
        return value

    def _certificate(self, root, person, identity_key, start):
        # First-path creation is a fresh stable ID; this is not key recovery.
        if stable_id_from_did_key(identity_key) != person:
            raise Refused("identity_key_mismatch")
        return {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": person,
            "domain": root.domain,
            "parent": {"kind": "namespace", "id": root.domain},
            "kind": "human",
            "issuer_key": root.did_key,
            "issued_at": datetime.fromtimestamp(start, UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        }

    def _protocol(self, db, root, purpose, body, *, actor, approval=None):
        # Private effect helper, never a caller-selected byte-signing endpoint.
        signature = self.store._sign(
            db,
            root,
            domain(purpose) + canonical(body),
            operation=purpose,
            actor=actor,
            approval=approval,
        )
        return encode(signature)

    def _check_enrollment_available(self, db, person):
        previous = db.execute(
            "SELECT * FROM enrollments WHERE person=?", (person,)
        ).fetchone()
        if previous and (previous["active"] or previous["retired_at"] is not None):
            raise Refused("enrollment_replacement_unavailable")
        if previous and not expired_pending(previous):
            raise Refused("person_already_exists")
        return previous

    def _pending(
        self,
        db,
        *,
        person,
        identity_key,
        requester,
        certificate,
        approval=None,
        actor=None,
    ):
        actor = actor or requester["key"]
        root = self.store._descriptor(db)
        previous = self._check_enrollment_available(db, person)
        if previous:
            # Retire the expired operation's idempotent lookup, so an old
            # receipt cannot return this new intent. Old R is expired/stale;
            # the revision and MAC checks still precede any new effect.
            # Signature records remain append-only and retain the old intent.
            db.execute("DELETE FROM consumed WHERE person=?", (person,))
            db.execute("DELETE FROM enrollments WHERE person=?", (person,))
        operation = parse_controller_object(
            {
                "operation": "namespace_id_issue",
                "domain": root.domain,
                "kind": "human",
                "certificate": certificate,
            }
        )
        approval_digest = (
            commitment("receipt_commitment", approval) if approval is not None else None
        )
        signature = self.store._sign(
            db,
            root,
            ControllerSigningContext(operation, root).signing_bytes(),
            operation="namespace_id_issue",
            actor=actor,
            approval=approval_digest,
        )
        start = now()
        requester = {"kind": "identity", "id": person, "key": identity_key}
        intent = {
            "version": 1,
            "purpose": "enroll_person",
            "organisation": root.domain,
            "person": person,
            "pending_certificate": {
                "certificate": certificate,
                "signature": encode(signature),
            },
            "identity_key": identity_key,
            "requester": requester,
            "origin": self.approval_origin,
            "rp_id": self.rp_id,
            "challenge": encode(secrets.token_bytes(32)),
            "not_before": start,
            "deadline": start + 24 * 60 * 60,
        }
        signed = {
            "intent": intent,
            "signature": self._protocol(
                db,
                root,
                "enrollment_intent",
                intent,
                actor=actor,
                approval=approval_digest,
            ),
        }
        validate("enrollment_intent", signed)
        db.execute(
            "INSERT INTO enrollments(person,identity_key,requester,intent,approval_receipt) VALUES (?,?,?,?,?)",
            (
                person,
                identity_key,
                canonical(requester).decode(),
                canonical(signed).decode(),
                canonical(approval).decode() if approval is not None else None,
            ),
        )
        self.store.advance_person(db, person)
        return {"state": "enrollment_pending", "intent": signed}

    def _row(self, db, person):
        row = db.execute(
            "SELECT * FROM enrollments WHERE person=?", (person,)
        ).fetchone()
        if row is None:
            raise Refused("enrollment_unknown")
        if row["retired_at"] is not None:
            raise Refused("enrollment_replacement_unavailable")
        return row

    def pending(self, person):
        with self.store._connection() as db:
            row = self._row(db, person)
            return {"state": "enrollment_pending", "intent": json.loads(row["intent"])}

    def active_person(self, person):
        with self.store._connection() as db:
            row = db.execute(
                "SELECT * FROM enrollments WHERE person=? AND active=1 AND retired_at IS NULL",
                (person,),
            ).fetchone()
            if row is None:
                raise Refused("approver_not_active")
            return dict(row)

    def bootstrap_pending(self, person, identity_key):
        """Private operator command; never reachable from the public HTTP router."""
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            root = self.store._descriptor(db)
            requester = {"kind": "identity", "id": person, "key": identity_key}
            old = db.execute(
                "SELECT * FROM enrollments WHERE person=?", (person,)
            ).fetchone()
            if old:
                if old["retired_at"] is not None:
                    raise Refused("enrollment_replacement_unavailable")
                if (
                    old["person"] != person
                    or old["identity_key"] != identity_key
                    or json.loads(old["requester"]) != requester
                ):
                    raise Refused("bootstrap_closed")
                if not expired_pending(old):
                    return {
                        "state": "enrollment_pending",
                        "intent": json.loads(old["intent"]),
                    }
            elif db.execute(
                "SELECT 1 FROM enrollments WHERE retired_at IS NULL LIMIT 1"
            ).fetchone():
                raise Refused("bootstrap_closed")
            certificate = self._certificate(root, person, identity_key, now())
            return self._pending(
                db,
                person=person,
                identity_key=identity_key,
                requester=requester,
                certificate=certificate,
                actor="operator",
            )

    async def bootstrap(self, person, identity_key):
        with self.store._connection() as db:
            exists = db.execute(
                "SELECT 1 FROM enrollments WHERE person=?", (person,)
            ).fetchone()
        if not exists:
            await self._new_identity(person, identity_key)
        result = self.bootstrap_pending(person, identity_key)
        issuer = await self.public.issuer(result["intent"])
        if issuer.key != self.store.descriptor().did_key:
            raise Refused("issuer_changed")
        return result

    @public_errors
    async def _new_identity(self, person, identity_key):
        self._certificate(self.store.descriptor(), person, identity_key, now())
        try:
            current = await self.registry.resolve_key_fresh(person)
        except DIDKeyNotFoundError as error:
            enrollment = error.id_tree
        else:
            enrollment = current.id_tree
            if current.current_did_key != identity_key:
                raise Refused("identity_key_mismatch")
        if enrollment is None:
            raise Refused("status_unavailable")
        if enrollment.enrolled:
            raise Refused("fresh_enrollment_required")

    async def enroll_existing(self, caller, *, person, chain):
        self.require_approval()
        if caller.identity != person:
            raise Refused("requester_mismatch")
        root = self.store.descriptor()
        trust = await self.public.person(
            chain, person=person, identity_key=caller.key, organisation=root.domain
        )
        if trust.namespace_issuer != root.did_key:
            raise Refused("issuer_changed")
        caller.check_time()
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            if (
                self.store._descriptor(db) != root
                or not 0 <= now() - trust.observed_at <= 60
            ):
                raise Refused("status_unavailable")
            old = db.execute(
                "SELECT * FROM enrollments WHERE person=?", (person,)
            ).fetchone()
            if (
                old
                and old["retired_at"] is None
                and not old["active"]
                and not expired_pending(old)
            ):
                saved = json.loads(old["intent"])
                previous_intent = saved["intent"]
                if (
                    previous_intent["purpose"] == "enroll_existing_person"
                    and previous_intent["requester"] == caller.descriptor
                    and previous_intent["identity_key"] == trust.identity_key
                    and id_certificate_id(
                        previous_intent["pending_certificate"]["certificate"]
                    )
                    == trust.certificate
                ):
                    return {"state": "enrollment_pending", "intent": saved}
            previous = self._check_enrollment_available(db, person)
            if previous:
                db.execute("DELETE FROM consumed WHERE person=?", (person,))
                db.execute("DELETE FROM enrollments WHERE person=?", (person,))
            start = now()
            body = {
                "version": 1,
                "purpose": "enroll_existing_person",
                "organisation": root.domain,
                "person": person,
                "pending_certificate": chain[-1],
                "identity_key": trust.identity_key,
                "requester": caller.descriptor,
                "origin": self.approval_origin,
                "rp_id": self.rp_id,
                "challenge": encode(secrets.token_bytes(32)),
                "not_before": start,
                "deadline": start + 86400,
            }
            signed = {
                "intent": body,
                "signature": self._protocol(
                    db, root, "enrollment_intent", body, actor=caller.key
                ),
            }
            validate("enrollment_intent", signed)
            db.execute(
                "INSERT INTO enrollments(person,identity_key,requester,intent,chain) VALUES (?,?,?,?,?)",
                (
                    person,
                    trust.identity_key,
                    canonical(caller.descriptor).decode(),
                    canonical(signed).decode(),
                    canonical(chain).decode(),
                ),
            )
            self.store.advance_person(db, person)
            caller.check_time()
            if not 0 <= now() - trust.observed_at <= 60:
                raise Refused("status_unavailable")
            return {"state": "enrollment_pending", "intent": signed}

    async def enrollment_admission(self, person, caller, chain, *, purpose):
        admitted = None
        if chain or caller.identity != person:
            admitted = await self.admit(caller, chain)
        else:
            observation = await self.public.key_observation(person)
            if observation.current_key != caller.key:
                raise Refused("identity_key_mismatch")
            caller.check_time()
        self.require_approval()
        signed = self.pending(person)["intent"]
        i = signed["intent"]
        if i["purpose"] == "enroll_existing_person":
            if caller.descriptor != i["requester"]:
                raise Refused("requester_mismatch")
            trust = await self.public.person(
                chain,
                person=person,
                identity_key=i["identity_key"],
                organisation=i["organisation"],
            )
            if trust.namespace_issuer != self.store.descriptor().did_key:
                raise Refused("issuer_changed")
            caller.check_time()
            return AdmittedRequester(
                canonical(caller.descriptor), caller.key, trust.observed_at
            ), trust
        if caller.descriptor == i["requester"] and caller.identity == person:
            observation = await self.public.key_observation(person)
            if observation.committed is False:
                issuer = await self.public.issuer(signed)
                admitted = admit_enrollment_target(
                    signed,
                    caller.descriptor,
                    issuer_key=issuer.key,
                    observation=observation,
                    origin=self.approval_origin,
                    rp_id=self.rp_id,
                    now=now(),
                    purpose=purpose,
                )
                caller.check_time()
                return admitted, None
        return admitted or await self.admit(caller, chain), None

    async def admit(self, caller, chain):
        root = self.store.descriptor()
        admitted = await self.public.requester(
            caller.descriptor,
            organisation=root.domain,
            admission={"team_certificate": None, "id_chain": chain},
        )
        caller.check_time()
        return admitted

    def _owner(self, row, caller, admitted, *, activation=False):
        original = json.loads(row["requester"])
        caller.check_time()
        if admitted is None or not 0 <= now() - admitted.observed_at <= 60:
            raise Refused("status_unavailable")
        if (
            admitted.descriptor_bytes != canonical(caller.descriptor)
            or admitted.key != caller.key
        ):
            raise Refused("requester_mismatch")
        own_activation = (
            activation
            and caller.identity == row["person"]
            and caller.key == row["identity_key"]
        )
        if original != caller.descriptor and not own_activation:
            raise Refused("requester_mismatch")

    async def prepare(self, caller, *, person, identity_key, approver, chain):
        if self.gate().policy.grade("organisation.human.add") is None:
            return 200, await self.issue_for_person(
                caller, person=person, identity_key=identity_key, chain=chain
            )
        self.require_approval()
        admitted = await self.admit(caller, chain)
        with self.store._connection() as db:
            self._check_enrollment_available(db, person)
        active = self.active_person(approver)
        await self.public.person(
            json.loads(active["chain"]),
            person=approver,
            identity_key=active["identity_key"],
            organisation=self.store.descriptor().domain,
        )
        await self._new_identity(person, identity_key)
        caller.check_time()
        if person == approver:
            raise Refused("target_is_approver")
        with self.store._connection() as db:
            if not 0 <= now() - admitted.observed_at <= 60:
                raise Refused("status_unavailable")
            root, start = self.store._descriptor(db), now()
            certificate = self._certificate(root, person, identity_key, start)
            request = self._request(
                db,
                purpose="act_approval",
                operation="human.add",
                requester=caller.descriptor,
                approver=approver,
                target={
                    "person": person,
                    "identity_key": identity_key,
                    "certificate": id_certificate_id(certificate),
                },
                start=start,
                deadline=start + 600,
            )
            gate = self.gate()
            if gate.policy.grade("organisation.human.add") is None:
                raise Refused("state_changed")
            return gate.evaluate("organisation.human.add", request=request)

    async def present(self, caller, value, *, chain):
        self.require_approval()
        validate("presentation", value)
        request = parse(decode(value["request_bytes"]))
        validate("request", request)
        check_definition(request)
        admitted = await self.admit(caller, chain)
        active = self.active_person(request["approver"])
        root = self.store.descriptor()
        trust = await self.public.person(
            value["receipt"]["id_chain"],
            person=request["approver"],
            identity_key=active["identity_key"],
            organisation=root.domain,
        )
        with self.store._connection() as db:
            applied = db.execute(
                "SELECT 1 FROM consumed WHERE nonce=?", (request["nonce"]["value"],)
            ).fetchone()
        if not applied:
            target = request["act"]["target"]
            try:
                await self._new_identity(target["person"], target["identity_key"])
            except Refused:
                with self.store._connection() as db:
                    applied = db.execute(
                        "SELECT 1 FROM consumed WHERE nonce=?",
                        (request["nonce"]["value"],),
                    ).fetchone()
                if not applied:
                    raise
        caller.check_time()
        if trust.issuer != root.did_key:
            raise Refused("issuer_changed")
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            caller.check_time()
            if not 0 <= now() - admitted.observed_at <= 60:
                raise Refused("status_unavailable")
            if request["organisation"] != root.domain or request["enforcer"] != {
                "audience": self.origin
            }:
                raise Refused("enforcer_mismatch")
            if (
                request["act"]["operation"] != "human.add"
                or request["purpose"] != "act_approval"
            ):
                raise Refused("operation_invalid")
            if request["requester"] != caller.descriptor:
                raise Refused("requester_mismatch")
            nonce = request["nonce"]["value"]
            digest = hashlib.sha256(canonical(request)).hexdigest()
            previous = db.execute(
                "SELECT * FROM consumed WHERE nonce=?", (nonce,)
            ).fetchone()
            if previous:
                if (
                    previous["request_digest"] != digest
                    or previous["requester"] != canonical(caller.descriptor).decode()
                ):
                    raise Refused("nonce_conflict")
                old = self._row(db, previous["person"])
                return {
                    "state": "active" if old["active"] else "enrollment_pending",
                    "intent": json.loads(old["intent"]),
                }
            if request["act"]["expected_revision"] != self.store.person_revision(
                db, request["act"]["target"]["person"]
            ):
                raise Refused("state_changed")
            if not self._row(db, request["approver"])["active"]:
                raise Refused("approver_not_active")
            gate = self.gate(db)
            if gate.policy.grade("organisation.human.add") is None:
                raise Refused("state_changed")
            gate.evaluate(
                "organisation.human.add",
                request=request,
                presentation=value,
                presenter=caller.descriptor,
                now=now(),
                trust=trust,
                nonce_keys=self._nonce_keys(db),
            )
            target = request["act"]["target"]
            if target["person"] == request["approver"]:
                raise Refused("target_is_approver")
            certificate = self._certificate(
                root, target["person"], target["identity_key"], request["not_before"]
            )
            if id_certificate_id(certificate) != target["certificate"]:
                raise Refused("certificate_mismatch")
            result = self._pending(
                db,
                person=target["person"],
                identity_key=target["identity_key"],
                requester=caller.descriptor,
                certificate=certificate,
                approval=value["receipt"],
            )
            db.execute(
                "INSERT INTO consumed VALUES (?,?,?,?)",
                (
                    nonce,
                    digest,
                    canonical(caller.descriptor).decode(),
                    target["person"],
                ),
            )
            return result

    def bind_registration(
        self,
        person,
        material,
        *,
        registration_count,
        caller,
        admitted,
        current=None,
    ):
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, person)
            self._owner(row, caller, admitted)
            signed = json.loads(row["intent"])
            intent = signed["intent"]
            answer = read_answer(
                "enrollment_material", material, status=200, intent=signed
            )
            if (
                type(registration_count) is not int
                or not 1 <= registration_count <= 8
                or len(answer["registrations"]) != registration_count
            ):
                raise Refused("registration_count_mismatch")
            if not intent["not_before"] <= now() < intent["deadline"]:
                raise Refused("enrollment_expired")
            assessments = [
                self.grading.check(
                    item["registration"],
                    expected_challenge=decode(intent["challenge"]),
                    origin=self.approval_origin,
                    rp_id=self.rp_id,
                    now=datetime.now(UTC),
                )
                for item in answer["registrations"]
            ]
            credentials = [result.binding_entry() for result in assessments]
            if len({item["id"] for item in credentials}) != len(credentials):
                raise Refused("credential_duplicate")
            root = self.store._descriptor(db)
            if (
                intent["purpose"] != "enroll_existing_person"
                and root.did_key
                != intent["pending_certificate"]["certificate"]["issuer_key"]
            ):
                raise Refused("issuer_changed")
            if intent["purpose"] == "enroll_existing_person":
                self._existing_current(intent, current, root)
            body = {
                "version": 1,
                "organisation": root.domain,
                "person": person,
                "certificate": id_certificate_id(
                    intent["pending_certificate"]["certificate"]
                ),
                "identity_key": row["identity_key"],
                "issuer": root.did_key,
                "origin": self.approval_origin,
                "rp_id": self.rp_id,
                "credentials": credentials,
            }
            if row["binding"]:
                binding = json.loads(row["binding"])
                if binding["binding"] != body:
                    raise Refused("registration_changed")
                confirmation = json.loads(row["confirmation"])
            else:
                binding = {
                    "binding": body,
                    "signature": self._protocol(
                        db, root, "binding", body, actor=intent["requester"]["key"]
                    ),
                }
                confirmation = self._request(
                    db,
                    purpose="enrollment_confirmation",
                    operation="enrollment.confirm",
                    requester=intent["requester"],
                    approver=person,
                    target={
                        "person": person,
                        "certificate": body["certificate"],
                        "identity_key": row["identity_key"],
                        "binding_commitment": commitment("binding_commitment", binding),
                    },
                    start=intent["not_before"],
                    deadline=intent["deadline"],
                )
                db.execute(
                    "UPDATE enrollments SET binding=?,confirmation=? WHERE person=?",
                    (
                        canonical(binding).decode(),
                        canonical(confirmation).decode(),
                        person,
                    ),
                )
                # Private issuer inventory for withdrawal matching and P assessment.
                # The credential grade is the only eligibility signal.
                # Capture it when B is signed, so retries cannot backfill old bindings.
                for result in assessments:
                    assessment = result.attestation_assessment
                    if assessment is None:
                        raise Refused("attestation_assessment_unavailable")
                    record = {"format": assessment.format}
                    if assessment.verified_chain:
                        record.update(
                            aaguid=assessment.aaguid,
                            firmware_version=assessment.firmware_version,
                            verified_chain=[
                                encode(cert) for cert in assessment.verified_chain
                            ],
                        )
                    db.execute(
                        "INSERT INTO attestation_inventory (namespace,person,credential,assessment) "
                        "VALUES (?,?,?,?)",
                        (root.domain, person, result.credential_id, json.dumps(record)),
                    )
            self._owner(row, caller, admitted)
            if not intent["not_before"] <= now() < intent["deadline"]:
                raise Refused("enrollment_expired")
            if intent["purpose"] == "enroll_existing_person":
                self._existing_current(intent, current, root)
            return {
                "state": "awaiting_confirmation",
                "intent": signed,
                "binding": binding,
                "request_bytes": encode(canonical(confirmation)),
            }

    @staticmethod
    def _existing_current(intent, current, root):
        if current is None or not 0 <= now() - current.observed_at <= 60:
            raise Refused("identity_unavailable")
        if (
            current.person,
            current.organisation,
            current.identity_key,
            current.certificate,
            current.namespace_issuer,
        ) != (
            intent["person"],
            root.domain,
            intent["identity_key"],
            id_certificate_id(intent["pending_certificate"]["certificate"]),
            root.did_key,
        ):
            raise Refused("enrollment_identity_mismatch")

    def finish_creation(
        self, person, receipt, *, issuer, caller, admitted, current=None
    ):
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, person)
            self._owner(row, caller, admitted)
            if not row["binding"] or issuer is None:
                raise Refused("creation_required")
            root = self.store._descriptor(db)
            signed, binding = json.loads(row["intent"]), json.loads(row["binding"])
            intent, confirmation = signed["intent"], json.loads(row["confirmation"])
            if issuer.key != root.did_key:
                raise Refused("issuer_changed")
            if (
                receipt.get("request_bytes") != encode(canonical(confirmation))
                or receipt.get("binding") != binding
            ):
                raise Refused("creation_mismatch")
            if row["evidence"]:
                if json.loads(row["creation_receipt"]) != receipt:
                    raise Refused("creation_changed")
                return self._activation(row)
            later = intent["purpose"] == "enroll_existing_person"
            if later:
                self._existing_current(intent, current, root)
            trust = (
                current
                if later
                else Trust(
                    person,
                    root.domain,
                    row["identity_key"],
                    binding["binding"]["certificate"],
                    root.did_key,
                    public_key_from_did(root.did_key),
                    issuer.observed_at,
                )
            )
            checked = check_creation_proof(
                receipt,
                intent=signed,
                issuer_key=root.did_key,
                requester=intent["requester"],
                origin=self.approval_origin,
                rp_id=self.rp_id,
                now=now(),
                pending_trust=trust,
                nonce_keys=self._nonce_keys(db),
            )
            body = {
                "version": 1,
                "kind": "human",
                "organisation": root.domain,
                "subject": {
                    "id": person,
                    "certificate": trust.certificate,
                    "key": row["identity_key"],
                },
                "issuer": root.did_key,
                "binding_commitment": checked["binding_commitment"],
                "creation": {
                    "credential": checked["credential"],
                    "grade": checked["grade"],
                    "receipt_commitment": commitment("receipt_commitment", receipt),
                },
            }
            if later:
                body["kind"] = "human_enrolled_later"
                body.pop("creation")
                body["enrollment"] = {
                    "credential": checked["credential"],
                    "grade": checked["grade"],
                    "since": now(),
                    "confirmation_receipt_commitment": commitment(
                        "receipt_commitment", receipt
                    ),
                }
            evidence = {
                "evidence": body,
                "signature": self._protocol(
                    db,
                    root,
                    "later_enrollment_evidence" if later else "identity_evidence",
                    body,
                    actor=intent["requester"]["key"],
                    approval=checked["digest"],
                ),
            }
            validate(
                "later_enrollment_evidence" if later else "creation_evidence", evidence
            )
            if later:
                self._existing_current(intent, current, root)
            db.execute(
                "UPDATE enrollments SET creation_receipt=?,evidence=?,chain=? WHERE person=?",
                (
                    canonical(receipt).decode(),
                    canonical(evidence).decode(),
                    canonical(receipt["id_chain"]).decode(),
                    person,
                ),
            )
            db.execute(
                "INSERT INTO consumed VALUES (?,?,?,?)",
                (
                    confirmation["nonce"]["value"],
                    hashlib.sha256(canonical(confirmation)).hexdigest(),
                    canonical(intent["requester"]).decode(),
                    person,
                ),
            )
            self._owner(row, caller, admitted)
            if not intent["not_before"] <= now() < intent["deadline"]:
                raise Refused("enrollment_expired")
            if later:
                self._existing_current(intent, current, root)
            return self._activation(self._row(db, person))

    def _activation(self, row):
        later = (
            json.loads(row["intent"])["intent"]["purpose"] == "enroll_existing_person"
        )
        return {
            "version": 2 if later else 1,
            "intent": json.loads(row["intent"]),
            "binding": json.loads(row["binding"]),
            ("confirmation_receipt" if later else "creation_receipt"): json.loads(
                row["creation_receipt"]
            ),
            "evidence": json.loads(row["evidence"]),
            "id_chain": json.loads(row["chain"]),
        }

    async def finish(self, person, receipt, *, caller, chain):
        admitted, current = await self.enrollment_admission(
            person, caller, chain, purpose="holder_finish"
        )
        issuer = (
            PublicIssuer(current.namespace_issuer, current.observed_at)
            if current
            else await self.public.issuer(self.pending(person)["intent"])
        )
        return self.finish_creation(
            person,
            receipt,
            issuer=issuer,
            caller=caller,
            admitted=admitted,
            current=current,
        )

    async def activate(self, person, *, caller, chain):
        admitted, _current = await self.enrollment_admission(
            person, caller, chain, purpose="holder_activate"
        )
        with self.store._connection() as db:
            row = self._row(db, person)
            self._owner(row, caller, admitted, activation=True)
            value = self._activation(row)
        trust = await self.public.person(
            value["id_chain"],
            person=person,
            identity_key=row["identity_key"],
            organisation=self.store.descriptor().domain,
        )
        with self.store._connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = self._row(db, person)
            self._owner(row, caller, admitted, activation=True)
            if self._activation(row) != value:
                raise Refused("enrollment_changed")
            result = check_activation(
                value,
                issuer_key=self.store._descriptor(db).did_key,
                requester=value["intent"]["intent"]["requester"],
                origin=self.approval_origin,
                rp_id=self.rp_id,
                now=now(),
                trust=trust,
            )
            if not row["active"]:
                hardware_credentials = {
                    entry["id"]
                    for entry in value["binding"]["binding"]["credentials"]
                    if entry["grade"] == "certified_hardware"
                }
                if hardware_credentials:
                    recorded = db.execute(
                        "SELECT credential FROM attestation_inventory WHERE namespace=? AND person=?",
                        (trust.organisation, person),
                    )
                    if not hardware_credentials.issubset(
                        item["credential"] for item in recorded
                    ):
                        raise Refused("attestation_assessment_unavailable")
            db.execute("UPDATE enrollments SET active=1 WHERE person=?", (person,))
            self._owner(row, caller, admitted, activation=True)
            if not 0 <= now() - trust.observed_at <= 60:
                raise Refused("status_unavailable")
            return result
