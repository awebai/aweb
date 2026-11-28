"""The trust-web model's cases, and the runner that executes them for real.

The cases are the seeds in ``docs/vectors/trust-web-cases-v2.json`` and the
model's emission in ``docs/vectors/trust-web-cases-model-v2.json`` (format
``aweb.trust-web-cases/2``, specified in docs/vectors/README.md). A case is
written in the vocabulary of the experimental Lean model in
``spec/trust-model``: a setup of model acts, one act by one party, the
expected decision (allowed, or refused because one named premise fails) and
predicates over the model's record that prove the effect or its absence.

The runner owns the other side, which the model does not describe:

* how each model act is performed through signed public routes of a real AWID
  registry and a real aweb server (``World``), including the wire
  prerequisites the model has no act for: namespace and team creation by the
  namespace controller, did:aw registration, and the member's connection to
  its team's server;
* how each predicate is read back from committed evidence (``World.observe``);
* which wire refusal each model premise corresponds to (``REFUSALS``).

The model assumes one current record that everyone sees at once. Every
reading here therefore goes to the authority itself, never through a cache:
identity status by a direct ``POST /v1/id-certificates/status`` judged by the
real chain verifier at age zero, team certificates by the uncached exact
status route, and a grant by a request signed with its own session key, which
the server judges at that moment.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from awid.did import did_key_from_signing_key
from awid.id_certificates import (
    IDChainEvidence,
    id_certificate_signing_bytes,
    verify_id_chain,
)
from awid.registry import RegistryClient
from awid.registry_types import RegistryError
from awid.signing import canonical_json_bytes, sign_message
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, running_registry
from nacl.signing import SigningKey
import pytest_asyncio
from redis.asyncio import Redis

from aweb.application_state import application_registry_client
from aweb.testing import running_server
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "docs/vectors/trust-web-cases-v2.json"
)
CORPUS = json.loads(CORPUS_PATH.read_text())
# The model's own emission (lake exe trust-web-cases), beside the hand-written
# seeds; its neighbours are its own cases.
MODEL_CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "docs/vectors/trust-web-cases-model-v2.json"
)
MODEL_CORPUS = json.loads(MODEL_CORPUS_PATH.read_text())
FORMAT_V1 = "aweb.trust-web-cases/1"
# /2 is /1 plus one optional case field, "propagation".
FORMAT_V2 = "aweb.trust-web-cases/2"
FORMATS = (FORMAT_V1, FORMAT_V2)
# "immediate": the code must decide at once, with no cache invalidated.
# "after": the code must agree once each accepted team-certificate revocation
# has propagated to the server's cached revocation list.
PROPAGATIONS = ("immediate", "after")

# ---------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------


class CaseFormatError(ValueError):
    """The case file is not a valid aweb.trust-web-cases/1 document."""


def _refuse(where: str, message: str) -> None:
    raise CaseFormatError(f"{where}: {message}")


def _fields(value: Any, expected: set[str], where: str) -> None:
    if type(value) is not dict or set(value) != expected:
        got = sorted(value) if type(value) is dict else type(value).__name__
        _refuse(where, f"fields {got} are not {sorted(expected)}")


def _symbol(value: Any, where: str) -> None:
    if type(value) is not str or not value:
        _refuse(where, f"{value!r} is not a symbol (a non-empty string)")


def _kind(value: Any, where: str) -> None:
    if value not in ("person", "agent"):
        _refuse(where, f"kind {value!r} is not person or agent")


def _team(value: Any, where: str) -> None:
    """The model's Team: "admin" or {"named": n}."""
    if value == "admin":
        return
    _fields(value, {"named"}, where)
    if type(value["named"]) is not int or value["named"] < 0:
        _refuse(where, f"team number {value['named']!r} is not a natural number")


def _issuer(value: Any, where: str) -> None:
    if value == "root":
        return
    _fields(value, {"member"}, where)
    _symbol(value["member"], f"{where} member")


def _record(spec: dict[str, Callable[[Any, str], None]]):
    def check(value: Any, where: str) -> None:
        _fields(value, set(spec), where)
        for name, field_check in spec.items():
            field_check(value[name], f"{where} {name}")

    return check


def _bool(value: Any, where: str) -> None:
    if type(value) is not bool:
        _refuse(where, f"{value!r} is not a boolean")


_cert = _record({"org": _symbol, "subject": _symbol, "kind": _kind, "issuer": _issuer})
_membership = _record({"org": _symbol, "team": _team, "member": _symbol})
_grant = _record(
    {
        "session": _symbol,
        "subject": _symbol,
        "org": _symbol,
        "team": _team,
        "maySend": _bool,
    }
)
_invite = _record({"token": _symbol, "org": _symbol, "team": _team})
_team_of = _record({"org": _symbol, "team": _team})


def _org_key(value: Any, where: str) -> None:
    """The model's OrgKey: {"root": org} or {"team": {"org", "team"}}."""
    if type(value) is not dict or len(value) != 1:
        _refuse(where, f"{value!r} is not an organisation key")
    [(form, inner)] = value.items()
    if form == "root":
        _symbol(inner, f"{where} root")
    elif form == "team":
        _team_of(inner, f"{where} team")
    else:
        _refuse(where, f"{form!r} is not an organisation key")


PARTY_FORMS: dict[str, Callable[[Any, str], None]] = {
    "dns": _symbol,
    "controller": _org_key,
    "id": _symbol,
    "session": _symbol,
    "bearer": _symbol,
}

# Every constructor of the model's Step (TrustWeb/Model.lean) and its arguments.
ACT_ARGS: dict[str, dict[str, Callable[[Any, str], None]]] = {
    "createOrg": {"org": _symbol},
    "replaceRoot": {"org": _symbol},
    "readmitByRoot": {"subject": _symbol},
    "readmitByParent": {"subject": _symbol},
    "release": {"key": _org_key},
    "entrust": {"key": _org_key},
    "registerByRoot": {"cert": _cert},
    "registerByParent": {"cert": _cert},
    "revokeSelf": {"subject": _symbol},
    "revokeChild": {"subject": _symbol},
    "revokeByOrg": {"subject": _symbol},
    "admit": {"membership": _membership},
    "admitAdmin": {"membership": _membership},
    "remove": {"membership": _membership},
    "leave": {"membership": _membership},
    "invite": {"invite": _invite},
    "redeem": {"invite": _invite, "member": _symbol},
    "mintGrant": {"grant": _grant},
    "revokeGrant": {"grant": _grant},
    "sendOwn": {},
    "sendGrant": {"session": _symbol},
}


def _issued_by(args: dict) -> dict | None:
    issuer = args["cert"]["issuer"]
    return None if issuer == "root" else {"id": issuer["member"]}


# Where a constructor builds its party from its arguments, the party a case
# names must be exactly that one: anything else is a different act.
FIXED_PARTY: dict[str, Callable[[dict], dict | None]] = {
    "createOrg": lambda args: {"dns": args["org"]},
    "replaceRoot": lambda args: {"dns": args["org"]},
    "entrust": lambda args: {"controller": args["key"]},
    "registerByParent": _issued_by,
    "revokeSelf": lambda args: {"id": args["subject"]},
    "leave": lambda args: {"id": args["membership"]["member"]},
    "redeem": lambda args: {"bearer": args["invite"]["token"]},
    "mintGrant": lambda args: {"id": args["grant"]["subject"]},
    "revokeGrant": lambda args: {"id": args["grant"]["subject"]},
    "sendGrant": lambda args: {"session": args["session"]},
}

# The premises a refusal may name, per constructor. Until the model names every
# premise of Step, only premises that are a definition of the model are
# nameable (agreed with the model's author, aweb-adyz).
PREMISES = {
    "registerByRoot": {"Issuer", "OrgExists", "Fresh", "Authorised"},
    "registerByParent": {"Issuer", "Asker", "Fresh", "Valid", "MayIssue"},
    "revokeSelf": {"Registered", "Asker"},
    "revokeChild": {"Registered", "Issuer", "Asker", "Valid"},
    "revokeByOrg": {"Registered", "Authorised"},
    "readmitByRoot": {"Authorised"},
    "readmitByParent": {"Valid"},
    "release": {"Authorised"},
    "admit": {"NotAdminTeam", "Authorised", "OneTeamIfLocal"},
    "admitAdmin": {"Valid", "Authorised"},
    "remove": {"Authorised", "KeepsAnAdmin"},
    "leave": {"KeepsAnAdmin"},
    "invite": {"Authorised"},
    "redeem": {"OneTeamIfLocal"},
    "mintGrant": {"Asker", "InTeam", "FreshSession"},
    "revokeGrant": {"Asker", "Stands"},
    "sendOwn": {"CanAct"},
}


def _cert_value(value: Any, where: str) -> None:
    if value is not None:
        _record({"org": _symbol, "kind": _kind, "issuer": _issuer})(value, where)


# Each predicate over the model's record: its arguments, and the type of 'is'.
OBSERVATIONS: dict[
    str, tuple[Callable[[Any, str], None], Callable[[Any, str], None]]
] = {
    "cert": (_record({"subject": _symbol}), _cert_value),
    "revoked": (_record({"key": _symbol}), _bool),
    "valid": (_record({"org": _symbol, "key": _symbol, "kind": _kind}), _bool),
    "canAct": (_record({"key": _symbol}), _bool),
    "hasTeamCert": (_record({"org": _symbol, "team": _team, "key": _symbol}), _bool),
    "inTeam": (_record({"org": _symbol, "team": _team, "key": _symbol}), _bool),
    "grant": (_record({"session": _symbol}), _bool),
    "grantLive": (_record({"session": _symbol}), _bool),
}

TOP_FIELDS = {"format", "status", "description", "model", "cases"}
MODEL_FIELDS = {"path", "commit", "emitter"}
CASE_FIELDS = {
    "id",
    "source",
    "status",
    "rule",
    "setup",
    "who",
    "act",
    "args",
    "expect",
    "observe",
}
REFUSAL_FIELDS = CASE_FIELDS | {"neighbour"}
RULES = {"any", "built", "admin", "team"}
# Only results that hold for every rule, or for the rule as built, can be run.
RUNNABLE_RULES = {"any", "built"}


@dataclass(frozen=True)
class Step:
    who: dict
    act: str
    args: dict


@dataclass(frozen=True)
class Observation:
    predicate: str
    args: dict
    expected: Any

    def label(self) -> str:
        return f"{self.predicate}({json.dumps(self.args, sort_keys=True)})"


@dataclass(frozen=True)
class Case:
    id: str
    source: str
    status: str
    rule: str
    setup: tuple[Step, ...]
    step: Step
    result: str
    premise: str | None
    neighbour: str | None
    observe: tuple[Observation, ...]
    propagation: str = "immediate"

    @property
    def runnable(self) -> bool:
        return self.status == "implemented"


def _party(value: Any, where: str) -> None:
    if type(value) is not dict or len(value) != 1 or set(value) - set(PARTY_FORMS):
        _refuse(where, f"party {value!r} is not one of {sorted(PARTY_FORMS)}")
    [(form, inner)] = value.items()
    PARTY_FORMS[form](inner, f"{where} party {form}")


# The premises whose failure is the very shape the format otherwise refuses: a
# certificate with the other kind of issuer, or a party other than the one the
# constructor builds. Only a refusal naming exactly that premise may have it.
ISSUER_PREMISES = {"registerByRoot.Issuer", "registerByParent.Issuer"}
ASKER_PREMISES = {
    "registerByParent.Asker",
    "registerByParent.Issuer",
    "revokeSelf.Asker",
    "mintGrant.Asker",
    "revokeGrant.Asker",
}


def _step(value: Any, where: str, refusing: str | None = None) -> Step:
    """One act; ``refusing`` is the premise a refused case names for it."""
    _fields(value, {"who", "act", "args"}, where)
    who, act, args = value["who"], value["act"], value["args"]
    _party(who, where)
    if act not in ACT_ARGS:
        _refuse(where, f"act {act!r} is not a model act")
    _record(ACT_ARGS[act])(args, f"{where} args of {act}")
    issuer_free = refusing in ISSUER_PREMISES
    if act == "registerByRoot" and args["cert"]["issuer"] != "root" and not issuer_free:
        _refuse(where, "registerByRoot registers a certificate issued by the root")
    if (
        act == "registerByParent"
        and args["cert"]["issuer"] == "root"
        and not issuer_free
    ):
        _refuse(where, "registerByParent registers a certificate issued by a member")
    fixed = FIXED_PARTY.get(act)
    if fixed is not None and who != fixed(args) and refusing not in ASKER_PREMISES:
        _refuse(
            where, f"party {who!r} is not the party {act} is asked by, {fixed(args)!r}"
        )
    return Step(who=who, act=act, args=args)


def _observation(value: Any, where: str) -> Observation:
    if type(value) is not dict or "is" not in value or len(value) != 2:
        _refuse(where, "an observation is one predicate and 'is'")
    [predicate] = [key for key in value if key != "is"]
    if predicate not in OBSERVATIONS:
        _refuse(where, f"observation {predicate!r} is not known")
    check_args, check_value = OBSERVATIONS[predicate]
    check_args(value[predicate], f"{where} observation {predicate}")
    check_value(value["is"], f"{where} observation {predicate} is")
    return Observation(predicate, value[predicate], value["is"])


def _case(value: Any, format: str) -> Case:
    where = f"case {value.get('id')!r}" if type(value) is dict else "case"
    expect = value.get("expect") if type(value) is dict else None
    refused = type(expect) is dict and expect.get("result") == "refused"
    expected = REFUSAL_FIELDS if refused else CASE_FIELDS
    if format == FORMAT_V2 and type(value) is dict and "propagation" in value:
        expected = expected | {"propagation"}
    _fields(value, expected, where)
    propagation = value.get("propagation", "immediate")
    if propagation not in PROPAGATIONS:
        _refuse(
            where, f"propagation {propagation!r} is not one of {list(PROPAGATIONS)}"
        )
    _symbol(value["id"], f"{where} id")
    if value["source"] not in {"seed", "emitted"}:
        _refuse(where, f"source {value['source']!r} is unknown")
    if value["status"] not in {"implemented", "design"}:
        _refuse(where, f"status {value['status']!r} is unknown")
    if value["rule"] not in RULES:
        _refuse(where, f"rule {value['rule']!r} is unknown")
    if value["status"] == "implemented" and value["rule"] not in RUNNABLE_RULES:
        _refuse(
            where,
            f"an implemented case's rule must be any or built, not {value['rule']!r}",
        )
    refusing = expect.get("premise") if refused else None
    step = _step({k: value[k] for k in ("who", "act", "args")}, where, refusing)
    if type(value["setup"]) is not list:
        _refuse(where, "setup must be a list of acts")
    setup = tuple(
        _step(item, f"{where} setup[{index}]")
        for index, item in enumerate(value["setup"])
    )
    premise = None
    if refused:
        _fields(expect, {"result", "premise"}, f"{where} expect")
        constructor, _, name = str(expect["premise"]).partition(".")
        if constructor != step.act or name not in PREMISES.get(step.act, set()):
            _refuse(
                where,
                f"premise {expect['premise']!r} is not a nameable premise of {step.act}",
            )
        premise = expect["premise"]
        _symbol(value["neighbour"], f"{where} neighbour")
    elif expect != {"result": "allowed"}:
        _refuse(where, f"result {expect!r} is neither allowed nor refused")
    if type(value["observe"]) is not list or not value["observe"]:
        _refuse(where, "a case needs at least one observation")
    observe = tuple(
        _observation(item, f"{where} observe[{index}]")
        for index, item in enumerate(value["observe"])
    )
    return Case(
        id=value["id"],
        source=value["source"],
        status=value["status"],
        rule=value["rule"],
        setup=setup,
        step=step,
        result="refused" if refused else "allowed",
        premise=premise,
        neighbour=value.get("neighbour"),
        observe=observe,
        propagation=propagation,
    )


def _model(value: Any, emitted: bool) -> None:
    _fields(value, MODEL_FIELDS, "model")
    _symbol(value["path"], "model path")
    commit = value["commit"]
    if (
        type(commit) is not str
        or len(commit) != 40
        or set(commit) - set("0123456789abcdef")
    ):
        _refuse("model commit", f"{commit!r} is not a full commit id")
    emitter = value["emitter"]
    if emitter is not None:
        _symbol(emitter, "model emitter")
    elif emitted:
        _refuse(
            "model emitter",
            "emitted cases need the emitter invocation that produced them",
        )


def load_corpus(corpus: Any) -> list[Case]:
    """Every case of an aweb.trust-web-cases/1 or /2 document, or CaseFormatError."""
    if type(corpus) is not dict or corpus.get("format") not in FORMATS:
        raise CaseFormatError(f"format is not one of {list(FORMATS)}")
    _fields(corpus, TOP_FIELDS, "document")
    if corpus["status"] != "experimental":
        raise CaseFormatError("document status must be experimental")
    if type(corpus["description"]) is not str:
        raise CaseFormatError("document description must be a string")
    if type(corpus["cases"]) is not list:
        raise CaseFormatError("cases must be a list")
    cases = [_case(value, corpus["format"]) for value in corpus["cases"]]
    _model(corpus["model"], emitted=any(case.source == "emitted" for case in cases))
    by_id: dict[str, Case] = {}
    for case in cases:
        if case.id in by_id:
            raise CaseFormatError(f"duplicate case id {case.id!r}")
        by_id[case.id] = case
    for case in cases:
        if case.result == "allowed":
            continue
        neighbour = by_id.get(case.neighbour)
        if neighbour is None:
            raise CaseFormatError(
                f"case {case.id!r}: neighbour {case.neighbour!r} is absent"
            )
        if neighbour.result != "allowed" or neighbour.step.act != case.step.act:
            raise CaseFormatError(
                f"case {case.id!r}: neighbour {neighbour.id!r} must be an allowed {case.step.act}"
            )
        if neighbour.status != case.status:
            raise CaseFormatError(
                f"case {case.id!r}: neighbour {neighbour.id!r} has status {neighbour.status}"
            )
    return cases


# ---------------------------------------------------------------------------
# Disagreements between the model and the code
# ---------------------------------------------------------------------------

# Cases the code decides differently, each with the task that files it. They
# are held out of the gate, which claims agreement only for the cases it runs,
# and run as ordinary failing comparisons by trust_web_disagreements.py
# (make test-trust-web-disagreements). A case returns to the gate when its task
# is decided and that run agrees.
#
# aweb-adyz.2: the server sees a team-certificate revocation only after its
# cached revocation list refreshes (60 s fresh, 60 s stale:
# docs/aweb-sot.md:448-466); the model assumes one current record (A4).
#
# aweb-adyz.1: AWID's team-certificate registration has no one-team check for
# a local member key (docs/identity.md:64-77).
# aweb-adyz.4: AWID has no admin team, so a plain admission adds an admin.
# aweb-adyz.5: AWID answers a namespace that does not exist as 503
# evidence_unavailable, not as a refusal.
DISAGREEMENTS: dict[str, str] = {
    "mint-grant-after-removal-refused": "aweb-adyz.2",
    "model-admit-local-member-to-second-team-refused": "aweb-adyz.1",
    "model-admit-to-admin-team-refused": "aweb-adyz.4",
    "model-register-person-in-missing-org-refused": "aweb-adyz.5",
}


def _cases_of(*corpora: dict) -> dict[str, Case]:
    """Every case of the given documents by id, each loaded on its own; an id
    in two documents is refused."""
    found: dict[str, Case] = {}
    for corpus in corpora:
        for case in load_corpus(corpus):
            if case.id in found:
                raise CaseFormatError(f"case id {case.id!r} is in two documents")
            found[case.id] = case
    return found


# The seeds and the model's emission: the cases the gate and the
# disagreement run draw from.
CASES = _cases_of(CORPUS, MODEL_CORPUS)


# ---------------------------------------------------------------------------
# The real stack
# ---------------------------------------------------------------------------


@dataclass
class Stack:
    registry: Any
    server: Any
    client: RegistryClient


@pytest_asyncio.fixture
async def stack_factory(test_db_factory, monkeypatch):
    """Each call: a real AWID and a real aweb server on fresh databases.

    The server verifies every team certificate against that AWID and requires
    it to be registered there (AWEB_REQUIRE_REGISTERED_CERTIFICATES).
    """
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/test")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AWID_REGISTRY_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "true")

    @asynccontextmanager
    async def start() -> AsyncIterator[Stack]:
        suffix = uuid4().hex[:8]
        awid_db = await test_db_factory.create_db(suffix=f"trust_web_awid_{suffix}")
        server_db = await test_db_factory.create_db(suffix=f"trust_web_aweb_{suffix}")
        async with Redis.from_url(
            os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            decode_responses=True,
        ) as redis:
            async with running_registry(
                awid_db.config.get_dsn(), redis=redis
            ) as registry:
                async with running_server(
                    server_db.config.get_dsn(), redis, awid_transport=registry.transport
                ) as server:
                    client = RegistryClient(
                        registry_url=REGISTRY_URL, transport=registry.transport
                    )
                    try:
                        yield Stack(registry=registry, server=server, client=client)
                    finally:
                        await client.aclose()

    return start


# ---------------------------------------------------------------------------
# Running a case
# ---------------------------------------------------------------------------


class NotRunnable(Exception):
    """The case is not one the runner may send."""


class SetupRefused(AssertionError):
    """A setup act, which the case says is allowed, was refused."""


class Unavailable(AssertionError):
    """An observation could not be read; it is not a false predicate."""


@dataclass(frozen=True)
class Refusal:
    status: int
    code: str | None
    detail: str

    def describe(self) -> str:
        return f"{self.status} {self.code or repr(self.detail)}"


@dataclass(frozen=True)
class Run:
    refusal: Refusal | None
    before: dict[str, Any]
    after: dict[str, Any]
    # For each observation read through the server after the act: how many
    # reads of its team's revocation list that observation's own request made.
    revocation_reads: dict[str, int] = field(default_factory=dict)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signer(key: SigningKey) -> Callable[[bytes], tuple[str, bytes]]:
    return lambda payload: (
        did_key_from_signing_key(bytes(key)),
        key.sign(payload).signature,
    )


def _team_name(team: str | dict) -> str:
    """The registry name of a model team: ``"admin"`` or ``{"named": n}``."""
    if team == "admin":
        return "admin"
    return f"t{team['named']}"


@dataclass
class _Identity:
    org: str
    did_aw: str
    chain: list[dict]
    # The member that issued it, or None when the root did.
    issuer: str | None


@dataclass
class _Membership:
    team_id: str
    certificate_id: str
    certificate: dict


@dataclass
class _Grant:
    grant_id: str
    team_id: str
    # The model's grant this real grant was minted for.
    binding: dict


@dataclass
class World:
    """The model's symbols bound to real keys, domains and records of one stack."""

    stack: Stack
    keys: dict[str, SigningKey] = field(default_factory=dict)
    domains: dict[str, str] = field(default_factory=dict)
    roots: dict[str, SigningKey] = field(default_factory=dict)
    team_keys: dict[str, SigningKey] = field(default_factory=dict)
    identities: dict[str, _Identity] = field(default_factory=dict)
    did_aws: dict[str, tuple[str, str]] = field(default_factory=dict)
    memberships: dict[tuple[str, str], _Membership] = field(default_factory=dict)
    sessions: dict[str, dict] = field(default_factory=dict)
    # Teams whose accepted revocation was propagated by invalidating the
    # server's cached list, and whose re-read no observation has shown yet.
    awaiting_reread: set[str] = field(default_factory=set)
    propagate: bool = False
    last_revocation_reads: int = 0
    session_keys: dict[str, SigningKey] = field(default_factory=dict)
    issued: dict[str, datetime] = field(default_factory=dict)
    grants: dict[str, _Grant] = field(default_factory=dict)

    # -- symbols ----------------------------------------------------------

    def key(self, symbol: str) -> SigningKey:
        return self.keys.setdefault(symbol, SigningKey.generate())

    def did_key(self, symbol: str) -> str:
        return did_key_from_signing_key(bytes(self.key(symbol)))

    def issue_time(self, subject: str) -> str:
        """A certificate time for ``subject`` later than any it was issued:
        AWID takes a byte-identical certificate again as a retry of the same
        registration, so each act signs its own, to the second."""
        now = datetime.now(timezone.utc).replace(microsecond=0)
        last = self.issued.get(subject)
        if last is not None and now <= last:
            now = last + timedelta(seconds=1)
        self.issued[subject] = now
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def root_key(self, org: str) -> SigningKey:
        """``org``'s root key, which exists before the organisation is created
        and signs as that root even if it never is."""
        return self.roots.setdefault(org, SigningKey.generate())

    def session_key(self, session: str) -> SigningKey:
        return self.session_keys.setdefault(session, SigningKey.generate())

    def domain(self, org: str) -> str:
        return self.domains.setdefault(org, f"{org}-{uuid4().hex[:10]}.trust-web.test")

    def symbol_of_did_aw(self, did_aw: str) -> str:
        [symbol] = [s for s, (d, _) in self.did_aws.items() if d == did_aw]
        return symbol

    def party_key(self, who: dict) -> SigningKey:
        """The key whoever ``who`` names signs with."""
        if "id" in who:
            return self.key(who["id"])
        if "controller" in who:
            controlled = who["controller"]
            if "root" in controlled:
                return self.root_key(controlled["root"])
            team = controlled["team"]
            return self.team_keys[self.team_id(team["org"], team["team"])]
        raise NotRunnable(f"party {who!r} has no key in the runner")

    # -- wire prerequisites the model has no act for ----------------------

    async def did_aw(self, symbol: str, org: str) -> str:
        """Register ``symbol``'s did:aw through AWID's own route, once, for
        an identity in ``org``."""
        if symbol not in self.did_aws:
            did_aw = await self.stack.registry.register_did(self.key(symbol))
            self.did_aws[symbol] = (did_aw, org)
        return self.did_aws[symbol][0]

    def team_id(self, org: str, team: dict) -> str:
        return f"{_team_name(team)}:{self.domain(org)}"

    async def ensure_team(self, org: str, team: dict) -> str:
        """Create the team by its namespace controller, once (docs/identity.md:95-100)."""
        team_id = self.team_id(org, team)
        if team_id not in self.team_keys:
            self.team_keys[team_id] = SigningKey.generate()
            await self.stack.registry.add_team(
                team_id,
                did_key_from_signing_key(bytes(self.team_keys[team_id])),
                namespace_controller=self.roots[org],
            )
        return team_id

    async def ensure_teams(self, step: Step) -> None:
        """Every team a step names exists before the step is sent."""
        controlled = step.who.get("controller", {})
        if "team" in controlled:
            await self.ensure_team(
                controlled["team"]["org"], controlled["team"]["team"]
            )
        membership = step.args.get("membership") or step.args.get("grant")
        if membership is not None:
            await self.ensure_team(membership["org"], membership["team"])
        grant = step.args.get("grant")
        if grant is not None:
            # A session names one model grant, so it can be observed before
            # the grant exists.
            bound = self.sessions.setdefault(grant["session"], grant)
            if bound != grant:
                raise NotRunnable(
                    f"session {grant['session']} names two grants: {bound!r} and {grant!r}"
                )

    def membership(self, org: str, team: dict, member: str) -> _Membership:
        team_id = self.team_id(org, team)
        found = self.memberships.get((team_id, member))
        if found is None:
            found = _Membership(
                team_id=team_id,
                certificate_id=f"tw-{uuid4().hex}",
                certificate={},
            )
            self.memberships[(team_id, member)] = found
        return found

    def team_headers(
        self, member: str, team_id: str, body: bytes, signer: str | None = None
    ) -> dict:
        """A request presenting ``member``'s certificate, signed by ``signer``
        (the member itself unless another party asks in its name)."""
        certificate = self.memberships[(team_id, member)].certificate
        signer = member if signer is None else signer
        return {
            **_signed_team_headers(
                bytes(self.key(signer)),
                self.did_key(signer),
                team_id,
                _encode_certificate(certificate),
                body,
            ),
            "Content-Type": "application/json",
        }

    async def connect(self, member: str, team_id: str) -> None:
        """The admitted member's team server learns it, through POST /v1/connect."""
        body = json.dumps({"hostname": "trust-web"}).encode()
        async with self.stack.server.client() as client:
            response = await client.post(
                "/v1/connect",
                content=body,
                headers=self.team_headers(member, team_id, body),
            )
        if response.status_code != 200:
            raise SetupRefused(
                f"connect {member} to {team_id}: {response.status_code} {response.text}"
            )

    # -- acts ---------------------------------------------------------------

    async def perform(self, step: Step) -> Refusal | None:
        """Send one model act; None when accepted, its refusal otherwise."""
        act = getattr(self, f"_act_{step.act}", None)
        if act is None:
            raise NotRunnable(f"act {step.act} has no route in the runner")
        try:
            await act(step)
        except RegistryError as refused:
            return Refusal(refused.status_code, refused.code, str(refused.detail))
        except _ServerRefusal as refused:
            return refused.refusal
        return None

    async def _act_createOrg(self, step: Step) -> None:
        org = step.args["org"]
        await self.stack.registry.ensure_namespace(
            domain=self.domain(org), controller=bytes(self.root_key(org))
        )

    async def _register(self, step: Step, parent_chain: list[dict]) -> None:
        cert = step.args["cert"]
        subject = cert["subject"]
        did_aw = await self.did_aw(subject, cert["org"])
        domain = self.domain(cert["org"])
        issuer = cert["issuer"]
        if issuer == "root":
            parent = {"kind": "namespace", "id": domain}
        else:
            # A member that holds no certificate is still named by its did:aw.
            member = issuer["member"]
            known = self.identities.get(member)
            parent_id = (
                known.did_aw if known else await self.did_aw(member, cert["org"])
            )
            parent = {"kind": "identity", "id": parent_id}
        signer = self.party_key(step.who)
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": did_aw,
            "domain": domain,
            "parent": parent,
            "kind": {"person": "human", "agent": "agent"}[cert["kind"]],
            "issuer_key": did_key_from_signing_key(bytes(signer)),
            "issued_at": self.issue_time(subject),
        }
        signed = {
            "certificate": fields,
            "signature": _b64url(
                signer.sign(id_certificate_signing_bytes(fields)).signature
            ),
        }
        chain = [*parent_chain, signed]
        # The model's actor signs the certificate; the subject's own key signs
        # the covering request, which is how AWID checks the subject holds it.
        await self.stack.client.register_id_certificate(
            {"v": 1, "type": "aweb.id-chain", "certificates": chain},
            signer=_signer(self.key(subject)),
            expected_head=None,
            invitation_id=None,
        )
        self.identities[subject] = _Identity(
            org=cert["org"],
            did_aw=did_aw,
            chain=chain,
            issuer=None if issuer == "root" else issuer["member"],
        )

    async def _act_registerByRoot(self, step: Step) -> None:
        await self._register(step, [])

    async def _act_registerByParent(self, step: Step) -> None:
        issuer = step.args["cert"]["issuer"]
        # A root-issued certificate asked by a member presents no ancestry.
        parent = None if issuer == "root" else self.identities.get(issuer["member"])
        await self._register(step, parent.chain if parent else [])

    async def _revoke(self, step: Step) -> None:
        symbol = step.args["subject"]
        subject = self.identities.get(symbol)
        if subject is None:
            # No certificate stands for it, so no head is named: the request
            # revokes its did:aw in the namespace it was given.
            did_aw, org = self.did_aws[symbol]
            expected_head = None
        else:
            did_aw, org = subject.did_aw, subject.org
            # AWID revokes only the head the request names: the subject's
            # current certificate, read from the registry's own status.
            entry = self._entry(await self._status(symbol), did_aw)
            if entry is None:
                raise Unavailable(f"no current certificate to revoke for {symbol}")
            expected_head = entry["current_certificate_id"]
        await self.stack.client.revoke_id_certificate(
            self.domain(org),
            did_aw,
            signer=_signer(self.party_key(step.who)),
            expected_head=expected_head,
        )

    # One identity-revocation route serves the three constructors: a request
    # names the subject and is signed by whoever asks.
    _act_revokeSelf = _revoke
    _act_revokeChild = _revoke
    _act_revokeByOrg = _revoke

    async def _act_admit(self, step: Step) -> None:
        m = step.args["membership"]
        membership = self.membership(m["org"], m["team"], m["member"])
        signer = self.party_key(step.who)
        # The certificate is always the team's own, signed by its key; only the
        # party asking for its registration is the case's. A local member: a
        # did:key with no did:aw, in this one team.
        team_key = self.team_keys[membership.team_id]
        certificate = _make_certificate(
            bytes(team_key),
            did_key_from_signing_key(bytes(team_key)),
            self.did_key(m["member"]),
            certificate_id=membership.certificate_id,
            team_id=membership.team_id,
            alias=m["member"],
            identity_scope="local",
        )
        name, domain = membership.team_id.split(":", 1)
        await self.stack.client.register_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(signer),
            certificate_id=membership.certificate_id,
            member_did_key=self.did_key(m["member"]),
            member_did_aw=None,
            member_address=None,
            alias=m["member"],
            identity_scope="local",
            certificate=base64.b64encode(canonical_json_bytes(certificate)).decode(
                "ascii"
            ),
        )
        membership.certificate = certificate
        await self.connect(m["member"], membership.team_id)

    async def _act_remove(self, step: Step) -> None:
        m = step.args["membership"]
        membership = self.membership(m["org"], m["team"], m["member"])
        name, domain = membership.team_id.split(":", 1)
        await self.stack.client.revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(self.party_key(step.who)),
            certificate_id=membership.certificate_id,
        )
        if self.propagate:
            await self._propagate(membership.team_id)

    async def _propagate(self, team_id: str) -> None:
        """Arrange the state after the accepted revocation has propagated:
        drop the server's cached revocation reads for the team, through its
        registry client's public invalidation (awid/src/awid/registry.py,
        RegistryClient.invalidate_team_certificate_cache). It also drops the
        team's cached key and certificate generations. This is a fixture
        step: the server's next read of the team must go to AWID, which the
        observation that follows has to show."""
        name, domain = team_id.split(":", 1)
        client = application_registry_client(self.stack.server.app.state)
        await client.invalidate_team_certificate_cache(domain, name)
        self.awaiting_reread.add(team_id)

    def _revocation_reads(self, team_id: str, since: int) -> int:
        name, domain = team_id.split(":", 1)
        path = f"/v1/namespaces/{domain}/teams/{name}/revocations"
        return sum(
            1
            for request in self.stack.registry.transport.calls[since:]
            if request.url.path == path
        )

    async def _through_server(self, team_id: str, read):
        """Run one server request for an observation of ``team_id`` and count
        the team's revocation reads it made. After a propagation, the first
        such observation must show the server read the team from AWID."""
        since = len(self.stack.registry.transport.calls)
        value = await read()
        self.last_revocation_reads = self._revocation_reads(team_id, since)
        if team_id in self.awaiting_reread:
            if self.last_revocation_reads == 0:
                raise Unavailable(
                    f"after-propagation case unarranged: the observation's request "
                    f"made no revocations read for {team_id}"
                )
            self.awaiting_reread.discard(team_id)
        return value

    async def _server(self, method: str, path: str, headers: dict, body: bytes) -> dict:
        async with self.stack.server.client() as client:
            response = await client.request(method, path, content=body, headers=headers)
        if response.status_code >= 300:
            raise _ServerRefusal(_server_refusal(response))
        return response.json()

    async def _act_mintGrant(self, step: Step) -> None:
        g = step.args["grant"]
        if g["maySend"] is not True:
            raise NotRunnable("the runner mints only a sending grant")
        team_id = self.team_id(g["org"], g["team"])
        body = json.dumps(
            {
                "grant_did_key": did_key_from_signing_key(
                    bytes(self.session_key(g["session"]))
                ),
                "scopes": GRANT_SCOPES,
                "ttl_seconds": GRANT_TTL_SECONDS,
            }
        ).encode()
        if (team_id, g["subject"]) not in self.memberships:
            raise NotRunnable(f"{g['subject']} holds no certificate of {team_id}")
        # A grant's subject is whoever's certificate signs the mint; another
        # party can ask only by presenting the subject's certificate.
        minted = await self._server(
            "POST",
            "/v1/identity-grants",
            self.team_headers(g["subject"], team_id, body, signer=step.who["id"]),
            body,
        )
        self.grants[g["session"]] = _Grant(
            grant_id=minted["grant_id"], team_id=team_id, binding=g
        )

    async def _act_revokeGrant(self, step: Step) -> None:
        g = step.args["grant"]
        grant = self.grants.get(g["session"])
        if grant is None:
            # No grant stands for the session, so the request names a grant
            # id the server never issued.
            team_id = self.team_id(g["org"], g["team"])
            grant = _Grant(grant_id=str(uuid4()), team_id=team_id, binding=g)
        if (grant.team_id, g["subject"]) not in self.memberships:
            raise NotRunnable(f"{g['subject']} holds no certificate of {grant.team_id}")
        if grant.binding != g:
            raise NotRunnable(
                f"revokeGrant names {g!r}, but session {g['session']} holds {grant.binding!r}"
            )
        # The grant's subject's certificate, signed by whoever asks: the
        # subject itself unless the case names another party.
        await self._server(
            "POST",
            f"/v1/identity-grants/{grant.grant_id}/revoke",
            self.team_headers(g["subject"], grant.team_id, b"", signer=step.who["id"]),
            b"",
        )

    # -- observations ---------------------------------------------------

    async def observe(self, observation: Observation) -> Any:
        reader = getattr(self, f"_read_{observation.predicate}", None)
        if reader is None:
            raise NotRunnable(
                f"observation {observation.predicate} has no reading in the runner"
            )
        return await reader(observation.args)

    async def _status(self, symbol: str) -> dict:
        """The registry's own current answer for ``symbol``'s identity, uncached."""
        if symbol not in self.did_aws:
            # Identity status is asked by did:aw; a key with none cannot be asked.
            raise NotRunnable(
                f"{symbol} has no did:aw, so the registry cannot be asked about it"
            )
        did_aw, org = self.did_aws[symbol]
        domain = self.domain(org)
        try:
            return await self.stack.client.fetch_id_certificate_status(
                domain,
                {"v": 1, "domain": domain, "ids": [did_aw]},
                registry_origin=REGISTRY_URL,
            )
        except RegistryError as error:
            raise Unavailable(
                f"identity status of {symbol}: {error.status_code} {error.detail}"
            ) from error

    @staticmethod
    def _entry(status: dict, did_aw: str) -> dict | None:
        found = [entry for entry in status["identities"] if entry["id"] == did_aw]
        return found[0] if found else None

    async def _read_cert(self, args: dict) -> dict | None:
        symbol = args["subject"]
        status = await self._status(symbol)
        did_aw, org = self.did_aws[symbol]
        entry = self._entry(status, did_aw)
        if entry is None:
            return None
        [current] = [c for c in entry["certificates"] if c["superseded_at"] is None]
        cert = current["signed"]["certificate"]
        parent = cert["parent"]
        return {
            "org": org,
            "kind": {"human": "person", "agent": "agent"}[cert["kind"]],
            "issuer": "root"
            if parent["kind"] == "namespace"
            else {"member": self.symbol_of_did_aw(parent["id"])},
        }

    async def _read_revoked(self, args: dict) -> bool:
        symbol = args["key"]
        status = await self._status(symbol)
        entry = self._entry(status, self.did_aws[symbol][0])
        return entry is not None and entry["revocation"] is not None

    async def _read_valid(self, args: dict) -> bool:
        symbol = args["key"]
        status = await self._status(symbol)
        did_aw, org = self.did_aws[symbol]
        if self._entry(status, did_aw) is None:
            # The registry holds no identity certificate for it.
            return False
        identity = self.identities[symbol]
        if org != args["org"]:
            return False
        verdict = verify_id_chain(
            {"v": 1, "type": "aweb.id-chain", "certificates": identity.chain},
            subject={"id": identity.did_aw, "did_key": self.did_key(symbol)},
            evidence=IDChainEvidence(
                status=status,
                namespace_authority={
                    "domain": self.domain(identity.org),
                    "dns_name": f"_awid.{self.domain(identity.org)}",
                    "inherited": False,
                    "controller_key": did_key_from_signing_key(
                        bytes(self.roots[identity.org])
                    ),
                },
                age_seconds=0,
            ),
            domain=self.domain(identity.org),
        )
        if verdict["identity_valid"] is None:
            raise Unavailable(f"chain verdict of {symbol}: {verdict['reason']}")
        kind = {"human": "person", "agent": "agent"}.get(verdict["kind"])
        return verdict["identity_valid"] is True and kind == args["kind"]

    async def _read_hasTeamCert(self, args: dict) -> bool:
        membership = self.membership(args["org"], args["team"], args["key"])
        name, domain = membership.team_id.split(":", 1)
        status = await self.stack.client.get_team_certificate_status_fresh(
            domain, name, membership.certificate_id, registry_url=REGISTRY_URL
        )
        return status is not None and status["status"] == "active"

    async def _subject_read(self, session: str, path: str) -> dict:
        """A read of ``session``'s grant by its subject, signed with the
        subject's own team certificate."""
        bound = self.sessions.get(session)
        if bound is None:
            raise NotRunnable(f"session {session} names no grant in the case")
        team_id = self.team_id(bound["org"], bound["team"])
        if (team_id, bound["subject"]) not in self.memberships:
            raise NotRunnable(f"{bound['subject']} holds no certificate of {team_id}")

        async def read():
            async with self.stack.server.client() as client:
                return await client.get(
                    path, headers=self.team_headers(bound["subject"], team_id, b"")
                )

        response = await self._through_server(team_id, read)
        if response.status_code != 200:
            raise Unavailable(
                f"grant {session} as read by {bound['subject']}: "
                f"{response.status_code} {response.text}"
            )
        return response.json()

    async def _read_grant(self, args: dict) -> bool:
        """Whether the grant stands in the server's record, as its subject reads it.

        A minted grant is read by its exact status: standing is unrevoked and
        effectively active, gone is revoked with a revocation time. Before any
        grant was minted for the session, its subject's own list must hold no
        unrevoked grant for the session's key.
        """
        session = args["session"]
        grant = self.grants.get(session)
        if grant is None:
            listed = await self._subject_read(session, "/v1/identity-grants")
            key = did_key_from_signing_key(bytes(self.session_key(session)))
            unrevoked = [
                g
                for g in listed["grants"]
                if g["grant_did_key"] == key and g["revoked_at"] is None
            ]
            if unrevoked:
                raise Unavailable(
                    f"session {session} has a grant the runner was not given"
                )
            return False
        status = await self._subject_read(
            session, f"/v1/identity-grants/{grant.grant_id}/status"
        )
        if status["revoked_at"] is None and status["effective_status"] == "active":
            return True
        if status["revoked_at"] is not None and status["effective_status"] == "revoked":
            return False
        raise Unavailable(
            f"grant {session}: revoked_at {status['revoked_at']!r}, "
            f"effective_status {status['effective_status']!r}"
        )

    async def _read_grantLive(self, args: dict) -> bool:
        """Whether the server lets the grant's session key act now: a read the
        grant's scopes allow, signed with that key, changing nothing.

        This goes through the server's ordinary request path, so it sees team
        revocations only as the server's cached revocation list does. Only the
        refusals that state the grant's own end count as not live; any other
        refusal, and a session never answered with a grant, cannot be read.
        """
        grant = self.grants.get(args["session"])
        if grant is None:
            raise Unavailable(
                f"session {args['session']} has no grant to use: the runner cannot try it"
            )
        path = "/v1/messages/inbox"
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = canonical_json_bytes(
            {
                "v": 1,
                "auth": "identity-grant",
                "method": "GET",
                "path": path,
                "grant_id": grant.grant_id,
                "body_sha256": hashlib.sha256(b"").hexdigest(),
                "timestamp": timestamp,
                "aud": self.stack.server.url,
            }
        )
        session = self.session_key(args["session"])
        did_key = did_key_from_signing_key(bytes(session))
        headers = {
            "Authorization": f"AWEB-Grant DIDKey {did_key} {sign_message(bytes(session), payload)}",
            "X-AWEB-Grant-ID": grant.grant_id,
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": _b64url(payload),
        }

        async def read():
            async with self.stack.server.client() as client:
                return await client.get(path, headers=headers)

        response = await self._through_server(grant.team_id, read)
        if response.status_code == 200:
            return True
        detail = response.json().get("detail") if response.status_code == 403 else None
        if isinstance(detail, str) and detail.startswith(GRANT_ENDED):
            return False
        raise Unavailable(
            f"grant {args['session']}: {response.status_code} {response.text}"
        )


# The grant-use refusals that state the grant has ended: revoked itself, or
# its issuing certificate revoked or superseded
# (server/src/aweb/identity_grant_auth.py:236-259).
GRANT_ENDED = ("grant revoked", "grant issuing certificate revoked.")
GRANT_SCOPES = ["mail.read", "mail.send"]
GRANT_TTL_SECONDS = 3600


class _ServerRefusal(Exception):
    def __init__(self, refusal: Refusal) -> None:
        super().__init__(refusal.describe())
        self.refusal = refusal


def _server_refusal(response) -> Refusal:
    detail = response.json().get("detail")
    if isinstance(detail, dict):
        return Refusal(
            response.status_code, detail.get("code"), str(detail.get("message"))
        )
    return Refusal(response.status_code, None, str(detail))


async def run_case(stack: Stack, case: Case) -> Run:
    """Replay ``case``'s setup, read its observations, send its act, read them again."""
    if not case.runnable:
        raise NotRunnable(f"case {case.id} is a design case and is never sent")
    world = World(stack, propagate=case.propagation == "after")
    for index, step in enumerate(case.setup):
        await world.ensure_teams(step)
        refusal = await world.perform(step)
        if refusal is not None:
            raise SetupRefused(
                f"setup[{index}] {step.act} by {step.who} refused: {refusal.describe()} {refusal.detail}"
            )
    await world.ensure_teams(case.step)
    if case.step.act in ("registerByRoot", "registerByParent"):
        # The subject's did:aw is a wire prerequisite of the registration,
        # registered before the record is first observed.
        cert = case.step.args["cert"]
        await world.did_aw(cert["subject"], cert["org"])
    if (
        case.step.act in REVOCATIONS
        and case.step.args["subject"] not in world.identities
    ):
        # A revocation of a subject that holds no certificate still names a
        # did:aw: the subject's, registered in the case's one organisation.
        await world.did_aw(case.step.args["subject"], _only_org(case))
    before = {o.label(): await world.observe(o) for o in case.observe}
    refusal = await world.perform(case.step)
    after: dict[str, Any] = {}
    reads: dict[str, int] = {}
    for observation in case.observe:
        world.last_revocation_reads = 0
        after[observation.label()] = await world.observe(observation)
        if observation.predicate in SERVER_OBSERVATIONS:
            reads[observation.label()] = world.last_revocation_reads
    return Run(refusal=refusal, before=before, after=after, revocation_reads=reads)


REVOCATIONS = ("revokeSelf", "revokeChild", "revokeByOrg")


def _only_org(case: Case) -> str:
    """The one organisation ``case`` creates; a subject with no certificate has
    no organisation of its own, and the model's premise names none."""
    orgs = [step.args["org"] for step in case.setup if step.act == "createOrg"]
    if len(orgs) != 1:
        raise NotRunnable(
            f"{case.step.args['subject']} holds no certificate and the case "
            f"creates {len(orgs)} organisations, so no namespace names it"
        )
    return orgs[0]


# The observations read through the aweb server, and so through its cached
# view of team revocations.
SERVER_OBSERVATIONS = ("grant", "grantLive")


# ---------------------------------------------------------------------------
# Comparing a run with its case
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WireRefusal:
    """A refusal a premise's failure is expected to produce at its route:
    the status with the structured code, or with the released detail where
    the route sends no code."""

    status: int
    code: str | None = None
    detail: str | None = None
    source: str = ""

    def matches(self, refusal: Refusal) -> bool:
        if refusal.status != self.status:
            return False
        if self.code is not None:
            return refusal.code == self.code
        return refusal.code is None and refusal.detail == self.detail

    def describe(self) -> str:
        return f"{self.status} {self.code or repr(self.detail)}"


@dataclass(frozen=True)
class PremiseRefusals:
    """Every reviewed wire form of one premise's failure. A premise has more
    than one only where the route tells apart cases the model's premise joins."""

    forms: tuple[WireRefusal, ...]

    def matches(self, refusal: Refusal) -> bool:
        return any(form.matches(refusal) for form in self.forms)

    def describe(self) -> str:
        return " or ".join(form.describe() for form in self.forms)


TEAM_CONTROLLER_ONLY = PremiseRefusals(
    (
        WireRefusal(
            403,
            detail="Only the team controller can perform this action",
            source="awid/src/awid_service/routes/teams.py:143-148",
        ),
    )
)

SUBJECT_HAS_A_HEAD = PremiseRefusals(
    (
        WireRefusal(
            409,
            code="head_conflict",
            source="awid/src/awid_service/id_registration.py:88-106",
        ),
    )
)

NO_SUCH_ID = PremiseRefusals(
    (
        WireRefusal(
            404,
            code="unknown_id",
            source="awid/src/awid_service/id_revocation.py:70-71",
        ),
    )
)

NOT_A_REVOKER = PremiseRefusals(
    (
        WireRefusal(
            403,
            code="revocation_forbidden",
            source="awid/src/awid_service/id_revocation.py:141-156",
        ),
    )
)

NOT_THE_CERTIFICATES_KEY = PremiseRefusals(
    (
        WireRefusal(
            401,
            detail="member_key_mismatch",
            source="awid/src/awid/team_certificate.py:292-293, 356-367",
        ),
    )
)

# Reviewed: each entry cites where its route refuses for that premise.
REFUSALS: dict[str, PremiseRefusals] = {
    "registerByRoot.Authorised": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="issuer_key_not_current",
                source="awid/src/awid_service/id_registration.py:197-201",
            ),
        )
    ),
    "registerByParent.MayIssue": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="human_issuer_is_agent",
                source="awid/src/awid_service/id_registration.py:220-221",
            ),
        )
    ),
    # The model's Valid parent: the registry refuses a revoked parent itself,
    # then the parent's whole current chain with the verifier's reason.
    "registerByParent.Valid": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="parent_revoked",
                source="awid/src/awid_service/id_registration.py:222-223",
            ),
            WireRefusal(
                422,
                code="revoked",
                source="awid/src/awid_service/id_registration.py:116-130, "
                "awid/src/awid/id_certificates.py:857-859",
            ),
        )
    ),
    "revokeChild.Valid": PremiseRefusals(
        (
            WireRefusal(
                403,
                code="revocation_forbidden",
                source="awid/src/awid_service/id_revocation.py:86-98",
            ),
        )
    ),
    "admit.Authorised": TEAM_CONTROLLER_ONLY,
    "remove.Authorised": TEAM_CONTROLLER_ONLY,
    "mintGrant.InTeam": PremiseRefusals(
        (
            WireRefusal(
                401,
                code="certificate_revoked",
                source="server/src/aweb/team_auth.py:40-47",
            ),
        )
    ),
    # A root-issued request names its namespace as parent; a certificate whose
    # parent is a member presents that member's chain, and the root's request
    # has none to present.
    "registerByRoot.Issuer": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="missing_parent",
                source="awid/src/awid_service/id_chains.py:30-32",
            ),
        )
    ),
    # A registration names the head it replaces; a first registration names
    # none, and the subject's standing head refuses it.
    "registerByRoot.Fresh": SUBJECT_HAS_A_HEAD,
    "registerByParent.Fresh": SUBJECT_HAS_A_HEAD,
    # A member signing a namespace-parented certificate does not hold the
    # namespace's root key.
    "registerByParent.Issuer": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="issuer_key_not_current",
                source="awid/src/awid_service/id_registration.py:196-199",
            ),
        )
    ),
    # A party signing a certificate whose parent is another member does not
    # hold that parent's key.
    "registerByParent.Asker": PremiseRefusals(
        (
            WireRefusal(
                422,
                code="issuer_key_not_current",
                source="awid/src/awid_service/id_registration.py:225-226",
            ),
        )
    ),
    "revokeSelf.Registered": NO_SUCH_ID,
    "revokeChild.Registered": NO_SUCH_ID,
    "revokeByOrg.Registered": NO_SUCH_ID,
    # The signer is none of the subject, its current parent and the root.
    "revokeSelf.Asker": NOT_A_REVOKER,
    "revokeChild.Issuer": NOT_A_REVOKER,
    "revokeChild.Asker": NOT_A_REVOKER,
    "revokeByOrg.Authorised": NOT_A_REVOKER,
    # The subject's certificate presented under another party's key.
    "mintGrant.Asker": NOT_THE_CERTIFICATES_KEY,
    "revokeGrant.Asker": NOT_THE_CERTIFICATES_KEY,
    "mintGrant.FreshSession": PremiseRefusals(
        (
            WireRefusal(
                409,
                detail="an active grant already exists for this grant_did_key",
                source="server/src/aweb/routes/identity_grants.py:136-152",
            ),
        )
    ),
    "revokeGrant.Stands": PremiseRefusals(
        (
            WireRefusal(
                404,
                detail="grant not found",
                source="server/src/aweb/routes/identity_grants.py:300-312",
            ),
        )
    ),
}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def compare(case: Case, run: Run) -> list[str]:
    """Every way ``run`` differs from what ``case`` expects; empty when it agrees."""
    mismatches: list[str] = []
    if case.result == "allowed":
        if run.refusal is not None:
            mismatches.append(
                f"decision: expected allowed, code refused with {run.refusal.describe()}"
            )
    elif run.refusal is None:
        mismatches.append(f"decision: expected refused ({case.premise}), code allowed")
    else:
        expected = REFUSALS.get(case.premise)
        if expected is None:
            mismatches.append(
                f"reason: no reviewed wire refusal for premise {case.premise}; "
                f"code refused with {run.refusal.describe()} {run.refusal.detail!r}"
            )
        elif not expected.matches(run.refusal):
            mismatches.append(
                f"reason: premise {case.premise} expects {expected.describe()}, "
                f"code refused with {run.refusal.describe()}"
            )
    for observation in case.observe:
        label, expected = observation.label(), observation.expected
        before, after = run.before[label], run.after[label]
        if after != expected:
            mismatches.append(
                f"observe {label}: expected after {_json(expected)}, read {_json(after)}"
            )
        if case.result == "allowed" and before == expected:
            # An observation that already held cannot prove the act's effect.
            mismatches.append(
                f"observe {label}: already {_json(before)} before the act"
            )
        if case.result == "refused" and before != expected:
            mismatches.append(
                f"observe {label}: expected before {_json(expected)}, read {_json(before)}"
            )
    return mismatches
