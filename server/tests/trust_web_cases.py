"""The trust-web model's cases, and the runner that executes them for real.

The cases are ``docs/vectors/trust-web-cases-v1.json`` (format
``aweb.trust-web-cases/1``, specified in docs/vectors/README.md). A case is
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
from datetime import datetime, timezone
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

from aweb.testing import running_server
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _signed_team_headers,
)

CORPUS_PATH = (
    Path(__file__).resolve().parents[2] / "docs/vectors/trust-web-cases-v1.json"
)
CORPUS = json.loads(CORPUS_PATH.read_text())
FORMAT = "aweb.trust-web-cases/1"

# ---------------------------------------------------------------------------
# The format
# ---------------------------------------------------------------------------


class CaseFormatError(ValueError):
    """The case file is not a valid aweb.trust-web-cases/1 document."""


# Every constructor of the model's Step (TrustWeb/Model.lean) and its arguments.
ACT_ARGS = {
    "createOrg": {"org"},
    "replaceRoot": {"org"},
    "readmitByRoot": {"subject"},
    "readmitByParent": {"subject"},
    "release": {"key"},
    "entrust": {"key"},
    "registerByRoot": {"cert"},
    "registerByParent": {"cert"},
    "revokeSelf": {"subject"},
    "revokeChild": {"subject"},
    "revokeByOrg": {"subject"},
    "admit": {"membership"},
    "admitAdmin": {"membership"},
    "remove": {"membership"},
    "leave": {"membership"},
    "invite": {"invite"},
    "redeem": {"invite", "member"},
    "mintGrant": {"grant"},
    "revokeGrant": {"grant"},
    "sendOwn": set(),
    "sendGrant": {"session"},
}

# The premises a refusal may name, per constructor. Until the model names every
# premise of Step, only premises that are a definition of the model are
# nameable (agreed with the model's author, aweb-adyz).
PREMISES = {
    "registerByRoot": {"Authorised", "Fresh"},
    "registerByParent": {"Fresh", "Valid", "MayIssue"},
    "revokeChild": {"Valid"},
    "revokeByOrg": {"Authorised"},
    "readmitByRoot": {"Authorised"},
    "readmitByParent": {"Valid"},
    "release": {"Authorised"},
    "admit": {"Authorised", "OneTeamIfLocal"},
    "admitAdmin": {"Valid", "Authorised"},
    "remove": {"Authorised", "KeepsAnAdmin"},
    "leave": {"KeepsAnAdmin"},
    "invite": {"Authorised"},
    "redeem": {"OneTeamIfLocal"},
    "mintGrant": {"InTeam"},
    "sendOwn": {"CanAct"},
}

OBSERVATION_ARGS = {
    "cert": {"subject"},
    "revoked": {"key"},
    "valid": {"org", "key", "kind"},
    "canAct": {"key"},
    "hasTeamCert": {"org", "team", "key"},
    "inTeam": {"org", "team", "key"},
    "grant": {"session"},
    "grantLive": {"session"},
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
PARTIES = {"dns", "controller", "id", "session", "bearer"}
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

    @property
    def runnable(self) -> bool:
        return self.status == "implemented"


def _fields(value: Any, expected: set[str], where: str) -> None:
    if type(value) is not dict or set(value) != expected:
        got = sorted(value) if type(value) is dict else type(value).__name__
        raise CaseFormatError(f"{where}: fields {got} are not {sorted(expected)}")


def _step(value: Any, where: str) -> Step:
    _fields(value, {"who", "act", "args"}, where)
    who, act, args = value["who"], value["act"], value["args"]
    if type(who) is not dict or len(who) != 1 or set(who) - PARTIES:
        raise CaseFormatError(f"{where}: party {who!r} is not one of {sorted(PARTIES)}")
    if act not in ACT_ARGS:
        raise CaseFormatError(f"{where}: act {act!r} is not a model act")
    _fields(args, ACT_ARGS[act], f"{where} args of {act}")
    return Step(who=who, act=act, args=args)


def _observation(value: Any, where: str) -> Observation:
    if type(value) is not dict or "is" not in value or len(value) != 2:
        raise CaseFormatError(f"{where}: an observation is one predicate and 'is'")
    [predicate] = [key for key in value if key != "is"]
    if predicate not in OBSERVATION_ARGS:
        raise CaseFormatError(f"{where}: observation {predicate!r} is not known")
    _fields(value[predicate], OBSERVATION_ARGS[predicate], f"{where} {predicate}")
    return Observation(predicate, value[predicate], value["is"])


def _case(value: Any) -> Case:
    where = f"case {value.get('id')!r}" if type(value) is dict else "case"
    expect = value.get("expect") if type(value) is dict else None
    refused = type(expect) is dict and expect.get("result") == "refused"
    _fields(value, REFUSAL_FIELDS if refused else CASE_FIELDS, where)
    if type(value["id"]) is not str or not value["id"]:
        raise CaseFormatError(f"{where}: id must be a non-empty string")
    if value["source"] not in {"seed", "emitted"}:
        raise CaseFormatError(f"{where}: source {value['source']!r} is unknown")
    if value["status"] not in {"implemented", "design"}:
        raise CaseFormatError(f"{where}: status {value['status']!r} is unknown")
    if value["rule"] not in RULES:
        raise CaseFormatError(f"{where}: rule {value['rule']!r} is unknown")
    if value["status"] == "implemented" and value["rule"] not in RUNNABLE_RULES:
        raise CaseFormatError(
            f"{where}: an implemented case's rule must be any or built, not {value['rule']!r}"
        )
    step = _step({k: value[k] for k in ("who", "act", "args")}, where)
    if type(value["setup"]) is not list:
        raise CaseFormatError(f"{where}: setup must be a list of acts")
    setup = tuple(
        _step(item, f"{where} setup[{index}]")
        for index, item in enumerate(value["setup"])
    )
    premise = None
    if refused:
        _fields(expect, {"result", "premise"}, f"{where} expect")
        constructor, _, name = str(expect["premise"]).partition(".")
        if constructor != step.act or name not in PREMISES.get(step.act, set()):
            raise CaseFormatError(
                f"{where}: premise {expect['premise']!r} is not a nameable premise of {step.act}"
            )
        premise = expect["premise"]
    elif expect != {"result": "allowed"}:
        raise CaseFormatError(
            f"{where}: result {expect!r} is neither allowed nor refused"
        )
    if type(value["observe"]) is not list or not value["observe"]:
        raise CaseFormatError(f"{where}: a case needs at least one observation")
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
    )


def load_corpus(corpus: Any) -> list[Case]:
    """Every case of an aweb.trust-web-cases/1 document, or CaseFormatError."""
    if type(corpus) is not dict or corpus.get("format") != FORMAT:
        raise CaseFormatError(f"format is not {FORMAT}")
    _fields(corpus, TOP_FIELDS, "document")
    if corpus["status"] != "experimental":
        raise CaseFormatError("document status must be experimental")
    _fields(corpus["model"], MODEL_FIELDS, "model")
    if type(corpus["cases"]) is not list:
        raise CaseFormatError("cases must be a list")
    cases = [_case(value) for value in corpus["cases"]]
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


@dataclass(frozen=True)
class Disagreement:
    """A case the code decides differently, filed as ``task``.

    ``mismatches`` is the exact comparison the run produces. The case keeps
    running: it fails if its comparison changes in any way, and is reported
    as an expected failure naming the task while it does not.
    """

    task: str
    mismatches: tuple[str, ...]


# The server sees a team-certificate revocation only after its cached
# revocation list refreshes (60 s fresh, 60 s stale: docs/aweb-sot.md:448-466);
# the model assumes one current record (A4). Shown by experiment in the task.
_REVOCATION_WINDOW = "aweb-adyz.2"

DISAGREEMENTS: dict[str, Disagreement] = {
    "mint-grant-after-removal-refused": Disagreement(
        _REVOCATION_WINDOW,
        (
            "decision: expected refused (mintGrant.InTeam), code allowed",
            'observe grantLive({"session": "s1"}): expected after false, read true',
        ),
    ),
    "remove-member-ends-its-grant": Disagreement(
        _REVOCATION_WINDOW,
        ('observe grantLive({"session": "s1"}): expected after false, read true',),
    ),
}


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


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signer(key: SigningKey) -> Callable[[bytes], tuple[str, bytes]]:
    return lambda payload: (
        did_key_from_signing_key(bytes(key)),
        key.sign(payload).signature,
    )


def _team_name(team: dict) -> str:
    if team == "admin" or team == {"admin": None}:
        return "admin"
    return f"t{team['named']}"


@dataclass
class _Identity:
    org: str
    did_aw: str
    chain: list[dict]


@dataclass
class _Membership:
    team_id: str
    certificate_id: str
    certificate: dict


@dataclass
class _Grant:
    session: SigningKey
    grant_id: str
    team_id: str
    subject: str


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
    grants: dict[str, _Grant] = field(default_factory=dict)

    # -- symbols ----------------------------------------------------------

    def key(self, symbol: str) -> SigningKey:
        return self.keys.setdefault(symbol, SigningKey.generate())

    def did_key(self, symbol: str) -> str:
        return did_key_from_signing_key(bytes(self.key(symbol)))

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
                return self.roots[controlled["root"]]
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

    def team_headers(self, member: str, team_id: str, body: bytes) -> dict:
        certificate = self.memberships[(team_id, member)].certificate
        return {
            **_signed_team_headers(
                bytes(self.key(member)),
                self.did_key(member),
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
        self.roots[org] = SigningKey.generate()
        await self.stack.registry.ensure_namespace(
            domain=self.domain(org), controller=bytes(self.roots[org])
        )

    async def _register(self, step: Step, parent_chain: list[dict]) -> None:
        cert = step.args["cert"]
        subject = cert["subject"]
        did_aw = await self.did_aw(subject, cert["org"])
        domain = self.domain(cert["org"])
        issuer = cert["issuer"]
        parent = (
            {"kind": "namespace", "id": domain}
            if issuer == "root"
            else {"kind": "identity", "id": self.identities[issuer["member"]].did_aw}
        )
        signer = self.party_key(step.who)
        fields = {
            "v": 1,
            "type": "aweb.id-certificate",
            "id": did_aw,
            "domain": domain,
            "parent": parent,
            "kind": {"person": "human", "agent": "agent"}[cert["kind"]],
            "issuer_key": did_key_from_signing_key(bytes(signer)),
            "issued_at": _now(),
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
            org=cert["org"], did_aw=did_aw, chain=chain
        )

    async def _act_registerByRoot(self, step: Step) -> None:
        await self._register(step, [])

    async def _act_registerByParent(self, step: Step) -> None:
        parent = step.args["cert"]["issuer"]["member"]
        await self._register(step, self.identities[parent].chain)

    async def _revoke(self, step: Step) -> None:
        symbol = step.args["subject"]
        subject = self.identities[symbol]
        # AWID revokes only the head the request names: the subject's current
        # certificate, read from the registry's own status.
        status = await self._status(symbol)
        entry = self._entry(status, subject.did_aw)
        if entry is None:
            raise Unavailable(f"no current certificate to revoke for {symbol}")
        await self.stack.client.revoke_id_certificate(
            self.domain(subject.org),
            subject.did_aw,
            signer=_signer(self.party_key(step.who)),
            expected_head=entry["current_certificate_id"],
        )

    _act_revokeSelf = _revoke
    _act_revokeChild = _revoke
    _act_revokeByOrg = _revoke

    async def _act_admit(self, step: Step) -> None:
        m = step.args["membership"]
        membership = self.membership(m["org"], m["team"], m["member"])
        signer = self.party_key(step.who)
        signer_did = did_key_from_signing_key(bytes(signer))
        # A local member: a did:key with no did:aw, in this one team.
        certificate = _make_certificate(
            bytes(signer),
            signer_did,
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

    async def _server(self, method: str, path: str, headers: dict, body: bytes) -> dict:
        async with self.stack.server.client() as client:
            response = await client.request(method, path, content=body, headers=headers)
        if response.status_code >= 300:
            raise _ServerRefusal(_server_refusal(response))
        return response.json()

    async def _act_mintGrant(self, step: Step) -> None:
        g = step.args["grant"]
        if g["subject"] != step.who.get("id") or g["maySend"] is not True:
            raise NotRunnable(
                "the runner mints only a sending grant, asked by its subject"
            )
        team_id = self.team_id(g["org"], g["team"])
        session = SigningKey.generate()
        body = json.dumps(
            {
                "grant_did_key": did_key_from_signing_key(bytes(session)),
                "scopes": GRANT_SCOPES,
                "ttl_seconds": GRANT_TTL_SECONDS,
            }
        ).encode()
        minted = await self._server(
            "POST",
            "/v1/identity-grants",
            self.team_headers(g["subject"], team_id, body),
            body,
        )
        self.grants[g["session"]] = _Grant(
            session=session,
            grant_id=minted["grant_id"],
            team_id=team_id,
            subject=g["subject"],
        )

    async def _act_revokeGrant(self, step: Step) -> None:
        g = step.args["grant"]
        grant = self.grants[g["session"]]
        await self._server(
            "POST",
            f"/v1/identity-grants/{grant.grant_id}/revoke",
            self.team_headers(grant.subject, grant.team_id, b""),
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

    async def _read_grantLive(self, args: dict) -> bool:
        """Whether the server lets the grant's session key act now: a read the
        grant's scopes allow, signed with that key, changing nothing.

        A session the server never answered with a grant id has no grant:
        grant authentication names the grant by that id, so nothing can act
        with it."""
        grant = self.grants.get(args["session"])
        if grant is None:
            return False
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
        did_key = did_key_from_signing_key(bytes(grant.session))
        headers = {
            "Authorization": f"AWEB-Grant DIDKey {did_key} {sign_message(bytes(grant.session), payload)}",
            "X-AWEB-Grant-ID": grant.grant_id,
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": _b64url(payload),
        }
        async with self.stack.server.client() as client:
            response = await client.get(path, headers=headers)
        if response.status_code == 200:
            return True
        if response.status_code in (401, 403):
            return False
        raise Unavailable(
            f"grant {args['session']}: {response.status_code} {response.text}"
        )


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
    world = World(stack)
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
    before = {o.label(): await world.observe(o) for o in case.observe}
    refusal = await world.perform(case.step)
    after = {o.label(): await world.observe(o) for o in case.observe}
    return Run(refusal=refusal, before=before, after=after)


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
