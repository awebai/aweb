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
from collections.abc import Callable
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
from nacl.signing import SigningKey

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


DISAGREEMENTS: dict[str, Disagreement] = {}
