"""The trust-web model's cases, run against the real AWID registry and aweb server.

The cases are the seeds and the model's emission trust_web_cases.py loads
(format ``aweb.trust-web-cases/2``, docs/vectors/README.md). Every implemented case
runs here: setup is replayed as model acts through signed public routes, the
act is sent, and the decision and the committed evidence read back are
compared with the case. A case the code decides differently stays a failing
comparison, pinned to its filed disagreement; design cases are never sent.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json

import pytest

from trust_web_cases import (
    CASES,
    CORPUS,
    DISAGREEMENTS,
    MODEL_CORPUS,
    MODEL_CORPUS_PATH,
    CaseFormatError,
    NotRunnable,
    Step,
    World,
    _Grant,
    compare,
    load_corpus,
    run_case,
)
from trust_web_cases import stack_factory as stack_factory
from trust_web_disagreements import CASE_IDS as DISAGREEMENT_RUN

__all__ = ["stack_factory"]


def _valid() -> dict:
    return copy.deepcopy(CORPUS)


def _case(corpus: dict, case_id: str) -> dict:
    [case] = [case for case in corpus["cases"] if case["id"] == case_id]
    return case


# The first batch, pinned here rather than read from the file under test, so a
# dropped or renamed case fails this module.
FIRST_BATCH = {
    "register-person-by-root",
    "register-person-by-other-org-root-refused",
    "register-agent-by-person-parent",
    "register-agent-by-agent-parent",
    "register-person-by-agent-parent-refused",
    "register-agent-by-revoked-parent-refused",
    "register-agent-by-orphaned-agent-parent-refused",
    "revoke-self",
    "revoke-child-by-parent",
    "revoke-child-by-revoked-parent-refused",
    "revoke-by-org",
    "admit-member",
    "admit-by-other-team-key-refused",
    "remove-member",
    "remove-by-other-team-key-refused",
    "mint-grant",
    "mint-grant-after-removal-refused",
    "revoke-grant",
    "remove-member-ends-its-grant",
    "leave-team-held-by-key-holder",
}


def test_the_committed_corpus_conforms_to_the_format():
    cases = load_corpus(_valid())
    assert all(case.source == "seed" for case in cases)


def test_a_version_1_document_keeps_its_meaning():
    corpus = _valid()
    corpus["format"] = "aweb.trust-web-cases/1"
    for case in corpus["cases"]:
        case.pop("propagation", None)
    assert {case.propagation for case in load_corpus(corpus)} == {"immediate"}


def test_version_1_has_no_propagation_field():
    corpus = _valid()
    corpus["format"] = "aweb.trust-web-cases/1"
    with pytest.raises(CaseFormatError, match="fields"):
        load_corpus(corpus)


def _present_cases(corpus: dict) -> set[str]:
    return {case.id for case in load_corpus(corpus)}


def test_the_corpus_holds_the_whole_first_batch():
    missing = FIRST_BATCH - _present_cases(_valid())
    assert missing == set(), f"first-batch cases missing: {sorted(missing)}"


def test_a_dropped_first_batch_case_is_detected():
    corpus = _valid()
    corpus["cases"] = [c for c in corpus["cases"] if c["id"] != "revoke-grant"]
    assert FIRST_BATCH - _present_cases(corpus) == {"revoke-grant"}


# The model's emission, pinned by its committed bytes: the model's build checks
# the file equals a fresh run of its emitter, so a changed file is a new
# emission to review here, never a silent edit.
MODEL_EMISSION_SHA256 = (
    "8fbb070cf9ad083c26ad93266e81ef2368345b182ed52cab965a033552f3233d"
)


def test_the_model_file_is_the_reviewed_emission():
    assert hashlib.sha256(MODEL_CORPUS_PATH.read_bytes()).hexdigest() == (
        MODEL_EMISSION_SHA256
    )
    cases = load_corpus(copy.deepcopy(MODEL_CORPUS))
    assert len(cases) == 38
    assert all(case.source == "emitted" and case.runnable for case in cases)
    assert all(case.id.startswith("model-") for case in cases)
    assert MODEL_CORPUS["model"]["emitter"] == "lake exe trust-web-cases"


TWIN_FIELDS = ("who", "act", "args", "setup", "expect", "neighbour", "observe")


def _as_emitted(case: dict) -> str:
    """The fields a seed and its emitted twin share, with the neighbour named
    as the emitter names it."""
    kept = {key: case[key] for key in TWIN_FIELDS if key in case}
    if "neighbour" in kept:
        kept["neighbour"] = kept["neighbour"].removeprefix("model-")
    return json.dumps(kept, sort_keys=True)


def test_every_implemented_seed_has_its_twin_in_the_model_file():
    emitted = {_as_emitted(case) for case in MODEL_CORPUS["cases"]}
    seeds = [case for case in CORPUS["cases"] if case["status"] == "implemented"]
    untwinned = [case["id"] for case in seeds if _as_emitted(case) not in emitted]
    assert untwinned == []


def test_the_two_files_name_no_case_twice():
    seeds = {case["id"] for case in CORPUS["cases"]}
    emitted = {case["id"] for case in MODEL_CORPUS["cases"]}
    assert seeds & emitted == set()


def _mutations():
    def unknown_format(c):
        c["format"] = "aweb.trust-web-cases/3"

    def unknown_top_field(c):
        c["extra"] = 1

    def unknown_case_field(c):
        _case(c, "register-person-by-root")["extra"] = 1

    def missing_case_field(c):
        del _case(c, "register-person-by-root")["observe"]

    def duplicate_id(c):
        c["cases"].append(copy.deepcopy(_case(c, "register-person-by-root")))

    def refusal_without_neighbour(c):
        del _case(c, "register-person-by-agent-parent-refused")["neighbour"]

    def neighbour_absent(c):
        _case(c, "register-person-by-agent-parent-refused")["neighbour"] = "nope"

    def neighbour_refused(c):
        _case(c, "register-person-by-agent-parent-refused")["neighbour"] = (
            "admit-by-other-team-key-refused"
        )

    def neighbour_other_act(c):
        _case(c, "register-person-by-agent-parent-refused")["neighbour"] = (
            "admit-member"
        )

    def neighbour_on_allowed(c):
        _case(c, "register-person-by-root")["neighbour"] = "admit-member"

    def premise_of_other_act(c):
        _case(c, "register-person-by-agent-parent-refused")["expect"]["premise"] = (
            "admit.Authorised"
        )

    def unknown_result(c):
        _case(c, "register-person-by-root")["expect"] = {"result": "maybe"}

    def implemented_under_design_rule(c):
        _case(c, "register-person-by-root")["rule"] = "admin"

    def unknown_source(c):
        _case(c, "register-person-by-root")["source"] = "guessed"

    def unknown_status(c):
        _case(c, "register-person-by-root")["status"] = "planned"

    def unknown_observation(c):
        _case(c, "register-person-by-root")["observe"].append(
            {"answersFor": {"key": "alice"}, "is": True}
        )

    def no_observation(c):
        _case(c, "register-person-by-root")["observe"] = []

    def unknown_cert_field(c):
        _case(c, "register-person-by-root")["args"]["cert"]["extra"] = 1

    def list_valued_member(c):
        _case(c, "admit-member")["args"]["membership"]["member"] = ["carol"]

    def emitted_without_emitter(c):
        _case(c, "register-person-by-root")["source"] = "emitted"

    def short_model_commit(c):
        c["model"]["commit"] = "e5c0ca2362"

    def string_may_send(c):
        _case(c, "mint-grant")["args"]["grant"]["maySend"] = "true"

    def team_not_a_number(c):
        _case(c, "admit-member")["args"]["membership"]["team"] = {"named": "1"}

    def unknown_party_form(c):
        _case(c, "admit-member")["who"] = {"operator": "o1"}

    def grant_revoked_by_another(c):
        _case(c, "revoke-grant")["who"] = {"id": "mallory"}

    def org_created_by_another_domain(c):
        _case(c, "register-person-by-root")["setup"][0]["who"] = {"dns": "o2"}

    def child_registered_by_another(c):
        _case(c, "register-agent-by-person-parent")["who"] = {"id": "bob"}

    def root_act_with_member_issuer(c):
        _case(c, "register-person-by-root")["args"]["cert"]["issuer"] = {
            "member": "bob"
        }

    def observation_of_wrong_type(c):
        _case(c, "revoke-self")["observe"][0]["is"] = "yes"

    def unknown_propagation(c):
        _case(c, "remove-member-ends-its-grant")["propagation"] = "later"

    def refusal_of_another_premise_by_another_party(c):
        _case(c, "mint-grant-after-removal-refused")["who"] = {"id": "mallory"}

    def refusal_of_another_premise_with_member_issuer(c):
        _case(c, "register-person-by-other-org-root-refused")["args"]["cert"][
            "issuer"
        ] = {"member": "bob"}

    def neighbour_not_a_symbol(c):
        _case(c, "register-person-by-agent-parent-refused")["neighbour"] = 7

    return {
        "unknown-format": (unknown_format, "format"),
        "unknown-top-field": (unknown_top_field, "fields"),
        "unknown-case-field": (unknown_case_field, "fields"),
        "missing-case-field": (missing_case_field, "fields"),
        "duplicate-id": (duplicate_id, "duplicate"),
        "refusal-without-neighbour": (refusal_without_neighbour, "neighbour"),
        "neighbour-absent": (neighbour_absent, "neighbour"),
        "neighbour-refused": (neighbour_refused, "neighbour"),
        "neighbour-other-act": (neighbour_other_act, "neighbour"),
        "neighbour-on-allowed": (neighbour_on_allowed, "neighbour"),
        "premise-of-other-act": (premise_of_other_act, "premise"),
        "unknown-result": (unknown_result, "result"),
        "implemented-under-design-rule": (implemented_under_design_rule, "rule"),
        "unknown-source": (unknown_source, "source"),
        "unknown-status": (unknown_status, "status"),
        "unknown-observation": (unknown_observation, "observation"),
        "no-observation": (no_observation, "observation"),
        "unknown-cert-field": (unknown_cert_field, "fields"),
        "list-valued-member": (list_valued_member, "symbol"),
        "emitted-without-emitter": (emitted_without_emitter, "emitter"),
        "short-model-commit": (short_model_commit, "commit"),
        "string-may-send": (string_may_send, "boolean"),
        "team-not-a-number": (team_not_a_number, "natural number"),
        "unknown-party-form": (unknown_party_form, "party"),
        "grant-revoked-by-another": (grant_revoked_by_another, "party"),
        "org-created-by-another-domain": (org_created_by_another_domain, "party"),
        "child-registered-by-another": (child_registered_by_another, "party"),
        "root-act-with-member-issuer": (root_act_with_member_issuer, "root"),
        "observation-of-wrong-type": (observation_of_wrong_type, "boolean"),
        "refusal-of-another-premise-by-another-party": (
            refusal_of_another_premise_by_another_party,
            "party",
        ),
        "refusal-of-another-premise-with-member-issuer": (
            refusal_of_another_premise_with_member_issuer,
            "root",
        ),
        "neighbour-not-a-symbol": (neighbour_not_a_symbol, "symbol"),
        "unknown-propagation": (unknown_propagation, "propagation"),
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_the_format_refuses_each_single_fault(name):
    mutate, named = _mutations()[name]
    corpus = _valid()
    mutate(corpus)
    with pytest.raises(CaseFormatError) as refused:
        load_corpus(corpus)
    assert named in str(refused.value), str(refused.value)


# A world with no stack: any request it tried to send would fail on the
# missing stack, so NotRunnable shows the act was refused before sending.


@pytest.mark.asyncio
async def test_a_grant_revocation_naming_another_grant_is_not_sent():
    minted = {
        "session": "s1",
        "subject": "carol",
        "org": "o1",
        "team": {"named": 1},
        "maySend": True,
    }
    world = World(stack=None)
    world.grants["s1"] = _Grant(grant_id="unsent", team_id="t1:o1", binding=minted)
    other = {**minted, "team": {"named": 2}}
    with pytest.raises(NotRunnable, match="holds"):
        await world.perform(
            Step(who={"id": "carol"}, act="revokeGrant", args={"grant": other})
        )


# ---------------------------------------------------------------------------
# The cases, against the real registry and server
# ---------------------------------------------------------------------------

RUNNABLE = sorted(case_id for case_id, case in CASES.items() if case.runnable)
GATED = sorted(set(RUNNABLE) - set(DISAGREEMENTS))
DESIGN = sorted(case_id for case_id, case in CASES.items() if not case.runnable)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", GATED)
async def test_the_code_decides_the_case_as_the_model_does(stack_factory, case_id):
    case = CASES[case_id]
    async with stack_factory() as stack:
        run = await run_case(stack, case)
    mismatches = compare(case, run)
    assert mismatches == [], "\n".join(mismatches)


@pytest.mark.parametrize("case_id", sorted(DISAGREEMENTS))
def test_held_out_of_the_gate_as_a_filed_disagreement(case_id):
    """The gate names each implemented case it does not run, and why: a filed
    disagreement that the disagreement run executes."""
    assert CASES[case_id].runnable, f"{case_id} is not an implemented case"
    assert DISAGREEMENTS[case_id].startswith("aweb-"), DISAGREEMENTS[case_id]
    assert case_id in DISAGREEMENT_RUN, f"{case_id} is not in the disagreement run"


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", DESIGN)
async def test_a_design_case_is_never_sent(stack_factory, case_id):
    async with stack_factory() as stack:
        before = (
            len(stack.registry.transport.calls),
            len(stack.server.transport.calls),
        )
        with pytest.raises(NotRunnable, match="design"):
            await run_case(stack, CASES[case_id])
        after = (len(stack.registry.transport.calls), len(stack.server.transport.calls))
    assert after == before


def _expecting(case, **changes):
    return dataclasses.replace(case, **changes)


@pytest.mark.asyncio
async def test_the_comparator_fails_on_a_deliberately_wrong_expectation(stack_factory):
    """One real allowed run and one real refused run, compared with their own
    cases and with expectations changed one fact at a time."""
    allowed = CASES["register-agent-by-agent-parent"]
    refused = CASES["register-person-by-agent-parent-refused"]
    async with stack_factory() as stack:
        allowed_run = await run_case(stack, allowed)
    async with stack_factory() as stack:
        refused_run = await run_case(stack, refused)
    assert compare(allowed, allowed_run) == []
    assert compare(refused, refused_run) == []

    as_refused = _expecting(
        allowed, result="refused", premise="registerByParent.MayIssue"
    )
    assert compare(as_refused, allowed_run)[0] == (
        "decision: expected refused (registerByParent.MayIssue), code allowed"
    )
    as_allowed = _expecting(refused, result="allowed", premise=None)
    assert compare(as_allowed, refused_run)[0] == (
        "decision: expected allowed, code refused with "
        + refused_run.refusal.describe()
    )
    other_premise = _expecting(refused, premise="registerByParent.Valid")
    [premise_mismatch] = compare(other_premise, refused_run)
    assert premise_mismatch.startswith(
        "reason: premise registerByParent.Valid expects "
    ), premise_mismatch
    cert = allowed.observe[0]
    wrong_kind = dataclasses.replace(cert, expected={**cert.expected, "kind": "person"})
    assert compare(_expecting(allowed, observe=(wrong_kind,)), allowed_run) == [
        f"observe {cert.label()}: expected after "
        f"{json.dumps(wrong_kind.expected, sort_keys=True)}, read "
        f"{json.dumps(cert.expected, sort_keys=True)}"
    ]


@pytest.mark.asyncio
async def test_without_propagation_a_removed_members_grant_stays_usable(stack_factory):
    """The cached lane is unchanged: with no invalidation, the server keeps
    honouring the grant inside its documented revocation window
    (docs/aweb-sot.md:448-466), and no revocations read happened on the
    observation's request. Only the after-propagation step closes it."""
    case = dataclasses.replace(
        CASES["remove-member-ends-its-grant"], propagation="immediate"
    )
    async with stack_factory() as stack:
        run = await run_case(stack, case)
    assert run.refusal is None
    [live] = [o for o in case.observe if o.predicate == "grantLive"]
    assert (run.before[live.label()], run.after[live.label()]) == (True, True)
    assert run.revocation_reads[live.label()] == 0
