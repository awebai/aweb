"""The trust-web model's cases, run against the real AWID registry and aweb server.

docs/vectors/trust-web-cases-v1.json holds the cases (format
``aweb.trust-web-cases/1``, docs/vectors/README.md). Every implemented case
runs here: setup is replayed as model acts through signed public routes, the
act is sent, and the decision and the committed evidence read back are
compared with the case. A case the code decides differently stays a failing
comparison, pinned to its filed disagreement; design cases are never sent.
"""

from __future__ import annotations

import copy
import dataclasses
import json

import pytest

from trust_web_cases import (
    CORPUS,
    DISAGREEMENTS,
    CaseFormatError,
    NotRunnable,
    compare,
    load_corpus,
    run_case,
    stack_factory,  # noqa: F401  (fixture)
)


def _valid() -> dict:
    return copy.deepcopy(CORPUS)


def _case(corpus: dict, case_id: str) -> dict:
    [case] = [case for case in corpus["cases"] if case["id"] == case_id]
    return case


def test_the_committed_corpus_conforms_to_the_format():
    cases = load_corpus(_valid())
    assert {case.id for case in cases} == {case["id"] for case in CORPUS["cases"]}
    assert all(case.source == "seed" for case in cases)


def _mutations():
    def unknown_format(c):
        c["format"] = "aweb.trust-web-cases/2"

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
    }


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_the_format_refuses_each_single_fault(name):
    mutate, named = _mutations()[name]
    corpus = _valid()
    mutate(corpus)
    with pytest.raises(CaseFormatError) as refused:
        load_corpus(corpus)
    assert named in str(refused.value), str(refused.value)


def test_every_disagreement_names_a_runnable_case_and_a_task():
    runnable = {case.id for case in load_corpus(_valid()) if case.runnable}
    for case_id, disagreement in DISAGREEMENTS.items():
        assert case_id in runnable
        assert disagreement.task.startswith("aweb-")


# ---------------------------------------------------------------------------
# The cases, against the real registry and server
# ---------------------------------------------------------------------------

CASES = {case.id: case for case in load_corpus(CORPUS)}
RUNNABLE = sorted(case_id for case_id, case in CASES.items() if case.runnable)
DESIGN = sorted(case_id for case_id, case in CASES.items() if not case.runnable)


@pytest.mark.asyncio
@pytest.mark.parametrize("case_id", RUNNABLE)
async def test_the_code_decides_the_case_as_the_model_does(stack_factory, case_id):
    case = CASES[case_id]
    async with stack_factory() as stack:
        run = await run_case(stack, case)
    mismatches = compare(case, run)
    disagreement = DISAGREEMENTS.get(case_id)
    if disagreement is None:
        assert mismatches == [], "\n".join(mismatches)
        return
    assert tuple(mismatches) == disagreement.mismatches, "\n".join(mismatches)
    pytest.xfail(f"disagreement {disagreement.task}: " + "; ".join(mismatches))


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
