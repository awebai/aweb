"""The definition's display renders the same words in Python and in the page."""

import json
import subprocess
from pathlib import Path
from uuid import uuid4

import pytest

from aweb_naapp.runtime.protected_signer import ProtectedKeyContext, RevokeHumanRole, SignerRefused
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS
from aweb_naapp.runtime.protected_signer.operation_display import OperationDisplay

REQUEST = {
    "requester": "did:key:z6Mkrequester",
    "subject": {"alias": "agent-one", "teams": ["a:customer.example", "b:customer.example"],
        "team_id": "engineering:customer.example", "target_kind": "kind not verified", "agent_kind": "agent",
        "other_kind": "human", "root_id": "did:aw:ROOT", "label": "oats-root", "window": 3600, "day": 86400,
        "odd": 90,
        "count": 3, "nothing": None, "policy": {"b": 2, "a": [1]}, "flag": True},
}

CASES = [
    # "|period" names a window in seconds; the requester is named when it is
    # the subject the definition names.
    (OperationDisplay("At most {/subject/count} per {/subject/window|period}?",
        ("Or per {/subject/day|period}, or per {/subject/odd|period}.",), (), (), (),
        requester_name=("/requester", "/subject/label")),
     {"title": "At most 3 per hour?", "consequences": ["Or per day, or per 90 seconds."], "names": [],
      "technical": [], "requester": "oats-root"}),
    (OperationDisplay("Remove it?", ("x",), (), (), (), requester_name=("/subject/root_id", "/subject/label")),
     {"title": "Remove it?", "consequences": ["x"], "names": [], "technical": [],
      "requester": "did:key:z6Mkrequester"}),
    # "|kind" names a frozen target kind in the words the owner page uses.
    (OperationDisplay("Remove {/subject/alias}?", ("x",),
        (("kind", "/subject/target_kind|kind"), ("other", "/subject/agent_kind|kind")),
        (("kind", "/subject/target_kind"),), ()),
     {"title": "Remove agent-one?", "consequences": ["x"],
      "names": [["Kind", "agent or person not confirmed"], ["Other", "agent"]],
      "technical": [["Kind", "kind not verified"]]}),
    # "|team" shows a team by its name, as the owner page does; the full id
    # stays available to technical rows without it.
    (OperationDisplay("Add {/subject/alias} to {/subject/team_id|team} and {/subject/teams|team}?", ("x",),
        (("team", "/subject/team_id|team"),), (("team", "/subject/team_id"),), ()),
     {"title": "Add agent-one to engineering and a, b?", "consequences": ["x"],
      "names": [["Team", "engineering"]], "technical": [["Team", "engineering:customer.example"]]}),
    (OperationDisplay("Remove {/subject/alias} from {/subject/teams}?",
        ("It counts {/subject/count} times.",), (("member", "/subject/alias"),),
        (("policy", "/subject/policy"), ("nothing", "/subject/nothing"), ("flag", "/subject/flag"),
         ("root_key", "/requester")), (("subject_ineligible", "Not eligible."),),
        responsibility_statement="You answer for it."),
     {"title": "Remove agent-one from a:customer.example, b:customer.example?",
      "consequences": ["You answer for it.", "It counts 3 times."],
      "names": [["Member", "agent-one"]],
      "technical": [["Policy", '{"a":[1],"b":2}'], ["Nothing", "null"], ["Flag", "true"],
          ["Root key", "did:key:z6Mkrequester"]]}),
]

REFUSED = [
    OperationDisplay("Per {/subject/alias|period}?", ("x",), (), (), ()),
    OperationDisplay("Per {/subject/count|period}?", ("x",), (), (), (), requester_name=("/subject/missing", "/subject/label")),
    OperationDisplay("Remove it?", ("x",), (("kind", "/subject/other_kind|kind"),), (), ()),
    OperationDisplay("Remove it?", ("x",), (("kind", "/subject/teams|kind"),), (), ()),
    OperationDisplay("Add {/subject/alias|team}?", ("x",), (), (), ()),
    OperationDisplay("Add {/subject/team_id|unknown}?", ("x",), (), (), ()),
    OperationDisplay("Add {/subject/team_id|Team}?", ("x",), (), (), ()),
    OperationDisplay("Add it?", ("x",), (("team", "/subject/count|team"),), (), ()),
    OperationDisplay("Remove {/subject/missing}?", ("x",), (), (), ()),
    OperationDisplay("Remove {/subject/policy}?", ("x",), (), (), ()),
    OperationDisplay("Remove {/subject/nothing}?", ("x",), (), (), ()),
    OperationDisplay("Remove {/subject/flag}?", ("x",), (), (), ()),
    OperationDisplay("Remove it?", ("x",), (("member", "/subject/policy"),), (), ()),
    OperationDisplay("Remove it?", ("x",), (), (("member", "/subject/missing"),), ()),
    OperationDisplay("Remove it?", ("x",), (), (("member", "/subject/alias/deeper"),), ()),
]


def revoke_request():
    team, domain = "engineering:customer.example", "customer.example"
    context = ProtectedKeyContext("customer-signer", "team_controller", team, domain, "human-id", domain, 1)
    revoke = RevokeHumanRole(str(uuid4()), context, "https://app.customer.example", "customer-app",
        str(uuid4()), "customer.owner", "human-id")
    return {**revoke.intent(), "requester": "did:key:z6Mkrequester"}


@pytest.mark.parametrize("display,expected", CASES)
def test_python_fills_templates_from_the_frozen_request(display, expected):
    assert display.render(REQUEST) == expected


@pytest.mark.parametrize("display", REFUSED)
def test_python_refuses_a_display_it_cannot_fill_exactly(display):
    with pytest.raises(SignerRefused, match="request_invalid"):
        display.render(REQUEST)


def test_refusal_sentence_is_the_definitions_own_or_none():
    display = CASES[4][0]
    assert display.refusal("subject_ineligible") == "Not eligible."
    assert display.refusal("approval_spent") is None


def test_revoke_row_names_the_principal_and_role_from_its_frozen_request():
    request = revoke_request()
    rendered = OPERATIONS[("human-role.revoke", "default")].display.render(request)
    assert rendered["title"] == "Remove human-id as customer.owner of customer-app?"
    assert rendered["consequences"] == ["human-id will no longer be customer.owner of customer-app."]
    assert ["Role", "customer.owner"] in rendered["names"]


def run_page_renderer(cases):
    script = r'''
import {readFileSync} from 'node:fs';
import {renderDisplay, displayRefusal} from './src/aweb_naapp/assets/protected-display.mjs';
const cases = JSON.parse(readFileSync(0, 'utf8'));
const out = cases.map(([display, request, code]) => {
  let rendered;
  try { rendered = renderDisplay(display, request); } catch (error) { rendered = error.message; }
  return [rendered, displayRefusal(display, code)];
});
process.stdout.write(JSON.stringify(out));
'''
    result = subprocess.run(["node", "--input-type=module", "-e", script], input=json.dumps(cases),
        text=True, capture_output=True, cwd=Path(__file__).resolve().parents[2], timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def test_page_renders_exactly_what_python_renders_and_refuses_the_same_displays():
    real = [(spec.display, revoke_request()) for spec in [OPERATIONS[("human-role.revoke", "default")]]]
    rendered = [(display, REQUEST) for display, _ in CASES] + real
    cases = [[d.fields(), r, "subject_ineligible"] for d, r in rendered]
    cases += [[d.fields(), REQUEST, "approval_spent"] for d in REFUSED]
    out = run_page_renderer(cases)
    for (display, request), (page, refusal) in zip(rendered, out[: len(rendered)], strict=True):
        assert page == display.render(request)
        assert refusal == display.refusal("subject_ineligible")
    for page, refusal in out[len(rendered):]:
        assert page == "handoff_refused" and refusal is None


@pytest.mark.parametrize("kind", ["agent", "kind not verified"])
def test_owner_removal_shows_its_frozen_kind_before_approval_on_every_surface(kind):
    from datetime import timedelta

    from aweb_naapp.runtime.protected_signer.execution_intent import prepare_artifact_intent
    from tests.runtime.test_protected_identity_artifacts import NOW
    from tests.runtime.test_protected_member_removal import CONTROLLER
    from tests.runtime.test_protected_owner_removal import owner_operation

    op = owner_operation()
    request = {**op.intent(), "artifact": prepare_artifact_intent(op, CONTROLLER, NOW, NOW + timedelta(hours=24)),
        "requester": "did:key:z6Mkrequester", "requester_key": CONTROLLER, "target_kind": kind}
    display = op.spec.display
    rendered = display.render(request)
    alias = request["subject"]["expected_membership"]["alias"]
    team = request["subject"]["team_id"].split(":")[0]
    label = "agent" if kind == "agent" else "agent or person not confirmed"
    assert rendered["title"] == f"Remove {alias} from {team}?"
    assert rendered["consequences"] == [f"{alias} leaves {team}.", "Its aweb identity is not deleted."]
    assert ["Kind", label] in rendered["names"]
    assert ["Kind", kind] in rendered["technical"]
    assert display.refusal("subject_ineligible") == "This member is a person, or could not be checked, so it cannot be removed here."
    assert display.refusal("issuer_kind_forbidden") == "Only an owner's passkey can approve this."
    [[page, _]] = run_page_renderer([[display.fields(), request, "subject_ineligible"]])
    assert page == rendered
