"""The hook-binding cases vector is consistent with the binding rules it states.

The model below is the smallest reading of the vector's scheme. It checks that
every expected outcome in every case follows from those rules, so the cases
cannot drift from the state machine they illustrate. The core binding registry
consumes the same cases against its real implementation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import pytest

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTOR = json.loads((AWEB_ROOT / "docs" / "vectors" / "hook-binding-cases-v1.json").read_bytes())
SCHEME = VECTOR["scheme"]
MUTATION_HOOK = "post-mutation-hook"


@dataclass
class Binding:
    id: str
    app: str
    kind: str
    hook: str
    known: bool
    state: str = "pending"
    active_from: int | None = None
    pending: list[str] = field(default_factory=list)


def _transition(binding: Binding, op: str, signer: str | None) -> str | None:
    for rule in SCHEME["transitions"]:
        if rule["from"] == binding.state and rule["op"] == op:
            if "signer" in rule and rule["signer"] != signer:
                return "owner_required"
            binding.state = rule["to"]
            return None
    return "binding_not_pending"


def _known(spec: dict) -> bool:
    catalog = {"id": spec["catalog_id"], "version": spec["catalog_version"]}
    return catalog in SCHEME["known_catalogs"] and spec["hook"] in SCHEME["known_hooks"]


def _owed(bindings: dict[str, Binding], hook: str, t: int) -> list[str]:
    return sorted(
        b.id
        for b in bindings.values()
        if b.kind == "registration"
        and b.hook == hook
        and b.state == "active"
        and b.active_from is not None
        and b.active_from <= t
    )


def _run(case: dict) -> None:
    bindings: dict[str, Binding] = {}
    for step in case["steps"]:
        expect = step["expect"]
        t, op = step["t"], step["op"]
        assert op in SCHEME["ops"], op
        refused = None
        observed: dict = {}

        if op in ("install", "update"):
            app = step.get("app", "first")
            if op == "update":
                for b in bindings.values():
                    if b.app == app:
                        _transition(b, "update", step["signer"])
            for spec in step["bindings"]:
                bindings[spec["id"]] = Binding(
                    spec["id"], app, spec["kind"], spec["hook"], _known(spec)
                )
        elif op == "activate":
            b = bindings[step["binding"]]
            if step["signer"] != "owner":
                refused = "owner_required"
            elif b.state == "pending" and not b.known:
                refused = "unknown_catalog"
            else:
                refused = _transition(b, "activate", step["signer"])
                if refused is None:
                    b.active_from = t + SCHEME["active_from_pad_seconds"]
            observed["active_from"] = {b.id: b.active_from}
        elif op in ("revoke", "uninstall"):
            targets = (
                [bindings[step["binding"]]]
                if op == "revoke"
                else [
                    b
                    for b in bindings.values()
                    if b.app == step.get("app", "first") and b.state in ("pending", "active")
                ]
            )
            observed["cancelled"], observed["final_entry"], observed["notified"] = {}, {}, {}
            for b in targets:
                was_active = b.state == "active"
                refused = _transition(b, op, step.get("signer"))
                if was_active:
                    observed["final_entry"][b.id] = "hook_binding.revoked"
                if b.pending:
                    observed["cancelled"][b.id] = list(b.pending)
                for other in _owed(bindings, MUTATION_HOOK, t):
                    observed["notified"][other] = {
                        "mutation_type": "hook_binding.revoked",
                        "cancelled_count": len(b.pending),
                    }
                b.pending.clear()
        elif op == "event":
            owed = _owed(bindings, step["hook"], t)
            observed["owed_to"] = owed
            observed["audit_critical_gate"] = "pass" if owed else "refuse"
            for bid in step.get("undelivered", []):
                assert bid in owed, f"{case['name']}: {bid} is not owed {step['event']}"
                bindings[bid].pending.append(step["event"])

        assert expect.get("refused") == refused, (case["name"], t)
        if refused is None:
            assert "refused" not in expect or expect["refused"] is None
        assert refused is None or refused in SCHEME["refusals"]
        for b_id, state in expect.get("states", {}).items():
            assert bindings[b_id].state == state, (case["name"], t, b_id)
            assert state in SCHEME["states"]
        for key in (
            "active_from",
            "cancelled",
            "final_entry",
            "notified",
            "owed_to",
            "audit_critical_gate",
        ):
            if key in expect:
                assert observed[key] == expect[key], (case["name"], t, key)


@pytest.mark.parametrize("case", VECTOR["cases"], ids=lambda case: case["name"])
def test_binding_case_follows_the_scheme(case) -> None:
    _run(case)


def test_cases_cover_the_required_scenarios() -> None:
    names = {case["name"] for case in VECTOR["cases"]}
    assert {
        "admin_install_leaves_bindings_pending",
        "admin_signer_cannot_activate",
        "owner_activation_and_active_from_pad",
        "unknown_catalog_cannot_activate",
        "new_generation_supersedes_and_never_inherits_activation",
        "revocation_final_entry_and_cancellation",
        "uninstall_revokes",
        "target_switch_order_keeps_a_target",
    } <= names
