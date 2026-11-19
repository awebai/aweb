"""Parked minted plans are inert data and cannot supply a reopened context."""

from aweb_secrets.run_plan import FrozenRunPlan
from aweb_secrets.run_service import _recovery_slots
from tests.test_run_plan import _inputs, _short_lived_inputs


def test_a_durable_frozen_plan_retains_its_exact_recovery_slots():
    plan = FrozenRunPlan.freeze(**_inputs())
    assert _recovery_slots(plan) == plan.slots


def test_a_genuine_frozen_mint_recipe_has_no_reopenable_result_context():
    # Freeze the same real recipe/operation/grant template used by plan tests.
    # This is not a fabricated admitted run: decision95 still refuses it.
    plan = FrozenRunPlan.freeze(**_short_lived_inputs())
    assert plan.slots[0].body["delivery"] == "short_lived"
    assert plan.slots[0].body["mint"] is not None
    assert _recovery_slots(plan) is None
