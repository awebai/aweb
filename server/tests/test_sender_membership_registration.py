"""Participant-scoped sender projections obey the staged registration rule."""

from __future__ import annotations

import base64
import json
from enum import StrEnum

import pytest
from prometheus_client import REGISTRY
from aweb.certificate_registration import RegistrationMode
from test_cli_never_grants import registry_listener
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _connect
from test_task_answers import _v2_request

__all__ = ["privacy_app"]


class RegistrationRequirement(StrEnum):
    OFF = "false"
    ENFORCE = "true"


@pytest.mark.asyncio
@pytest.mark.parametrize("requirement", list(RegistrationRequirement))
async def test_sender_membership_uses_registered_certificate_requirement(
    privacy_app, monkeypatch, requirement
):
    env = privacy_app
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "false")
    sender, recipient = env.actors["alice"], env.actors["bob"]
    async with registry_listener(env) as (registry, _):
        for actor, alias in ((sender, "alice"), (recipient, "bob")):
            assert (
                await _connect(env, (actor.sk, actor.did, alias), actor.certificate)
            ).status_code == 200
        # The reader has an actual registered certificate. The writer's valid
        # signed legacy certificate remains deliberately unregistered.
        cert = json.loads(base64.b64decode(recipient.certificate))
        await registry.register_team_certificate(
            "example.test",
            TEAM.split(":", 1)[0],
            team_controller_signing_key=env.team_sk,
            certificate_id=cert["certificate_id"],
            member_did_key=recipient.did,
            member_did_aw=None,
            member_address=None,
            alias="bob",
            identity_scope="local",
            certificate=recipient.certificate,
        )
        sent = await _v2_request(
            env,
            "alice",
            "POST",
            "/v1/messages",
            {
                "to_did": recipient.did,
                "subject": "Registration",
                "body": "Legacy sender",
            },
        )
        assert sent.status_code == 200, sent.text
        monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", requirement.value)
        mode = (
            RegistrationMode.REQUIRED
            if requirement is RegistrationRequirement.ENFORCE
            else RegistrationMode.NOT_REQUIRED
        )
        labels = {"enforcement": mode.value, "outcome": "would_refuse"}
        metric = "aweb_certificate_registration_observations_total"
        before = REGISTRY.get_sample_value(metric, labels) or 0
        shown = await _v2_request(
            env, "bob", "GET", f"/v1/messages/{sent.json()['message_id']}"
        )
        assert shown.status_code == 200, shown.text
        expected = (
            "inactive" if requirement is RegistrationRequirement.ENFORCE else "active"
        )
        assert shown.json()["sender_membership"]["state"] == expected
        assert (REGISTRY.get_sample_value(metric, labels) or 0) == before + int(
            requirement is RegistrationRequirement.ENFORCE
        )
