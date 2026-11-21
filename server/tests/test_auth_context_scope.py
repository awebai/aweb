"""Named auth scope retains the released constructor and JSON field vocabulary."""

import json
from dataclasses import asdict

import pytest
from aweb.auth_context import MessagingAuth, TeamIdentity
from aweb.identity_scope import IdentityScope


def test_existing_constructor_strings_become_named_scope_without_changing_json():
    identity = TeamIdentity(
        team_id="team:example.test",
        alias="worker",
        did_key="did:key:worker",
        did_aw="",
        address="",
        agent_id="native-agent",
        identity_scope="ephemeral",
        certificate_id="member-certificate",
    )
    assert identity.identity_scope is IdentityScope.LOCAL
    assert json.loads(json.dumps(asdict(identity)))["identity_scope"] == "local"
    messaging = MessagingAuth(
        did_key="did:key:worker",
        did_aw=None,
        address=None,
        identity_scope="global",
    )
    assert messaging.identity_scope is IdentityScope.GLOBAL
    assert json.loads(json.dumps(asdict(messaging)))["identity_scope"] == "global"


def test_identity_only_messaging_has_no_implicit_team_scope():
    auth = MessagingAuth(did_key="did:key:worker", did_aw=None, address=None)
    assert auth.identity_scope is None
    with pytest.raises(ValueError, match="identity_scope must"):
        MessagingAuth(did_key="did:key:worker", did_aw=None, address=None, identity_scope="unknown")
