"""Local operator provisioning checks; real DB/authority cases live in native suite."""

import json
from types import SimpleNamespace

import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused

from aweb.protected_signing.admission import provision_policy
from aweb.protected_signing.operator import parser
from tests.test_protected_admission_policy import CONTEXT, configured_policy


class Store:
    def __init__(self, *, existing=None):
        self.row = existing
        self.inserted = []

    def transaction(self):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def execute(self, sql, *args):
        if "INSERT INTO" in sql:
            self.inserted.append(args)
            self.row = {"policy": args[-1]}
        else:
            assert "pg_advisory_xact_lock" in sql

    async def fetch_one(self, sql, *args):
        return self.row


class Authority:
    def __init__(self, *, changed=False):
        self.changed = changed
        self.checks = []

    async def observe(self, context, *, purpose):
        assert context == CONTEXT
        return self

    async def binding(self, tx, *, hold=False):
        self.checks.append(hold)
        if self.changed:
            raise SignerRefused("authority_changed")
        return {"generation": CONTEXT.generation, "policy_version": 1}

    def require_fresh(self):
        pass


def composition(*, existing=None, changed=False):
    return SimpleNamespace(db=Store(existing=existing), context=CONTEXT, authority=Authority(changed=changed))


@pytest.mark.asyncio
async def test_operator_initial_policy_is_once_only_and_exact_replay_is_not_a_change():
    c = composition()
    unsigned = configured_policy().fields()
    unsigned.pop("digest")
    first = await provision_policy(c, unsigned)
    assert first == configured_policy().fields()
    assert len(c.db.inserted) == 1
    assert await provision_policy(c, unsigned) == first
    assert len(c.db.inserted) == 1
    assert all(c.authority.checks)
    unsigned["bounds"]["max_active"] += 1
    with pytest.raises(SignerRefused, match="policy_changed"):
        await provision_policy(c, unsigned)
    assert len(c.db.inserted) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["another_team", "changed_controller", "another_service", "malformed_policy"])
async def test_operator_cannot_create_a_policy_without_its_actual_controller_authority(case):
    c = composition(changed=case == "changed_controller")
    fields = configured_policy().fields()
    fields.pop("digest")
    if case == "another_team":
        fields["teams"].append("other:customer.example")
        fields["teams"].sort()
    if case == "another_service":
        fields["root_selector"]["service_id"] = "unowned"
    if case == "malformed_policy":
        fields["bounds"]["max_active"] = 0
    with pytest.raises(SignerRefused):
        await provision_policy(c, fields)
    assert c.db.inserted == []


def test_operator_policy_init_takes_only_public_configuration_from_a_file(tmp_path):
    source = tmp_path / "policy.json"
    source.write_text(json.dumps(configured_policy().fields()))
    args = parser().parse_args(["policy-init", "--file", str(source)])
    assert args.command == "policy-init" and args.file == source
