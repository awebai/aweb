"""Pure durable binding of public app holding metadata; no DB or network."""

import json
import os
import subprocess
import sys
import unittest
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

from aweb_naapp.runtime.installation import AdmittedInstallation

from aweb_secrets.human_holders import OwnerPublicScope, OwnerSessionTarget
from aweb_secrets.owners import owner_scope

# Public-metadata known-answer vector, frozen with the v1 encoding. Any field,
# domain or encoding change requires a new version, not a changed v1 answer.
PREIMAGE = (
    b"aweb.secrets.owner-holding/1\n"
    b'{"app_id":"secrets","b3_scope":"secrets.owner.7c14a4c615d3a38f8bdbd10fa3d10dc2f26e0870",'
    b'"generation":"7","installation_id":"6f9619ff-8b86-4011-b42d-00c04fc964ff",'
    b'"principal":"did:aw:2P3H7nHnykfHALDcRjxfRLo1Pfdm","role":"secrets.owner",'
    b'"role_assigned_at":"2026-11-09T12:34:56.123456+00:00",'
    b'"subject":"00000000-0000-4000-8000-000000000001","team_id":"holding:example.com"}'
)
EXPECTED = (
    "aweb.secrets.owner-holding/1:39ef75f86baa31affd04cd89a54d367b838408e11195797b0b425876598b9b89"
)


def target():
    fields = json.loads(PREIMAGE.split(b"\n", 1)[1])
    return OwnerSessionTarget(
        OwnerPublicScope(fields["installation_id"], fields["role"], fields["principal"]),
        AdmittedInstallation(
            team_id=fields["team_id"],
            app_id=fields["app_id"],
            installation_id=fields["installation_id"],
            generation=int(fields["generation"]),
        ),
        fields["b3_scope"],
        fields["subject"],
        datetime.fromisoformat(fields["role_assigned_at"]),
    )


def identity(value):
    from aweb_secrets.human_holding_identity import owner_holding_identity

    return owner_holding_identity(value)


class HoldingIdentity(unittest.TestCase):
    def test_frozen_known_answer(self):
        value = target()
        original = value.holding_ref
        self.assertEqual(identity(value), EXPECTED)
        self.assertEqual(value.holding_ref, original)

    def test_independent_objects_and_equal_timestamp_instants_have_the_same_identity(self):
        first, second = target(), target()
        self.assertIsNot(first, second)
        offset = timezone(timedelta(hours=5, minutes=30))
        second = replace(second, _role_assigned_at=second._role_assigned_at.astimezone(offset))
        self.assertEqual(identity(first), identity(second))

    def test_another_worker_and_hash_seed_use_the_same_bytes(self):
        program = "from tests.test_human_holding_identity import target,identity;print(identity(target()))"
        for seed in ("1", "293"):
            result = subprocess.run(
                [sys.executable, "-c", program],
                env={**os.environ, "PYTHONHASHSEED": seed},
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(result.stdout.strip(), EXPECTED)

    def test_every_original_holding_binding_changes_the_identity(self):
        original = target()
        variants = [
            replace(original, admitted=replace(original.admitted, app_id="another-app")),
            replace(original, admitted=replace(original.admitted, generation=8)),
            replace(original, public_scope=replace(original.public_scope, role="another-role")),
            replace(original, subject="00000000-0000-4000-8000-000000000002"),
            replace(
                original, _role_assigned_at=original._role_assigned_at + timedelta(microseconds=1)
            ),
        ]
        for field, value in (
            ("installation_id", "new-installation"),
            ("team_id", "new:example.com"),
            ("principal", "did:aw:another-principal"),
        ):
            admitted = (
                replace(original.admitted, **{field: value})
                if field != "principal"
                else original.admitted
            )
            public = (
                replace(original.public_scope, **{field: value})
                if field != "team_id"
                else original.public_scope
            )
            variants.append(
                replace(
                    original,
                    admitted=admitted,
                    public_scope=public,
                    b3_scope=owner_scope(
                        admitted.installation_id, admitted.team_id, public.principal
                    ),
                )
            )
        for index, changed in enumerate(variants):
            with self.subTest(binding=index):
                self.assertNotEqual(identity(changed), EXPECTED)

    def test_large_generation_is_lossless(self):
        original = target()
        first = replace(original, admitted=replace(original.admitted, generation=2**63 - 2))
        second = replace(original, admitted=replace(original.admitted, generation=2**63 - 1))
        self.assertNotEqual(identity(first), identity(second))

    def test_credential_or_member_key_fields_do_not_redefine_the_holding(self):
        @dataclass(frozen=True)
        class WithEvidence(OwnerSessionTarget):
            login_credential_id: str
            member_key: str

        value = target()
        original = WithEvidence(
            value.public_scope,
            value.admitted,
            value.b3_scope,
            value.subject,
            value._role_assigned_at,
            "first",
            "old-key",
        )
        renewed = replace(original, login_credential_id="replacement", member_key="new-key")
        self.assertEqual(identity(original), EXPECTED)
        self.assertEqual(identity(renewed), EXPECTED)

    def test_mismatched_installation_or_b3_scope_and_naive_timestamp_are_refused(self):
        original = target()
        for invalid in (
            replace(original, public_scope=replace(original.public_scope, installation_id="other")),
            replace(original, b3_scope="secrets.owner.another"),
            replace(original, _role_assigned_at=original._role_assigned_at.replace(tzinfo=None)),
            replace(original, admitted=replace(original.admitted, generation=True)),
            object(),
        ):
            with self.assertRaises(ValueError):
                identity(invalid)


if __name__ == "__main__":
    unittest.main()
