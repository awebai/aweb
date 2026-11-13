"""The hook act uses the existing closed wire and the one live-floor pipeline."""

from datetime import UTC, datetime

import pytest
from awid.did import did_from_public_key, generate_keypair

from aweb_naapp.hooks.owner_act import hook_binding_subject, owner_act_signing_bytes
from aweb_naapp.runtime.protected_signer import CatalogOperation, SignerRefused
from aweb_naapp.runtime.protected_signer.codecs import artifact_for, signing_bytes
from tests.runtime.test_protected_log_key import operation as log_operation


@pytest.mark.parametrize("kind", ["registration", "production"])
def test_hook_activation_freezes_the_exact_existing_binding_subject(kind):
    context = log_operation().context
    subject = hook_binding_subject(
        binding_id="00000000-0000-4000-8000-000000000003",
        installation_id="00000000-0000-4000-8000-000000000004", generation=7,
        app_id="logs", origin="https://logs.example.org", digest="sha256:" + "a" * 64,
        kind=kind, catalog_id="aweb.hooks", catalog_version=1, hook="post-command-hook",
        **({"tool": "record", "method": "POST", "path": "/record", "scopes": ["logs:write"]}
           if kind == "registration" else {"reads": ["search"]}),
    )
    operation = CatalogOperation(log_operation().operation_id, context,
                                 "https://coord.example.org", "hook-binding.activate", "default", subject)
    assert operation.spec.needs_human and operation.spec.key_role == "team_controller"
    _, public = generate_keypair()
    artifact = artifact_for(operation, did_from_public_key(public), datetime.now(UTC))
    assert signing_bytes(operation, artifact) == owner_act_signing_bytes(artifact)
    subject["generation"] = 8
    assert operation.intent()["subject"]["generation"] == 7
    with pytest.raises(SignerRefused, match="operation_mismatch"):
        signing_bytes(operation, {**artifact, "subject": subject})
    with pytest.raises(SignerRefused):
        CatalogOperation(operation.operation_id, context, operation.audience,
                         "hook-binding.activate", "default", {**subject, "signing_bytes": "raw"})
