"""Explicit native protection for a selected test world.

Calling this helper opts the selected test world into protection. Ordinary
legacy admission/removal worlds stay unmarked. It does not prepare, approve
or sign an operation on behalf of its caller.
"""

from awid.did import did_from_public_key
from awid_service.protected_teams import provision_team_protection
from nacl.signing import SigningKey

from aweb.protected_signing.custody import ProtectedControllerCustody


async def activate(a, tmp_path):
    """Provision the selected fixture team; this is not implicit global setup."""
    w = a.w
    name, domain = w.context.authority_id.split(":", 1)
    service = SigningKey.generate()
    directory = tmp_path / "retention-custody"
    directory.mkdir(mode=0o700)
    controller_file, service_file = directory / "controller", directory / "service"
    for path, key in ((controller_file, w.controller), (service_file, service)):
        path.write_text(bytes(key).hex())
        path.chmod(0o400)
    custody = ProtectedControllerCustody(service_id=w.context.service_id,
        team_id=w.context.authority_id, domain=domain, key_file=controller_file,
        service_key_file=service_file, worker_uids=frozenset({65534}))
    w.app.authority.custody = w.app.signer.custody = custody
    custody.configure_effects(registry=w.registry,
        clients={w.registry.registry_url: w.registry._http_client},
        receipt_origins=frozenset({w.registry.registry_url}), clock=lambda: w.app.signer.clock())
    async with w.host.db.transaction() as tx:
        await provision_team_protection(tx, domain=domain, name=name,
            service_id=w.context.service_id,
            service_did_key=did_from_public_key(bytes(service.verify_key)),
            expected_generation=0, approval_ref="native-explicit-provisioning")
    return custody
