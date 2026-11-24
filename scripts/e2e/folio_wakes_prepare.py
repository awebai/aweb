"""Prepare public test material in the wakes stack's disposable named volume."""

from pathlib import Path

from container_fixture_modes import prepare_fixture_permissions

from aweb_naapp_contracts_testing.network import make_certificates

certificates = Path("/fixture/tls")
certificates.mkdir(parents=True, exist_ok=True)
make_certificates(certificates, ["folio-wakes.test"], [])
for name, byte in (("emit-other", "02"), ("grant-read", "03")):
    path = certificates / (name + ".key")
    path.write_text(byte * 32 + "\n")
    path.chmod(0o644)

prepare_fixture_permissions(root=Path("/fixture"))
