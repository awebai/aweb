"""Disposable CA for the real Library install and custody journey."""

from pathlib import Path

from container_fixture_modes import prepare_fixture_permissions

from aweb_naapp_contracts_testing.network import make_certificates

certificates = Path("/fixture/tls")
certificates.mkdir(parents=True, exist_ok=True)
make_certificates(certificates, ["library-grant.test"], [])

prepare_fixture_permissions(root=Path("/fixture"))
