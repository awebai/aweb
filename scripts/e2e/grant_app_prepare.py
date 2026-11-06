"""Disposable CA for the real Library install and custody journey."""
from pathlib import Path

from aweb_naapp_testing.network import make_certificates

certificates = Path("/fixture/tls")
certificates.mkdir(parents=True, exist_ok=True)
make_certificates(certificates, ["library-grant.test"], [])
