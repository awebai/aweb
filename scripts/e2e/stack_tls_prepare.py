"""A container test stack's disposable CA and one server certificate for its
TLS services' names.

Run with the stack's fixture volume at /fixture and aweb_naapp_testing on the
path. Writes /fixture/tls/{ca.pem,server.pem,server.key} for the hostnames and
makes the fixture's public trees readable by the stack's other users.
Usage: stack_tls_prepare.py <hostname>...
"""

import sys
from pathlib import Path

from container_fixture_modes import prepare_fixture_permissions

from aweb_naapp_testing.network import make_certificates

if len(sys.argv) < 2:
    raise SystemExit("usage: stack_tls_prepare.py <hostname>...")
certificates = Path("/fixture/tls")
certificates.mkdir(parents=True, exist_ok=True)
make_certificates(certificates, sys.argv[1:], [])
# The stack's services run as distinct users; the tls, e2e and test-support
# trees are public, and Library's grant-read key stays owner-only.
prepare_fixture_permissions(root=Path("/fixture"))
