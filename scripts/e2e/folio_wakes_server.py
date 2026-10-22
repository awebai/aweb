"""Disposable wakes server with the installation test's exact TLS destination.

Only GETs to this test app's address/port are allowed, including the catalog's
advertised manifest variant paths. The
normal shared egress guard still verifies TLS, pins the address, refuses
redirects and applies response bounds. Production defaults are unchanged.
"""

import logging
import os

import uvicorn
from aweb.api import create_app
from aweb.app_manifests import ManifestFetcher
from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    InternalDestinations,
    parse_destination,
)


class ManifestFetchDiagnostics(ManifestFetcher):
    """Keep the real fetch, with its exception chain in disposable service logs."""

    async def fetch(self, *args, **kwargs):
        try:
            return await super().fetch(*args, **kwargs)
        except Exception:
            logging.exception("Wakes fixture origin fetch failed")
            raise


address = os.environ["FOLIO_WAKES_ADDRESS"]
destination = parse_destination({
    "host": address, "port": 38765, "path": "/**", "methods": ["GET"],
    "network": "internal", "cidr": address + "/32",
}, internal_destinations=InternalDestinations.ALLOWED)
app = create_app()
app.state.manifest_fetcher = ManifestFetchDiagnostics(
    egress=Egress(addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                  resolver=DnsResolver(), user_agent="folio-wakes-test/1",
                  ca_file="/tls/ca.pem"),
    destination=destination,
)
uvicorn.run(app, host="0.0.0.0", port=38000)
