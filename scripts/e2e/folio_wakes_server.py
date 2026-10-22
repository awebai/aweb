"""Disposable wakes server with the installation test's exact TLS destination.

Only GETs to this test app's address/port are allowed, including the catalog's
advertised manifest variant paths. The
normal shared egress guard still verifies TLS, pins the address, refuses
redirects and applies response bounds. Production defaults are unchanged.
"""

import os

import uvicorn
from aweb.api import create_app
from aweb.app_manifests import ManifestFetcher
from aweb_naapp.egress import (
    AddressPolicy,
    Egress,
    InternalDestinations,
    parse_destination,
)

address = os.environ["FOLIO_WAKES_ADDRESS"]
destination = parse_destination({
    "host": address, "port": 38765, "path": "/**", "methods": ["GET"],
    "network": "internal", "cidr": address + "/32",
}, internal_destinations=InternalDestinations.ALLOWED)
app = create_app()
app.state.manifest_fetcher = ManifestFetcher(
    egress=Egress(addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                  ca_file="/tls/ca.pem"),
    destination=destination,
)
uvicorn.run(app, host="0.0.0.0", port=38000)
