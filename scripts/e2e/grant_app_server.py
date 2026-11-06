"""Grant/custody server using the real guard on the compose network's TLS origin."""

import socket

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

host = "library-grant.test"
address = socket.gethostbyname(host)
destination = parse_destination({
    "host": host, "port": 8765, "path": "/**", "methods": ["GET"],
    "network": "internal", "cidr": address + "/32",
}, internal_destinations=InternalDestinations.ALLOWED)
app = create_app()
app.state.manifest_fetcher = ManifestFetcher(
    egress=Egress(addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                  resolver=DnsResolver(), user_agent="grant-app-test/1",
                  ca_file="/fixture/tls/ca.pem"),
    destination=destination,
)
uvicorn.run(app, host="0.0.0.0", port=8000)
