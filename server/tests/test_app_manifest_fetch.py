"""Origin evidence through the real shared DNS/TLS egress and C3 interpreter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import pytest
import pytest_asyncio
from aweb_naapp.egress import (
    AddressPolicy,
    DnsResolver,
    Egress,
    InternalDestinations,
    parse_destination,
)
from aweb_naapp_testing.network import (
    DnsServer,
    TlsServer,
    local_address,
    make_certificates,
)

from aweb.app_manifests import ManifestFetcher, ManifestFetchError

pytestmark = pytest.mark.asyncio
NAME = "manifest.fetch.test"
CATALOG = "/.well-known/aweb-app-versions.json"
LEGACY = "/.well-known/aweb-app.json"
VARIANT = "/.well-known/aweb-app-v2.json"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


@dataclass
class Origin:
    url: str
    tls: TlsServer
    fetcher: ManifestFetcher
    public_fetcher: ManifestFetcher
    routes: dict
    dns: DnsServer

    def manifest(self, manifest_version=2, **app_changes):
        vectors = Path(__file__).parents[2] / "test-vectors/app-manifests/app-manifest-v2-v1.json"
        doc = json.loads(vectors.read_bytes())["base_manifests"][f"v{manifest_version}"]
        doc["app"].update({"origin": self.url, **app_changes})
        # Deliberately non-canonical: exact fetched bytes must survive parsing.
        return (json.dumps(doc, indent=2) + "\n").encode()

    def publish(self, data):
        self.routes[VARIANT] = (200, data, [])
        self.routes[CATALOG] = (200, json.dumps({
            "catalog_version": 1, "app_id": "fixture", "variants": [
                {"manifest_version": 1, "url": LEGACY, "digest": digest(self.manifest(1))},
                {"manifest_version": 2, "url": VARIANT, "digest": digest(data)},
            ],
        }).encode(), [])


@pytest_asyncio.fixture
async def origin(tmp_path_factory):
    host = local_address()
    certificates = make_certificates(tmp_path_factory.mktemp("manifest-origin"), [NAME], [host])
    dns = DnsServer(records={(NAME, "A"): [host]})
    routes = {}

    async def respond(seen):
        return routes.get(seen.request_line.split(" ")[1], (404, b"", []))

    tls = TlsServer(certificates, host, respond=respond)
    await dns.start()
    await tls.start()

    def guard(policy):
        return Egress(
            addresses=AddressPolicy(internal_destinations=policy),
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            user_agent="manifest-test/1", ca_file=certificates.ca_file,
        )

    destination = parse_destination({
        "host": NAME, "port": tls.port, "path": "/**", "methods": ["GET"],
        "network": "internal", "cidr": f"{host}/32",
    }, internal_destinations=InternalDestinations.ALLOWED)
    try:
        yield Origin(
            f"https://{NAME}:{tls.port}", tls,
            ManifestFetcher(egress=guard(InternalDestinations.ALLOWED), destination=destination),
            ManifestFetcher(egress=guard(InternalDestinations.DISABLED)), routes, dns,
        )
    finally:
        dns.close()
        await tls.close()


async def test_selects_v2_and_preserves_exact_bytes_origin_and_shared_interpretation(origin):
    data = origin.manifest()
    origin.publish(data)
    fetched = await origin.fetcher.fetch(origin.url)
    assert fetched.data == data
    assert fetched.digest == digest(data)
    assert fetched.origin == origin.url
    assert fetched.manifest.manifest_version == 2
    assert fetched.manifest.app_id == "fixture"
    assert fetched.manifest.surface_tools
    assert [s.request_line.split(" ")[1] for s in origin.tls.seen] == [CATALOG, VARIANT]
    for seen in origin.tls.seen:
        assert ("accept-encoding", "identity") in [(k.lower(), v) for k, v in seen.headers]


async def test_only_catalog_404_uses_legacy(origin):
    data = origin.manifest(1)
    origin.routes[LEGACY] = (200, data, [])
    fetched = await origin.fetcher.fetch(origin.url)
    assert fetched.data == data
    assert fetched.manifest.manifest_version == 1


@pytest.mark.parametrize("status", [302, 401, 500])
async def test_catalog_failure_never_falls_back_or_follows_redirects(origin, status):
    origin.routes[CATALOG] = (status, b"", [("Location", origin.url + LEGACY)])
    origin.routes[LEGACY] = (200, origin.manifest(1), [])
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url)
    assert refused.value.code == "catalog_unavailable"
    assert len(origin.tls.seen) == 1


async def test_variant_redirect_is_not_followed(origin):
    origin.publish(origin.manifest())
    origin.routes[VARIANT] = (302, b"", [("Location", origin.url + LEGACY)])
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url)
    assert refused.value.code == "variant_unavailable"
    assert len(origin.tls.seen) == 2


async def test_catalog_digest_mismatch_refuses(origin):
    origin.publish(origin.manifest())
    origin.routes[VARIANT] = (200, origin.manifest(version="2.0.0"), [])
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url)
    assert refused.value.code == "variant_digest_mismatch"


async def test_a_manifest_declaring_another_origin_is_not_origin_evidence(origin):
    origin.publish(origin.manifest(origin="https://another.example"))
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url)
    assert refused.value.code == "manifest_origin_mismatch"


async def test_confirmation_refuses_changed_exact_bytes(origin):
    data = origin.manifest()
    origin.publish(data)
    origin.publish(data + b" ")
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url, expected_digest=digest(data))
    assert refused.value.code == "manifest_changed"
    assert refused.value.status_code == 409


@pytest.mark.parametrize("catalog", [True, False])
async def test_truncated_bytes_are_never_accepted(origin, catalog):
    origin.publish(origin.manifest())
    path, bound = (CATALOG, 64 << 10) if catalog else (VARIANT, 10 << 20)
    origin.routes[path] = (200, b" " * (bound + 1), [])
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url)
    assert refused.value.code == ("catalog_unavailable" if catalog else "variant_unavailable")


async def test_default_public_policy_refuses_private_dns_before_connect(origin):
    with pytest.raises(ManifestFetchError) as refused:
        await origin.public_fetcher.fetch(origin.url)
    assert refused.value.code == "catalog_unavailable"
    assert origin.dns.queries[(NAME, "A")] > 0
    assert not origin.tls.seen


async def test_http_origin_is_refused_before_any_request(origin):
    with pytest.raises(ManifestFetchError) as refused:
        await origin.fetcher.fetch(origin.url.replace("https:", "http:"))
    assert refused.value.code == "origin_invalid"
    assert not origin.tls.seen
