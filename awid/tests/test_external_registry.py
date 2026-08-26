from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from awid.external_authority import DNSLookup, OriginContext, compare_claim_to_evidence
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from awid.identity_log_verify import IdentityCheckpoint


_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "docs" / "vectors"


def _identity() -> tuple[dict, list[dict]]:
    vector = json.loads((_VECTORS / "identity-log-v1.json").read_text())
    entries = [
        {
            **item["entry_payload"],
            "entry_hash": item["entry_hash"],
            "signature": item["signature_b64"],
        }
        for item in vector["entries"]
    ]
    return vector, entries


class DNS:
    async def lookup_txt(self, name: str) -> DNSLookup:
        assert name == "_awid.alpha.example.com"
        return DNSLookup(
            "record",
            (
                "awid=v1; controller=did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd; registry=https://registry-a.example;",
            ),
        )


class Hosts:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def resolve_all(self, hostname: str) -> tuple[str, ...]:
        self.calls.append(hostname)
        return ("93.184.216.34", "2606:4700:4700::1111")


class HTTP:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.paths: list[tuple[str, bool]] = []

    async def get_json(self, path: str, *, bypass_cache: bool = False):
        self.paths.append((path, bypass_cache))
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return value

    async def aclose(self) -> None:
        return None


def responses(*, include_log: bool = True, degraded: bool = False) -> dict[str, object]:
    vector, entries = _identity()
    mapping = vector["mapping"]
    head = entries[-1]
    escaped_did = mapping["did_aw"].replace(":", "%3A")
    result: dict[str, object] = {
        "/v1/namespaces/alpha.example.com": {
            "domain": "alpha.example.com",
            "controller_did": mapping["initial_did_key"],
        },
        "/v1/namespaces/alpha.example.com/addresses/Alice": {
            "address_id": "addr-alpha-alice",
            "domain": "alpha.example.com",
            "name": "Alice",
            "did_aw": mapping["did_aw"],
            "current_did_key": mapping["rotated_did_key"],
            "delivery": {"origin": "https://aweb-alpha.example"},
        },
        f"/v1/did/{escaped_did}/key": {
            "did_aw": mapping["did_aw"],
            "current_did_key": mapping["rotated_did_key"],
            "log_head": head,
            "status": "OK_DEGRADED" if degraded else "OK_VERIFIED",
        },
    }
    if include_log:
        result[f"/v1/did/{escaped_did}/log"] = entries
    return result


@pytest.mark.asyncio
async def test_fetches_complete_verified_evidence_from_one_strict_origin() -> None:
    hosts = Hosts()
    http = HTTP(responses())
    factory_calls: list[tuple[str, tuple[str, ...], int]] = []

    def factory(origin: str, approved_ips: tuple[str, ...], generation: int):
        factory_calls.append((origin, approved_ips, generation))
        return http

    resolver = StrictExternalRegistry(
        txt_resolver=DNS(),
        host_resolver=hosts,
        http_factory=factory,
        origin_context=OriginContext(),
    )
    evidence = await resolver.fetch_evidence("alpha.example.com/Alice", authority_generation=4)
    vector, _ = _identity()
    assert evidence.did_aw == vector["mapping"]["did_aw"]
    assert evidence.current_did_key == vector["mapping"]["rotated_did_key"]
    assert evidence.verified_log.seq == 2
    assert evidence.delivery_origin == "https://aweb-alpha.example"
    assert evidence.registry_origin == "https://registry-a.example"
    assert evidence.authority_statement_digest.startswith("sha256:")
    assert hosts.calls == ["registry-a.example"]
    assert factory_calls == [
        (
            "https://registry-a.example",
            ("93.184.216.34", "2606:4700:4700::1111"),
            4,
        )
    ]
    assert len({path.split("/v1", 1)[0] for path, _ in http.paths}) == 1


@pytest.mark.asyncio
async def test_response_domains_accept_canonical_equivalents() -> None:
    equivalent = responses()
    equivalent["/v1/namespaces/alpha.example.com"]["domain"] = "Alpha.Example.Com."
    equivalent["/v1/namespaces/alpha.example.com/addresses/Alice"]["domain"] = (
        "ALPHA.EXAMPLE.COM."
    )
    resolver = StrictExternalRegistry(
        txt_resolver=DNS(),
        host_resolver=Hosts(),
        http_factory=lambda *_args: HTTP(equivalent),
    )
    evidence = await resolver.fetch_evidence(
        "ALPHA.EXAMPLE.COM./Alice", authority_generation=5
    )
    assert evidence.canonical_address == "alpha.example.com/Alice"


@pytest.mark.asyncio
async def test_degraded_or_unanchored_head_forces_full_log() -> None:
    http = HTTP(responses(degraded=True))
    resolver = StrictExternalRegistry(
        txt_resolver=DNS(),
        host_resolver=Hosts(),
        http_factory=lambda *_args: http,
    )
    evidence = await resolver.fetch_evidence("alpha.example.com/Alice", authority_generation=5)
    assert evidence.verified_log.seq == 2
    assert any(path.endswith("/log") for path, _ in http.paths)


@pytest.mark.asyncio
async def test_checkpoint_must_be_contained_in_full_log() -> None:
    vector, _ = _identity()
    mapping = vector["mapping"]
    checkpoint = IdentityCheckpoint(
        seq=2,
        entry_hash="a" * 64,
        state_hash="b" * 64,
        current_did_key=mapping["rotated_did_key"],
        revision=2,
    )
    resolver = StrictExternalRegistry(
        txt_resolver=DNS(),
        host_resolver=Hosts(),
        http_factory=lambda *_args: HTTP(responses(degraded=True)),
    )
    with pytest.raises(FederationAuthorityError) as raised:
        await resolver.fetch_evidence(
            "alpha.example.com/Alice",
            authority_generation=6,
            checkpoint=checkpoint,
        )
    assert raised.value.reason == "sender_did_log_split_view"


@pytest.mark.asyncio
async def test_namespace_or_address_mismatch_never_falls_back() -> None:
    mismatched = responses()
    mismatched["/v1/namespaces/alpha.example.com"] = {
        "domain": "alpha.example.com",
        "controller_did": "did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
    }
    resolver = StrictExternalRegistry(
        txt_resolver=DNS(),
        host_resolver=Hosts(),
        http_factory=lambda *_args: HTTP(mismatched),
    )
    with pytest.raises(FederationAuthorityError) as raised:
        await resolver.fetch_evidence("alpha.example.com/Alice", authority_generation=7)
    assert raised.value.reason == "sender_address_did_mismatch"


@pytest.mark.asyncio
async def test_resolver_chain_has_one_absolute_deadline() -> None:
    class SlowDNS:
        async def lookup_txt(self, _name: str) -> DNSLookup:
            await asyncio.sleep(1)
            return DNSLookup("nxdomain")

    resolver = StrictExternalRegistry(
        txt_resolver=SlowDNS(),
        host_resolver=Hosts(),
        http_factory=lambda *_args: HTTP({}),
        deadline_seconds=0.01,
    )
    with pytest.raises(FederationAuthorityError) as raised:
        await resolver.fetch_evidence("alpha.example.com/Alice", authority_generation=8)
    assert raised.value.reason == "sender_registry_unavailable"


def test_request_claim_comparison_is_not_stored_in_fetched_evidence() -> None:
    evidence = {
        "did_aw": "did:aw:correct",
        "current_did_key": "did:key:correct",
        "delivery_origin": "https://aweb.example",
        "authority_generation": 4,
    }
    with pytest.raises(FederationAuthorityError):
        compare_claim_to_evidence(
            evidence,
            did_aw="did:aw:wrong",
            current_did_key="did:key:correct",
            delivery_origin="https://aweb.example",
        )
    assert compare_claim_to_evidence(
        evidence,
        did_aw="did:aw:correct",
        current_did_key="did:key:correct",
        delivery_origin="https://aweb.example",
    ) is evidence
