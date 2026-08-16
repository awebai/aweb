from __future__ import annotations

import json
from pathlib import Path

import httpcore
import pytest

from awid.external_authority import (
    DNSLookup,
    OriginContext,
    authority_statement,
    canonical_protocol_address,
    canonical_registry_origin,
    compare_claim_to_evidence,
    discover_registry_authority,
    normalize_source_ip,
    validate_resolved_addresses,
)
from awid.external_http import PinnedRegistryHTTP
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from awid.identity_log_verify import IdentityCheckpoint
from test_external_registry import _identity as lookup_identity


_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "docs" / "vectors"


def _load(name: str) -> dict:
    return json.loads((_VECTORS / name).read_text(encoding="utf-8"))


class VectorDNS:
    def __init__(self, queries: list[dict]) -> None:
        self._queries = {query["name"]: query for query in queries}
        self.lookups: list[str] = []

    async def lookup_txt(self, name: str) -> DNSLookup:
        self.lookups.append(name)
        query = self._queries[name]
        return DNSLookup(outcome=query["outcome"], records=tuple(query["records"]))


class ChangingHostAnswers:
    def __init__(self, initial: list[str], subsequent: list[str]) -> None:
        self._answers = (tuple(initial), tuple(subsequent))
        self.calls = 0

    async def resolve(self) -> tuple[str, ...]:
        answers = self._answers[min(self.calls, 1)]
        self.calls += 1
        return answers

    @property
    def subsequent(self) -> tuple[str, ...]:
        return self._answers[1]


@pytest.mark.parametrize("case", _load("federation-discovery-v1.json")["canonical_address_cases"], ids=lambda case: case["name"])
def test_canonical_protocol_address_vectors(case: dict) -> None:
    if case["expected"]["valid"]:
        assert canonical_protocol_address(case["input"]) == case["expected"]["canonical"]
    else:
        with pytest.raises(FederationAuthorityError) as raised:
            canonical_protocol_address(case["input"])
        assert raised.value.reason == "sender_registry_unresolvable"


@pytest.mark.parametrize("space", ["\u00a0", "\u2003"])
def test_canonical_protocol_address_rejects_unicode_space(space: str) -> None:
    with pytest.raises(FederationAuthorityError) as raised:
        canonical_protocol_address(f"alpha.example.com/Alice{space}Smith")
    assert raised.value.reason == "sender_registry_unresolvable"


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _load("federation-discovery-v1.json")["dns_cases"], ids=lambda case: case["name"])
async def test_strict_dns_discovery_vectors(case: dict) -> None:
    resolver = VectorDNS(case["queries"])
    expected = case["expected"]
    if expected["reason"]:
        with pytest.raises(FederationAuthorityError) as raised:
            await discover_registry_authority(
                case["sender_domain"],
                resolver,
                registered_domain=case["registered_domain"],
            )
        assert raised.value.reason == expected["reason"]
        return

    authority = await discover_registry_authority(
        case["sender_domain"],
        resolver,
        registered_domain=case["registered_domain"],
    )
    assert authority.selection == expected["selection"]
    assert authority.authority_name == expected["authority_name"]
    assert authority.inherited is expected["inherited"]
    assert authority.registry_explicit is expected["registry_explicit"]
    assert authority.registry_origin == expected["registry_origin"]


@pytest.mark.parametrize("case", _load("federation-discovery-v1.json")["authority_statement_cases"], ids=lambda case: case["name"])
def test_authority_statement_vectors(case: dict) -> None:
    statement = authority_statement(**case["payload"])
    assert statement.canonical_payload.decode("utf-8") == case["canonical_payload"]
    assert statement.version == case["authority_statement_version"]
    assert statement.digest == case["authority_statement_digest"]


@pytest.mark.parametrize("case", _load("federation-origin-ip-v1.json")["origin_cases"], ids=lambda case: case["name"])
def test_registry_origin_vectors(case: dict) -> None:
    context = OriginContext(**case["context"])
    expected = case["expected"]
    if expected["ok"]:
        assert canonical_registry_origin(case["input"], context=context) == expected["canonical_origin"]
    else:
        with pytest.raises(FederationAuthorityError) as raised:
            canonical_registry_origin(case["input"], context=context)
        assert raised.value.reason == expected["reason"]


@pytest.mark.parametrize("case", _load("federation-origin-ip-v1.json")["ip_cases"], ids=lambda case: case["name"])
def test_individual_registry_ip_vectors(case: dict) -> None:
    expected = case["expected"]
    if expected["allowed"]:
        assert validate_resolved_addresses([case["input"]]) == (case["input"],)
    else:
        with pytest.raises(FederationAuthorityError) as raised:
            validate_resolved_addresses([case["input"]])
        assert raised.value.reason == expected["reason"]


@pytest.mark.parametrize("case", _load("federation-origin-ip-v1.json")["answer_set_cases"], ids=lambda case: case["name"])
def test_all_resolved_addresses_are_validated(case: dict) -> None:
    expected = case["expected"]
    if expected["allowed"]:
        assert list(validate_resolved_addresses(case["answers"])) == expected["approved_ips"]
    else:
        with pytest.raises(FederationAuthorityError) as raised:
            validate_resolved_addresses(case["answers"])
        assert raised.value.reason == expected["reason"]


@pytest.mark.parametrize("case", _load("federation-origin-ip-v1.json")["source_ip_cases"], ids=lambda case: case["name"])
def test_source_ip_vectors(case: dict) -> None:
    result = normalize_source_ip(
        direct_peer=case["direct_peer"],
        forwarded_for=case["forwarded_for"],
        trusted_proxy_cidrs=case["trusted_proxy_cidrs"],
    )
    assert {
        "source_ip": result.source_ip,
        "forwarded_header_used": result.forwarded_header_used,
        "unknown_bucket": result.unknown_bucket,
    } == case["expected"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _load("federation-origin-ip-v1.json")["transport_cases"], ids=lambda case: case["name"]
)
async def test_pinned_transport_vectors(case: dict) -> None:
    resolver = ChangingHostAnswers(
        case["resolved_answers"], case["subsequent_answers"]
    )
    approved_ips = validate_resolved_addresses(await resolver.resolve())
    client = PinnedRegistryHTTP(
        origin=case["origin"],
        approved_ips=approved_ips,
        authority_generation=11,
        selected_ip=case["selected_ip"],
    )
    expected = case["expected"]
    assert resolver.calls == 1
    if case["name"] == "pinned_ip_preserves_hostname_tls_and_disables_ambient_state":
        with pytest.raises(FederationAuthorityError) as rebound:
            validate_resolved_addresses(resolver.subsequent)
        assert rebound.value.reason == "sender_registry_origin_forbidden"
        assert case["selected_ip"] not in resolver.subsequent
    else:
        assert validate_resolved_addresses(resolver.subsequent) == approved_ips
    assert client.selected_ip == expected["connect_ip"]
    assert client.selected_ip == case["selected_ip"]
    assert case["selected_ip"] in client._url("/continued")
    assert resolver.calls == 1
    assert client._hostname == expected["tls_server_name"]
    assert client._host_header == expected["host_header"]
    assert client.pool_key == (case["origin"], approved_ips, 11)
    assert expected["pool_key_fields"] == [
        "origin",
        "validated_ip_set",
        "authority_generation",
    ]
    assert all(
        expected[field] is False
        for field in (
            "second_resolution",
            "redirect_follow",
            "ambient_proxy",
            "cookies",
            "auth",
        )
    )

    original_pool = client._pool
    assert getattr(original_pool, "_proxy", None) is None
    await original_pool.aclose()

    class RedirectPool:
        def __init__(self) -> None:
            self.requests: list[httpcore.Request] = []

        async def handle_async_request(self, request: httpcore.Request) -> httpcore.Response:
            self.requests.append(request)
            return httpcore.Response(
                status=302,
                headers=[(b"location", b"https://internal.example/secret")],
                content=b"",
            )

        async def aclose(self) -> None:
            return None

    pool = RedirectPool()
    client._pool = pool
    with pytest.raises(FederationAuthorityError) as raised:
        await client.get_json("/vector")
    assert raised.value.reason == "sender_registry_protocol_invalid"
    assert len(pool.requests) == 1
    request = pool.requests[0]
    headers = {key.lower(): value for key, value in request.headers}
    assert headers[b"host"].decode() == expected["host_header"]
    assert headers[b"accept-encoding"].decode() == expected["accept_encoding"]
    assert not {b"authorization", b"proxy-authorization", b"cookie"} & headers.keys()
    assert request.extensions["sni_hostname"] == expected["tls_server_name"]
    await client.aclose()


class LookupCaseDNS:
    def __init__(self, case: dict, controller_did: str) -> None:
        self.case = case
        self.controller_did = controller_did

    async def lookup_txt(self, _name: str) -> DNSLookup:
        if self.case["selection"] == "public_default":
            return DNSLookup("nxdomain")
        return DNSLookup(
            "record",
            (
                "awid=v1; "
                f"controller={self.controller_did}; "
                f"registry={self.case['registry_origin']};",
            ),
        )


class LookupHosts:
    async def resolve_all(self, _hostname: str) -> tuple[str, ...]:
        return ("93.184.216.34",)


class LookupHTTP:
    def __init__(self, responses: dict[str, object]) -> None:
        self.responses = responses
        self.paths: list[str] = []

    async def get_json(self, path: str, *, bypass_cache: bool = False):
        self.paths.append(path)
        value = self.responses[path]
        if isinstance(value, Exception):
            raise value
        return value

    async def aclose(self) -> None:
        return None


def lookup_case_responses(case: dict) -> tuple[dict[str, object], IdentityCheckpoint | None]:
    identity, entries = lookup_identity()
    mapping = identity["mapping"]
    escaped_did = mapping["did_aw"].replace(":", "%3A")
    namespace = case["namespace"]
    address = case["address"]
    domain = (
        namespace.get("domain")
        if isinstance(namespace, dict)
        else address.get("domain")
        if isinstance(address, dict)
        else "alpha.example.com"
    )
    name = address.get("name", "Alice") if isinstance(address, dict) else "Alice"
    namespace_path = f"/v1/namespaces/{domain}"
    address_path = namespace_path + f"/addresses/{name}"
    key_path = f"/v1/did/{escaped_did}/key"
    log_path = f"/v1/did/{escaped_did}/log"
    result: dict[str, object] = {}
    if namespace == "transport_failure":
        result[namespace_path] = FederationAuthorityError("sender_registry_unavailable")
    elif namespace is None:
        result[namespace_path] = FederationAuthorityError("sender_identity_not_found")
    else:
        result[namespace_path] = namespace
    result[address_path] = (
        FederationAuthorityError("sender_identity_not_found")
        if address is None
        else address
    )
    key = case["key"]
    checkpoint = None
    if key is None:
        result[key_path] = FederationAuthorityError("sender_identity_not_found")
    else:
        key_row = dict(key)
        key_row["log_head"] = entries[-1]
        result[key_path] = key_row
        result[log_path] = entries
        if key.get("status") == "OK_DEGRADED":
            result[log_path] = FederationAuthorityError("sender_identity_not_found")
        if key.get("extends_checkpoint") is False:
            key_row["status"] = "OK_DEGRADED"
            checkpoint = IdentityCheckpoint(
                seq=1,
                entry_hash="a" * 64,
                state_hash="b" * 64,
                current_did_key=mapping["initial_did_key"],
                revision=1,
            )
    return result, checkpoint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", _load("federation-discovery-v1.json")["authority_lookup_cases"], ids=lambda case: case["name"]
)
async def test_authority_lookup_vectors(case: dict) -> None:
    identity, _entries = lookup_identity()
    http_responses, checkpoint = lookup_case_responses(case)
    http = LookupHTTP(http_responses)
    contacted_origins: list[str] = []

    def factory(origin: str, _approved: tuple[str, ...], _generation: int):
        contacted_origins.append(origin)
        return http

    resolver = StrictExternalRegistry(
        txt_resolver=LookupCaseDNS(case, identity["mapping"]["initial_did_key"]),
        host_resolver=LookupHosts(),
        http_factory=factory,
    )
    expected = case["expected"]
    namespace = case["namespace"]
    address = case["address"]
    domain = (
        namespace.get("domain")
        if isinstance(namespace, dict)
        else address.get("domain")
        if isinstance(address, dict)
        else "alpha.example.com"
    )
    name = address.get("name", "Alice") if isinstance(address, dict) else "Alice"
    canonical_address = f"{domain}/{name}"
    if expected["accepted"]:
        evidence = await resolver.fetch_evidence(
            canonical_address, authority_generation=20, checkpoint=checkpoint
        )
        assert evidence.registry_origin == case["registry_origin"]
    else:
        with pytest.raises(FederationAuthorityError) as raised:
            await resolver.fetch_evidence(
                canonical_address, authority_generation=20, checkpoint=checkpoint
            )
        assert raised.value.reason == expected["reason"]
    assert contacted_origins == [case["registry_origin"]]
    assert expected["fallback_contacted"] is False
    requested_log = any(path.endswith("/log") for path in http.paths)
    if "full_log_required" in expected:
        assert requested_log is expected["full_log_required"]


def test_wrong_claim_cannot_poison_correct_claim() -> None:
    evidence = {
        "canonical_address": "alpha.example.com/Alice",
        "did_aw": "did:aw:correct",
        "current_did_key": "did:key:correct",
        "delivery_origin": "https://aweb-alpha.example",
        "generation": 4,
    }
    with pytest.raises(FederationAuthorityError) as wrong:
        compare_claim_to_evidence(
            evidence,
            did_aw="did:aw:wrong",
            current_did_key="did:key:correct",
            delivery_origin="https://aweb-alpha.example",
        )
    assert wrong.value.reason == "sender_address_did_mismatch"

    result = compare_claim_to_evidence(
        evidence,
        did_aw="did:aw:correct",
        current_did_key="did:key:correct",
        delivery_origin="https://aweb-alpha.example",
    )
    assert result["generation"] == 4
