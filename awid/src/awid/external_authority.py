"""Pure strict external-address authority and network-policy primitives.

These functions are deliberately separate from the home/operator RegistryClient.
They contain no stale/degraded fallback and do not consume sender claims as cache
keys or fetched authority.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from typing import Protocol, Sequence
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
from publicsuffix2 import get_sld

from awid.did import validate_did
from awid.federation_errors import FederationAuthorityError
from awid.signing import canonical_json_bytes

PUBLIC_REGISTRY_ORIGIN = "https://api.awid.ai"
AUTHORITY_STATEMENT_VERSION = "aweb.federation-authority.dns.v1"
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class DNSLookup:
    outcome: str
    records: tuple[str, ...] = ()


class TXTOutcomeResolver(Protocol):
    async def lookup_txt(self, name: str) -> DNSLookup: ...


class SystemTXTOutcomeResolver:
    """Map dnspython outcomes into the strict discovery taxonomy."""

    async def lookup_txt(self, name: str) -> DNSLookup:
        try:
            answers = await dns.asyncresolver.resolve(name, "TXT")
        except dns.resolver.NXDOMAIN:
            return DNSLookup("nxdomain")
        except dns.resolver.NoAnswer:
            return DNSLookup("nodata")
        except dns.exception.Timeout:
            return DNSLookup("timeout")
        except dns.resolver.NoNameservers:
            return DNSLookup("servfail")
        except Exception:
            return DNSLookup("servfail")
        records: list[str] = []
        try:
            for answer in answers:
                records.append(b"".join(answer.strings).decode("utf-8"))
        except (AttributeError, UnicodeDecodeError):
            return DNSLookup("malformed")
        if not any(record.strip().startswith("awid=") for record in records):
            return DNSLookup("no_awid_record", tuple(records))
        return DNSLookup("record", tuple(records))


@dataclass(frozen=True)
class OriginContext:
    app_env: str = "production"
    federation_test_enabled: bool = False
    listener_origin: str = ""


@dataclass(frozen=True)
class RegistryAuthority:
    selection: str
    authority_name: str
    controller_did: str | None
    inherited: bool
    registry_explicit: bool
    registry_origin: str


@dataclass(frozen=True)
class AuthorityStatement:
    canonical_payload: bytes
    version: str
    digest: str


@dataclass(frozen=True)
class SourceIP:
    source_ip: str | None
    forwarded_header_used: bool
    unknown_bucket: bool


def canonical_protocol_address(value: str) -> str:
    value = (value or "").strip()
    if value.count("/") != 1 or "\\" in value:
        raise FederationAuthorityError("sender_registry_unresolvable")
    domain, name = value.split("/", 1)
    if domain.endswith("."):
        domain = domain[:-1]
    domain = domain.lower()
    if not domain or not name or len(domain) > 253:
        raise FederationAuthorityError("sender_registry_unresolvable")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise FederationAuthorityError("sender_registry_unresolvable") from exc
    try:
        ipaddress.ip_address(domain.strip("[]"))
    except ValueError:
        pass
    else:
        raise FederationAuthorityError("sender_registry_unresolvable")
    labels = domain.split(".")
    if any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise FederationAuthorityError("sender_registry_unresolvable")
    if any(char.isspace() or ord(char) < 0x20 or ord(char) == 0x7F for char in name):
        raise FederationAuthorityError("sender_registry_unresolvable")
    return f"{domain}/{name}"


def canonical_protocol_domain(value: str) -> str:
    address = canonical_protocol_address(f"{value}/_")
    return address.split("/", 1)[0]


def _candidate_domains(domain: str, registered_domain: str | None) -> list[str]:
    domain = canonical_protocol_domain(domain)
    if registered_domain is None:
        registered_domain = get_sld(domain, strict=True) or domain
    registered_domain = canonical_protocol_domain(registered_domain)
    if domain != registered_domain and not domain.endswith("." + registered_domain):
        raise FederationAuthorityError("sender_registry_discovery_failed")
    labels = domain.split(".")
    boundary_labels = registered_domain.split(".")
    return [".".join(labels[index:]) for index in range(len(labels) - len(boundary_labels) + 1)]


def _parse_awid_record(record: str, *, dns_name: str, context: OriginContext) -> RegistryAuthority:
    fields: dict[str, str] = {}
    for raw_part in record.split(";"):
        part = raw_part.strip()
        if not part:
            continue
        if "=" not in part:
            raise FederationAuthorityError("sender_registry_discovery_failed")
        key, value = (piece.strip() for piece in part.split("=", 1))
        if key in fields or key not in {"awid", "controller", "registry"} or not value:
            raise FederationAuthorityError("sender_registry_discovery_failed")
        fields[key] = value
    if fields.get("awid") != "v1" or not validate_did(fields.get("controller", "")):
        raise FederationAuthorityError("sender_registry_discovery_failed")
    explicit = "registry" in fields
    registry = fields.get("registry", PUBLIC_REGISTRY_ORIGIN)
    registry = canonical_registry_origin(registry, context=context)
    return RegistryAuthority(
        selection="dns",
        authority_name=dns_name,
        controller_did=fields["controller"],
        inherited=False,
        registry_explicit=explicit,
        registry_origin=registry,
    )


async def discover_registry_authority(
    domain: str,
    resolver: TXTOutcomeResolver,
    *,
    registered_domain: str | None = None,
    origin_context: OriginContext | None = None,
) -> RegistryAuthority:
    canonical = canonical_protocol_domain(domain)
    context = origin_context or OriginContext()
    for candidate in _candidate_domains(canonical, registered_domain):
        qname = f"_awid.{candidate}"
        try:
            result = await resolver.lookup_txt(qname)
        except Exception as exc:
            raise FederationAuthorityError("sender_registry_discovery_failed") from exc
        if result.outcome in {"nxdomain", "nodata", "no_awid_record"}:
            continue
        if result.outcome != "record":
            raise FederationAuthorityError("sender_registry_discovery_failed")
        records = tuple(record.strip() for record in result.records if record.strip().startswith("awid="))
        if len(records) != 1:
            raise FederationAuthorityError("sender_registry_discovery_failed")
        authority = _parse_awid_record(records[0], dns_name=qname, context=context)
        return RegistryAuthority(
            selection=authority.selection,
            authority_name=authority.authority_name,
            controller_did=authority.controller_did,
            inherited=candidate != canonical,
            registry_explicit=authority.registry_explicit,
            registry_origin=authority.registry_origin,
        )
    return RegistryAuthority(
        selection="public_default",
        authority_name="",
        controller_did=None,
        inherited=False,
        registry_explicit=False,
        registry_origin=PUBLIC_REGISTRY_ORIGIN,
    )


def authority_statement(
    *,
    authority_name: str,
    controller_did: str,
    inherited: bool,
    registry_explicit: bool,
    registry_origin: str,
    selection: str,
    version: str,
) -> AuthorityStatement:
    payload = canonical_json_bytes(
        {
            "authority_name": authority_name,
            "controller_did": controller_did,
            "inherited": inherited,
            "registry_explicit": registry_explicit,
            "registry_origin": registry_origin,
            "selection": selection,
            "version": version,
        }
    )
    return AuthorityStatement(
        canonical_payload=payload,
        version=AUTHORITY_STATEMENT_VERSION,
        digest="sha256:" + hashlib.sha256(payload).hexdigest(),
    )


def _is_isolated_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return (
            "." not in host
            or host == "localhost"
            or host.endswith(".localhost")
            or host.endswith(".test")
            or host.endswith(".test.local")
        )
    return address.is_loopback


def _isolated_http_enabled(host: str, context: OriginContext) -> bool:
    if context.app_env.strip().lower() != "development" or not context.federation_test_enabled:
        return False
    try:
        listener = urlsplit(context.listener_origin)
    except ValueError:
        return False
    listener_host = listener.hostname or ""
    return _is_isolated_host(host) and _is_isolated_host(listener_host)


def canonical_registry_origin(raw: str, *, context: OriginContext | None = None) -> str:
    context = context or OriginContext()
    raw = (raw or "").strip()
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise FederationAuthorityError("sender_registry_origin_forbidden") from exc
    try:
        host.encode("ascii")
    except UnicodeEncodeError as exc:
        raise FederationAuthorityError("sender_registry_origin_forbidden") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise FederationAuthorityError("sender_registry_origin_forbidden")
    host = host.lower().rstrip(".")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    isolated = _isolated_http_enabled(host, context)
    if parsed.scheme != "https" and not isolated:
        raise FederationAuthorityError("sender_registry_origin_forbidden")
    if literal is not None and not isolated:
        raise FederationAuthorityError("sender_registry_origin_forbidden")
    if parsed.scheme == "http" and not _is_isolated_host(host):
        raise FederationAuthorityError("sender_registry_origin_forbidden")
    default_port = 443 if parsed.scheme == "https" else 80
    host_out = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        host_out = f"{host_out}:{port}"
    return f"{parsed.scheme}://{host_out}"


def _is_allowed_external_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def isolated_registry_test_enabled(origin: str, context: OriginContext) -> bool:
    try:
        host = urlsplit(origin).hostname or ""
    except ValueError:
        return False
    return _isolated_http_enabled(host, context)


def validate_resolved_addresses(
    values: Sequence[str], *, allow_nonpublic_test: bool = False
) -> tuple[str, ...]:
    approved: list[str] = []
    for value in values:
        try:
            canonical = str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise FederationAuthorityError("sender_registry_origin_forbidden") from exc
        address = ipaddress.ip_address(canonical)
        allowed_test_address = allow_nonpublic_test and (
            address.is_private or address.is_loopback or address.is_link_local
        )
        if not _is_allowed_external_ip(canonical) and not allowed_test_address:
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        if canonical not in approved:
            approved.append(canonical)
    if not approved:
        raise FederationAuthorityError("sender_registry_origin_forbidden")
    return tuple(approved)


def normalize_source_ip(
    *,
    direct_peer: str,
    forwarded_for: str,
    trusted_proxy_cidrs: Sequence[str],
) -> SourceIP:
    try:
        peer = ipaddress.ip_address(direct_peer.strip())
        networks = tuple(ipaddress.ip_network(value) for value in trusted_proxy_cidrs)
    except ValueError:
        return SourceIP(None, False, True)
    if not any(peer in network for network in networks):
        return SourceIP(str(peer), False, False)
    try:
        hops = [ipaddress.ip_address(value.strip()) for value in forwarded_for.split(",")]
    except ValueError:
        return SourceIP(None, False, True)
    source = next(
        (hop for hop in reversed(hops) if not any(hop in network for network in networks)),
        None,
    )
    return SourceIP(str(source) if source is not None else None, True, source is None)


def compare_claim_to_evidence(
    evidence: dict[str, object],
    *,
    did_aw: str,
    current_did_key: str,
    delivery_origin: str,
) -> dict[str, object]:
    if evidence.get("did_aw") != did_aw:
        raise FederationAuthorityError("sender_address_did_mismatch", did_aw=did_aw)
    if evidence.get("current_did_key") != current_did_key:
        raise FederationAuthorityError("sender_current_key_mismatch", did_aw=did_aw)
    if evidence.get("delivery_origin") != delivery_origin:
        raise FederationAuthorityError("sender_route_mismatch", did_aw=did_aw)
    return evidence
