"""DNS TXT record verification for awid namespace authority.

Exact namespace verification uses:
    _awid.<domain> TXT "awid=v1; controller=<did:key>; [registry=<origin>;]"

Client-side registry discovery can inherit the nearest ancestor awid record,
which keeps parent-authorized subdomains resolvable without duplicating TXT
records on every child name.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import os

import dns.asyncresolver
import dns.exception
import dns.resolver

from aweb.awid.did import validate_did
from aweb.awid.log import canonical_server_origin
from aweb.config import DEFAULT_AWID_REGISTRY_URL


@dataclass(frozen=True)
class DomainAuthority:
    controller_did: str
    registry_url: str
    dns_name: str
    inherited: bool = False


class DnsVerificationError(Exception):
    """Raised when DNS verification of a domain fails."""


_AWID_PREFIX = "awid="


async def verify_domain(domain: str) -> DomainAuthority:
    """Verify a domain's exact awid TXT record and return its authority."""
    authority = await _lookup_domain_authority(domain, allow_ancestors=False)
    if authority is None:
        qname = awid_txt_name(domain)
        raise DnsVerificationError(f"No TXT records found for {qname}")
    return authority


async def discover_authoritative_registry(domain: str) -> str:
    """Discover the authoritative registry for a domain.

    Walks up the DNS hierarchy until it finds the nearest awid TXT record.
    If no awid TXT record exists, fall back to the default public registry.
    """
    authority = await _lookup_domain_authority(domain, allow_ancestors=True)
    if authority is None:
        return DEFAULT_AWID_REGISTRY_URL
    return authority.registry_url


def awid_txt_name(domain: str) -> str:
    return f"_awid.{_canonicalize_domain(domain)}"


def awid_txt_value(controller_did: str, registry_url: str | None = None) -> str:
    parts = ["awid=v1", f"controller={controller_did}"]
    if registry_url is not None:
        parts.append(f"registry={canonical_server_origin(registry_url)}")
    return "; ".join(parts) + ";"


async def _lookup_domain_authority(domain: str, *, allow_ancestors: bool) -> DomainAuthority | None:
    candidate_domains = _candidate_domains_for_lookup(domain, allow_ancestors=allow_ancestors)
    for candidate_domain in candidate_domains:
        qname = awid_txt_name(candidate_domain)

        try:
            answers = await dns.asyncresolver.resolve(qname, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            if allow_ancestors:
                continue
            return None
        except (dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            raise DnsVerificationError(f"DNS lookup failed for {qname}") from exc

        awid_records = []
        for rdata in answers:
            text = b"".join(rdata.strings).decode()
            if text.startswith(_AWID_PREFIX):
                awid_records.append(text)

        if not awid_records:
            if allow_ancestors:
                continue
            raise DnsVerificationError(f"No awid TXT record found at {qname}")

        if len(awid_records) > 1:
            raise DnsVerificationError(
                f"Multiple awid TXT records found at {qname} — expected exactly one"
            )

        authority = _parse_awid_record(awid_records[0], dns_name=qname)
        if candidate_domain != _canonicalize_domain(domain):
            return DomainAuthority(
                controller_did=authority.controller_did,
                registry_url=authority.registry_url,
                dns_name=authority.dns_name,
                inherited=True,
            )
        return authority

    return None


def _canonicalize_domain(domain: str) -> str:
    """Lowercase and strip trailing dot."""
    return domain.lower().rstrip(".")


def _candidate_domains_for_lookup(domain: str, *, allow_ancestors: bool) -> list[str]:
    canonical_domain = _canonicalize_domain(domain)
    if not allow_ancestors:
        return [canonical_domain]

    labels = canonical_domain.split(".")
    boundary_domain = _registered_domain_boundary(canonical_domain)
    boundary_labels = boundary_domain.split(".")
    max_index = len(labels) - len(boundary_labels)
    return [".".join(labels[index:]) for index in range(max_index + 1)]


def _registered_domain_boundary(domain: str) -> str:
    try:
        from publicsuffix2 import get_sld
    except ImportError as exc:
        raise RuntimeError("publicsuffix2 is required for awid registry discovery") from exc

    boundary = get_sld(domain, strict=True)
    if not boundary:
        return domain
    return _canonicalize_domain(boundary)


def _parse_awid_record(record: str, *, dns_name: str) -> DomainAuthority:
    """Parse an awid TXT record.

    Expected format: awid=v1; controller=<did:key>; [registry=<origin>;]
    """
    fields: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        normalized_key = key.strip()
        if normalized_key in fields:
            raise DnsVerificationError(f"Duplicate {normalized_key} field in awid TXT record")
        fields[normalized_key] = value.strip()

    version = fields.get("awid")
    if version != "v1":
        raise DnsVerificationError(f"Unsupported awid version: {version}")

    controller = fields.get("controller")
    if not controller:
        raise DnsVerificationError("Missing controller field in awid TXT record")
    if not validate_did(controller):
        raise DnsVerificationError(f"Invalid controller DID: {controller} (must be did:key Ed25519)")

    registry = fields.get("registry")
    if registry:
        try:
            registry = _validate_registry_origin(registry)
        except Exception as exc:
            raise DnsVerificationError(f"Invalid registry origin in awid TXT record: {registry}") from exc
    else:
        registry = DEFAULT_AWID_REGISTRY_URL

    return DomainAuthority(
        controller_did=controller,
        registry_url=registry,
        dns_name=dns_name,
        inherited=False,
    )


def _validate_registry_origin(registry_url: str) -> str:
    canonical = canonical_server_origin(registry_url)
    parsed = ipaddress.ip_address  # bind for local use below without repeated global lookup

    from urllib.parse import urlparse

    url = urlparse(canonical)
    host = (url.hostname or "").lower()
    if not host:
        raise ValueError("registry URL must include a host")

    if _is_production_environment() and url.scheme != "https":
        raise ValueError("registry URL must use https in production")

    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("registry URL must not target localhost")

    try:
        ip = parsed(host)
    except ValueError:
        ip = None

    if ip is not None:
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise ValueError("registry URL must not target a local or reserved IP address")
        raise ValueError("registry URL must not use a literal IP address")

    return canonical


def _is_production_environment() -> bool:
    for name in ("APP_ENV", "ENVIRONMENT"):
        value = (os.getenv(name) or "").strip().lower()
        if value:
            return value in {"prod", "production"}
    return False
