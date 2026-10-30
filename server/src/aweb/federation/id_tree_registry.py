"""ID-tree reads scoped to the authority already admitted by Phase A."""

import asyncio
import logging
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import httpx
from awid.dns_verify import DomainAuthority
from awid.external_authority import RegistryAuthority, isolated_registry_test_enabled, validate_resolved_addresses
from awid.federation_errors import FederationAuthorityError
from awid.registry import CachedRegistryClient

logger = logging.getLogger(__name__)


class _PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, origin, approved_ips, ssl_context):
        self.origin = httpx.URL(origin)
        self.ip = approved_ips[0]
        self.transport = httpx.AsyncHTTPTransport(verify=ssl_context or True, trust_env=False)

    async def handle_async_request(self, request):
        if (request.url.scheme, request.url.host, request.url.port) != (
            self.origin.scheme, self.origin.host, self.origin.port
        ):
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        request.headers["Host"] = self.origin.netloc.decode("ascii")
        request.extensions["sni_hostname"] = self.origin.host
        request.url = request.url.copy_with(host=self.ip)
        return await self.transport.handle_async_request(request)

    async def aclose(self):
        await self.transport.aclose()


class _ScopedRegistry(CachedRegistryClient):
    def _id_status_cache_key(self, request):
        # A DNS/controller generation change cannot reuse another authority's tree.
        return self._authority_scope + super()._id_status_cache_key(request)


@asynccontextmanager
async def received_registry_client(activation, token, did_key, redis):
    row = await activation.core.repository.db.fetch_one(
        """
        SELECT c.* FROM {{tables.federation_address_authority_cohorts}} c
        JOIN {{tables.federation_did_checkpoints}} d
          ON d.did_aw = c.bound_did_aw AND d.revision = c.checkpoint_revision
         AND d.current_did_key = c.bound_current_did_key
        WHERE c.canonical_address=$1 AND c.bound_did_aw=$2
          AND c.bound_current_did_key=$3 AND c.checkpoint_revision=$4
          AND c.generation=$5 AND c.expires_at > clock_timestamp()
          AND c.authoritative_read_completed_at <= clock_timestamp()
          AND c.authoritative_read_completed_at >= clock_timestamp() - INTERVAL '60 seconds'
        """,
        token.canonical_address, token.did_aw, did_key,
        token.checkpoint_revision, token.cohort_generation,
    )
    if row is None:
        raise FederationAuthorityError("federation_authority_cas_conflict")
    authority = RegistryAuthority(
        selection=row["authority_selection"], authority_name=row["authority_name"],
        controller_did=row["controller_did"], inherited=row["inherited"],
        registry_explicit=row["registry_explicit"], registry_origin=row["registry_origin"],
    )
    # Reuse strict resolver address admission, including its isolated-test policy.
    try:
        async with asyncio.timeout(5):
            answers = await activation.resolver.host_resolver.resolve_all(urlsplit(authority.registry_origin).hostname)
    except TimeoutError as exc:
        logger.warning("Federation ID-tree registry host lookup timed out", exc_info=True)
        raise FederationAuthorityError("sender_registry_unavailable") from exc
    approved_ips = validate_resolved_addresses(
        answers, allow_nonpublic_test=isolated_registry_test_enabled(
            authority.registry_origin, activation.resolver.origin_context,
        ),
    )
    domain = token.canonical_address.split("/", 1)[0]

    async def verify_domain(requested):
        # ID-tree namespace is independent of the sender's address alias. Its
        # authority must be discovered independently, without another HTTP client.
        tree_authority = authority if requested == domain else await activation._discover_registry_authority(requested)
        if (tree_authority.selection != "dns" or not tree_authority.controller_did
                or tree_authority.registry_origin != authority.registry_origin):
            raise FederationAuthorityError("sender_registry_unavailable")
        return DomainAuthority(
            controller_did=tree_authority.controller_did, registry_url=tree_authority.registry_origin,
            dns_name=tree_authority.authority_name, inherited=tree_authority.inherited,
            registry_explicit=tree_authority.registry_explicit,
        )

    client = _ScopedRegistry(
        registry_url=authority.registry_origin, redis_client=redis,
        transport=_PinnedTransport(authority.registry_origin, approved_ips, activation.resolver.ssl_context),
        domain_verifier=verify_domain,
    )
    object.__setattr__(client, "_authority_scope", f"federation:{authority.registry_origin}:{row['authority_statement_digest']}:{token.cohort_generation}:")
    try:
        yield client
    finally:
        await client.aclose()
