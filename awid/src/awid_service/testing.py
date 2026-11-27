"""AWID in-process, for the tests of the services that rely on it.

:func:`running_registry` serves AWID's own registry routes (``mount_registry``)
on a database the test owns, with AWID's migrations applied. A relying service
reaches it through :attr:`Registry.transport`, an in-process transport that
records every request. A test may set ``fault`` to change a response after the
real handler produced it, ``down`` to make AWID unreachable, or ``delay`` to
hold each response, so the code under test, the routes and the database all
stay real.

No rate limit applies. Nothing here is used by the registry service itself.

:func:`require_selected_test_database` is the one rule for which Postgres a test
database may be created on; ``awid_service.testing_postgres`` applies it to
pgdbm's fixtures in every suite that loads that plugin.
"""

from __future__ import annotations

import asyncio
import base64
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from inspect import isawaitable
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

import httpx
from fastapi import FastAPI
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager, DatabaseConfig
from pgdbm.testing import DatabaseTestConfig
from redis.asyncio import Redis

from awid.attestation_records import (
    MEMBER_CUSTODY,
    MEMBER_PERSON,
    TEAM_CUSTODIAN,
    sign_record,
)
from awid.did import did_key_from_signing_key, generate_keypair
from awid.external_authority import DNSLookup
from awid.id_tree_requests import covering_payload
from awid.dns_verify import DomainAuthority, DnsVerificationError, DomainVerifier
from awid.contract import normalize_identity_scope
from awid.ratelimit import NoOpRateLimiter
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, sign_message
from awid.team_server_record import record_signing_bytes

from .db import AwidDatabaseInfra
from .deps import get_domain_verifier
from .main import mount_registry

if TYPE_CHECKING:
    import pytest

REGISTRY_URL = "https://registry.example"

# The Postgres server a run names for its test databases (pgdbm's own names).
_SELECTION = ("TEST_DB_HOST", "TEST_DB_PORT")


class PostgresNotSelected(RuntimeError):
    """A test database was requested on a Postgres server the run did not name."""


def selected_test_database_config() -> DatabaseTestConfig:
    """pgdbm's test database settings for the Postgres server the run names.

    Without TEST_DB_HOST and TEST_DB_PORT, pgdbm falls back to localhost:5432,
    which on a workstation is the host's own shared Postgres; a test database is
    never created there by default (aweb-admf).
    """
    missing = [name for name in _SELECTION if not os.environ.get(name)]
    if missing:
        raise PostgresNotSelected(
            f"{' and '.join(missing)} unset: test databases are created only on a "
            "Postgres server the run names, never by default on the host's "
            "localhost:5432. Run the database tests on a gate-vms lease, or point "
            "TEST_DB_HOST and TEST_DB_PORT at a disposable Postgres you started for "
            "this run. Setting TEST_DB_PORT=5432 by hand on a workstation is a "
            "knowing choice of the host's own Postgres."
        )
    return DatabaseTestConfig.from_env()


def require_selected_test_database(config: DatabaseTestConfig) -> None:
    """Refuses ``config`` unless it is the Postgres server the run names."""
    selected = selected_test_database_config()
    if (config.host, config.port) != (selected.host, selected.port):
        raise PostgresNotSelected(
            f"pgdbm's test databases target {config.host}:{config.port}, but the run "
            f"names {selected.host}:{selected.port}. Set TEST_DB_HOST and TEST_DB_PORT "
            "before the test run starts, so pgdbm reads them when it loads."
        )


# Code that keeps a child test run off every server, whatever its plugins do.
NO_NETWORK = """
import socket

def _refuse(*args, **kwargs):
    raise OSError("this test run may not open network connections")

socket.socket.connect = _refuse
socket.socket.connect_ex = _refuse
"""


# Set in the child run of check_suite_refuses_an_unnamed_server.
_UNNAMED_SERVER_CHILD = "AWID_TEST_UNNAMED_SERVER_CHILD"


def check_suite_refuses_an_unnamed_server(
    request: pytest.FixtureRequest, scratch: Path
) -> None:
    """The whole body of a suite's one test that its database fixtures refuse a
    run that names no Postgres server.

    The test runs itself again in a child pytest, which loads the suite's own
    conftest, names no server and can reach none. Only the child requests the
    factory, and it must be refused.
    """
    if _UNNAMED_SERVER_CHILD in os.environ:
        try:
            request.getfixturevalue("test_db_factory")
        except PostgresNotSelected:
            return
        raise AssertionError("the suite's test_db_factory admitted an unnamed server")

    (scratch / "no_network.py").write_text(NO_NETWORK)
    # The parent's worker and options are not the child's.
    environ = {
        name: value
        for name, value in os.environ.items()
        if name not in _SELECTION and not name.startswith("PYTEST_")
    }
    environ[_UNNAMED_SERVER_CHILD] = "1"
    environ["PYTHONPATH"] = os.pathsep.join(
        filter(None, (str(scratch), os.environ.get("PYTHONPATH")))
    )
    child = subprocess.run(
        [
            sys.executable,
            "-P",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no_network",
            "-p",
            "no:cacheprovider",
        ]
        + [f"--basetemp={scratch / 'child'}", f"{request.path}::{request.node.name}"],
        cwd=request.config.invocation_params.dir,
        env=environ,
        capture_output=True,
        text=True,
    )
    output = child.stdout + child.stderr
    assert child.returncode == 0 and "1 passed" in child.stdout, output


SERVICE_TOKEN = "awid-testing-service-token-32-bytes"

# Changes the real response in place, or returns a response to send instead.
ResponseFault = Callable[[httpx.Request, httpx.Response], httpx.Response | None]


async def fixture_domain_authority(
    overrides: Mapping[
        Callable[..., Any], Callable[[], DomainVerifier | Awaitable[DomainVerifier]]
    ],
    domain: str,
) -> DomainAuthority:
    """Resolve the fixture's DNS override outside FastAPI dependency injection."""
    factory = overrides.get(get_domain_verifier)
    if factory is None:
        raise DnsVerificationError(f"No TXT records found for _awid.{domain}")
    verifier = factory()
    if isawaitable(verifier):
        verifier = await verifier
    return await verifier(domain)


class ServiceTransport(httpx.AsyncBaseTransport):
    """Delivers each request to a real in-process service and records it."""

    def __init__(self, app: FastAPI) -> None:
        self._inner = httpx.ASGITransport(app=app)
        self.calls: list[httpx.Request] = []
        self.fault: ResponseFault | None = None
        self.down = False
        self.delay = 0.0

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.down:
            raise httpx.ConnectError("service unreachable", request=request)
        if self.delay:
            await asyncio.sleep(self.delay)
        response = await self._inner.handle_async_request(request)
        if self.fault is None:
            return response
        await response.aread()
        replacement = self.fault(request, response)
        return response if replacement is None else replacement


def _did_key(key: SigningKey) -> str:
    return did_key_from_signing_key(bytes(key))


class TXTAnswers:
    """DNS as a relying server sees it: ``_awid`` records by query name,
    NXDOMAIN for anything else. DNS is outside every service under test."""

    def __init__(self, controllers: dict[str, str] | None = None) -> None:
        self.controllers = dict(controllers or {})

    async def lookup_txt(self, name: str) -> DNSLookup:
        controller = self.controllers.get(name)
        if controller is None:
            return DNSLookup("nxdomain")
        return DNSLookup("record", (f"awid=v1; controller={controller};",))


def dns_naming(domain: str, controller: SigningKey | str) -> TXTAnswers:
    """DNS whose ``_awid.<domain>`` names ``controller`` as namespace controller."""
    did = controller if isinstance(controller, str) else _did_key(controller)
    return TXTAnswers({f"_awid.{domain}": did})


class TeamMemberFixture(Protocol):
    team_id: str
    certificate_id: str
    team_key: SigningKey

    @property
    def team_did_key(self) -> str: ...

    @property
    def did_key(self) -> str: ...


class AttestationOperation(StrEnum):
    CUSTODIAN = "publish_team_custodian"
    CUSTODY = "publish_member_custody"
    PERSON = "publish_member_person"


class TeamVisibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"


@dataclass(frozen=True)
class _CertificateAuthority:
    team_id: str
    signing_key: SigningKey = field(repr=False)


@dataclass
class Registry:
    """A running in-process AWID: its app, its database and its transport."""

    app: FastAPI
    db: AsyncDatabaseManager
    transport: ServiceTransport
    registry_url: str = REGISTRY_URL
    _namespace_keys: dict[str, bytes] = field(default_factory=dict, repr=False)
    _certificate_authority: dict[tuple[str, str], _CertificateAuthority] = field(
        default_factory=dict, repr=False
    )

    _registry_client: RegistryClient | None = field(
        default=None, init=False, repr=False
    )

    async def ensure_namespace(
        self,
        *,
        domain: str,
        controller: bytes | None = None,
    ) -> bytes:
        """Register namespace authority through AWID; retain only fixture-owned custody.

        docs/identity.md:95-100 separates namespace authority from the team key.
        The fixture's DNS answer is outside the registry under test, as TXTAnswers is.
        """
        key = controller if controller is not None else self._namespace_keys.get(domain)
        client = self._client()
        known = await client.get_namespace(domain)
        if known is not None:
            if key is None or known.controller_did != did_key_from_signing_key(key):
                raise ValueError(
                    f"Namespace {domain} has a different controller. "
                    "Pass its current signing key as controller=."
                )
            self._namespace_keys[domain] = key
            return key
        if key is None:
            key, _ = generate_keypair()
        self._namespace_keys[domain] = key
        if get_domain_verifier not in self.app.dependency_overrides:

            async def get_namespace_verifier() -> DomainVerifier:
                return self.namespace_authority

            self.app.dependency_overrides[get_domain_verifier] = get_namespace_verifier
        try:
            await client.register_namespace(domain, did_key_from_signing_key(key), key)
        except Exception:
            del self._namespace_keys[domain]
            raise
        return key

    async def namespace_authority(self, domain: str) -> DomainAuthority:
        """The DNS authority published by this fixture's explicit namespace controller."""
        key = self._namespace_keys.get(domain)
        if key is None:
            raise DnsVerificationError(
                f"No fixture DNS authority exists for {domain}. "
                "Register the namespace through ensure_namespace first."
            )
        return DomainAuthority(
            controller_did=did_key_from_signing_key(key),
            registry_url=self.registry_url,
            dns_name=f"_awid.{domain}",
        )

    async def add_team(
        self,
        team_id: str,
        team_did_key: str,
        *,
        visibility: TeamVisibility | str = TeamVisibility.PUBLIC,
        namespace_controller: SigningKey | None = None,
    ) -> None:
        """Create the team by its namespace controller, per docs/identity.md:95-100."""
        name, domain = team_id.split(":", 1)
        controller = await self.ensure_namespace(
            domain=domain,
            controller=bytes(namespace_controller)
            if namespace_controller is not None
            else None,
        )
        await self._client().register_team(
            domain=domain,
            name=name,
            display_name=name,
            team_did_key=team_did_key,
            visibility=visibility,
            namespace_controller_signing_key=controller,
        )

    async def rotate_team_key(self, team_id: str, team_did_key: str) -> None:
        """Write the registry's team key directly, as the registry's operator
        could: no namespace-controller act backs it, so a server that pinned
        the team refuses it (awid.team_key_acts)."""
        name, domain = team_id.split(":", 1)
        await self.db.execute(
            "UPDATE {{tables.teams}} SET team_did_key = $3 WHERE domain = $1 AND name = $2",
            domain,
            name,
            team_did_key,
        )

    async def rotate_team_key_by_controller(
        self, team_id: str, team_did_key: str, controller: SigningKey
    ) -> None:
        """Rotate through the real route, signed by ``controller`` as the
        namespace controller (registered for the domain if it has none), so
        AWID keeps the act a pinned server checks against DNS (dns_naming)."""
        name, domain = team_id.split(":", 1)
        namespace_key = await self.ensure_namespace(
            domain=domain, controller=bytes(controller)
        )
        await self._client().rotate_team_key(
            domain,
            name,
            new_team_did_key=team_did_key,
            namespace_controller_signing_key=namespace_key,
        )

    async def add_certificate(
        self, cert: dict[str, Any], *, team_key: SigningKey
    ) -> None:
        """Register the signed membership through AWID, per docs/identity.md:97-100."""
        name, domain = cert["team_id"].split(":", 1)
        await self._client().register_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(team_key),
            certificate_id=cert["certificate_id"],
            member_did_key=cert["member_did_key"],
            member_did_aw=cert.get("member_did_aw"),
            member_address=cert.get("member_address"),
            alias=cert["alias"],
            identity_scope=normalize_identity_scope(
                cert.get("identity_scope", cert.get("lifetime"))
            ),
            certificate=base64.b64encode(canonical_json_bytes(cert)).decode("ascii"),
        )
        self._certificate_authority[(cert["team_id"], cert["certificate_id"])] = (
            _CertificateAuthority(cert["team_id"], team_key)
        )

    async def revoke(self, certificate_id: str, *, team_id: str | None = None) -> None:
        """Revoke using the controller custody recorded by successful registration."""
        matching = [
            authority
            for (
                registered_team,
                registered_certificate,
            ), authority in self._certificate_authority.items()
            if registered_certificate == certificate_id
            and (team_id is None or team_id == registered_team)
        ]
        if len(matching) != 1:
            raise ValueError(
                "Certificate controller custody is unavailable. "
                "Register it through add_certificate and select team_id= before revoking it."
            )
        authority = matching[0]
        name, domain = authority.team_id.split(":", 1)
        await self._client().revoke_team_certificate(
            domain,
            name,
            team_controller_signing_key=bytes(authority.signing_key),
            certificate_id=certificate_id,
        )

    async def publish_signed_record(
        self,
        *,
        record: dict[str, Any],
        signature: str,
        team_key: SigningKey,
    ) -> None:
        """Publish through docs/principal-attestation.md's team-controller boundary."""
        name, domain = record["team_id"].split(":", 1)
        prefix = f"/v1/namespaces/{domain}/teams/{name}"
        if record["type"] == TEAM_CUSTODIAN:
            operation = AttestationOperation.CUSTODIAN
            claims = {"team_name": name, "custodian_id": record["custodian_id"]}
            path = f"{prefix}/custodians/{record['custodian_id']}"
        elif record["type"] in (MEMBER_CUSTODY, MEMBER_PERSON):
            operation = (
                AttestationOperation.CUSTODY
                if record["type"] == MEMBER_CUSTODY
                else AttestationOperation.PERSON
            )
            claims = {"team_name": name, "certificate_id": record["certificate_id"]}
            resource = (
                "custody" if operation is AttestationOperation.CUSTODY else "person"
            )
            path = f"{prefix}/certificates/{record['certificate_id']}/{resource}"
        else:
            raise ValueError(
                "Unsupported attestation record type. "
                "Publish a team custodian, member custody or member person record."
            )
        body = canonical_json_bytes({"record": record, "signature": signature})
        timestamp = datetime.now(UTC).isoformat()
        payload = covering_payload(
            aud=self.registry_url,
            path=path,
            domain=domain,
            operation=operation,
            body=body,
            timestamp=timestamp,
            claims=claims,
            method="PUT",
        )
        headers = {
            "Content-Type": "application/json",
            "X-AWEB-Timestamp": timestamp,
            "X-AWEB-Signed-Payload": base64.urlsafe_b64encode(payload)
            .rstrip(b"=")
            .decode("ascii"),
            "Authorization": f"DIDKey {_did_key(team_key)} {sign_message(bytes(team_key), payload)}",
        }
        async with httpx.AsyncClient(
            transport=self.transport, base_url=self.registry_url
        ) as client:
            response = await client.put(path, content=body, headers=headers)
        response.raise_for_status()

    async def add_custody(
        self,
        member: TeamMemberFixture,
        *,
        custodian_id: str,
        issuer: SigningKey,
    ) -> None:
        """Register the signed custodian and custody through their actual AWID writers."""
        issued_at = datetime.now(UTC).replace(microsecond=0)
        common = {
            "v": 1,
            "team_id": member.team_id,
            "team_did_key": member.team_did_key,
            "custodian_id": custodian_id,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        }
        records = (
            {**common, "type": TEAM_CUSTODIAN, "issuer_did_keys": [_did_key(issuer)]},
            {
                **common,
                "type": MEMBER_CUSTODY,
                "certificate_id": member.certificate_id,
                "member_did_key": member.did_key,
            },
        )
        for record in records:
            await self.publish_signed_record(
                record=record,
                signature=sign_record(bytes(member.team_key), record),
                team_key=member.team_key,
            )

    def _client(self) -> RegistryClient:
        if self._registry_client is None:
            self._registry_client = RegistryClient(
                registry_url=self.registry_url, transport=self.transport
            )
        return self._registry_client

    async def aclose(self) -> None:
        """Release the client owned by this registry fixture."""
        if self._registry_client is not None:
            await self._registry_client.aclose()
            self._registry_client = None

    async def register_did(self, key: SigningKey) -> str:
        """Registers ``key`` as a new did:aw through AWID's own route; returns the did:aw."""
        mapping = await self._client().register_did(_did_key(key), bytes(key))
        return mapping.did_aw

    async def rotate_did(self, did_aw: str, old: SigningKey, new: SigningKey) -> None:
        await self._client().rotate_key(did_aw, _did_key(new), bytes(old), bytes(new))

    async def publish_team_server(
        self,
        team_id: str,
        team_key: SigningKey,
        *,
        server_url: str,
        issued_at: datetime | None = None,
    ) -> None:
        """Publishes the team's ``aweb.team-server/1`` record, signed by its
        team key, through AWID's own route."""
        name, domain = team_id.split(":", 1)
        body = signed_team_server_record(
            team_id,
            team_key,
            server_url=server_url,
            issued_at=issued_at or datetime.now(UTC),
        )
        async with httpx.AsyncClient(
            transport=self.transport, base_url=self.registry_url
        ) as client:
            response = await client.put(
                f"/v1/namespaces/{domain}/teams/{name}/server", json=body
            )
        response.raise_for_status()


def signed_team_server_record(
    team_id: str, team_key: SigningKey, *, server_url: str, issued_at: datetime
) -> dict[str, Any]:
    """A team's ``aweb.team-server/1`` record and its team-key signature, as AWID's route takes them."""
    record = {
        "v": 1,
        "type": "aweb.team-server",
        "team_id": team_id,
        "team_did_key": _did_key(team_key),
        "server_url": server_url,
        "issued_at": issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    return {
        "record": record,
        "signature": sign_message(bytes(team_key), record_signing_bytes(record)),
    }


@asynccontextmanager
async def running_registry(
    database_url: str,
    *,
    service_token: str | None = SERVICE_TOKEN,
    redis: Redis | None = None,
) -> AsyncIterator[Registry]:
    """AWID, with its migrations applied, on the empty database at ``database_url``.
    Its health reports the ``redis`` it is given, and fails without one."""
    pool = await AsyncDatabaseManager.create_shared_pool(
        DatabaseConfig(connection_string=database_url, schema=None)
    )
    infra = AwidDatabaseInfra(schema="awid")
    registry = None
    try:
        await infra.initialize(shared_pool=pool, run_migrations=True)
        app = FastAPI()
        app.state.db = infra
        app.state.redis = redis
        app.state.db_schema = infra.schema
        app.state.rate_limiter = NoOpRateLimiter()
        app.state.awid_service_token = service_token
        mount_registry(app)
        # Its public origin, which covering controller signatures name. After
        # mount_registry, which reads AWID_PUBLIC_ORIGINS from the environment.
        app.state.awid_public_origins = (REGISTRY_URL,)
        registry = Registry(
            app=app, db=infra.get_manager("aweb"), transport=ServiceTransport(app)
        )
        yield registry
    finally:
        try:
            if registry is not None:
                await registry.aclose()
        finally:
            try:
                await infra.close()
            finally:
                await pool.close()
