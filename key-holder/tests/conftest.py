"""Native holder tests use isolated real AWID, DNS, PostgreSQL and Redis."""

import asyncio
import os
from types import SimpleNamespace
from uuid import uuid4

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest_asyncio
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore
from awid.db_config import build_database_config
from awid.registry import RegistryClient
from awid_service.db import AwidDatabaseInfra
from awid_service.main import create_app
from pgdbm import AsyncDatabaseManager
from redis.asyncio import Redis
from policy_inputs import policy_file

pytest_plugins = ("pgdbm.fixtures.conftest",)


@pytest_asyncio.fixture
async def native_holder(tmp_path, test_db_factory):
    store = KeyStore.create(tmp_path / "private", organisation="holder.example.test")
    root = store.descriptor()

    class Authority(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, address):
            query = dns.message.from_wire(data)
            answer = dns.message.make_response(query)
            answer.flags |= dns.flags.AA
            if str(query.question[0].name) == "_awid.holder.example.test.":
                answer.answer.append(
                    dns.rrset.from_text(
                        "_awid.holder.example.test.",
                        0,
                        "IN",
                        "TXT",
                        '"awid=v1; controller=' + root.did_key + ';"',
                    )
                )
            else:
                answer.set_rcode(dns.rcode.NXDOMAIN)
            self.transport.sendto(answer.to_wire(), address)

    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        Authority, local_addr=("127.0.0.1", 0)
    )
    previous = dns.asyncresolver.default_resolver
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = transport.get_extra_info("sockname")[1]
    dns.asyncresolver.default_resolver = resolver
    database = await test_db_factory.create_db(suffix="holder_registry")
    old_configuration = {
        name: os.environ.get(name) for name in ("AWID_DATABASE_URL", "AWID_REDIS_URL")
    }
    os.environ["AWID_DATABASE_URL"] = database.config.get_dsn()
    os.environ["AWID_REDIS_URL"] = os.environ["REDIS_URL"]
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(
            connection_string=database.config.get_dsn(),
            min_connections=2,
            max_connections=5,
        )
    )
    infra = AwidDatabaseInfra(schema="holder_registry")
    try:
        await infra.initialize(shared_pool=pool, run_migrations=True)
        async with Redis.from_url(
            os.environ["REDIS_URL"], decode_responses=True
        ) as redis:
            app = create_app(db_infra=infra, redis=redis)
            app.state.awid_public_origins = ("http://registry.test",)
            async with app.router.lifespan_context(app):
                # Each fixture is an independent client/registry world. Keep
                # one peer for its entire scenario, as the SDK's controller
                # fixture does; never reset, enlarge or exempt its real quota.
                peer_id = uuid4().hex
                peer = "fd00:" + ":".join(peer_id[i : i + 4] for i in range(0, 28, 4))
                registry = RegistryClient(
                    "http://registry.test",
                    transport=httpx.ASGITransport(app=app, client=(peer, 12345)),
                )
                try:
                    policy = policy_file(tmp_path / "human-approval.json", root.domain)
                    holder = Holder(
                        store,
                        registry=registry,
                        human_approval_config=policy,
                        origin="https://holder.example",
                        approval_origin="https://approval.example",
                        rp_id="approval.example",
                        grading=EnrollmentGrading("passkey_only", None),
                    )
                    yield SimpleNamespace(holder=holder, registry=registry, app=app)
                finally:
                    await registry.aclose()
    finally:
        await infra.close()
        await pool.close()
        dns.asyncresolver.default_resolver = previous
        transport.close()
        for name, value in old_configuration.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
