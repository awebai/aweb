"""Controller continuity with real DNS/HTTP/PG/Redis, current and released AWID.

The old registry runs from the pinned production project in an isolated Python
process. DNS is a loopback authoritative server, not an overridden verifier.
"""

import asyncio
import os
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import dns.asyncresolver
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest
from awid.controller_signing import (
    ControllerDescriptor,
    parse_controller_object,
    parse_controller_request,
    sign_controller_object,
)
from awid.did import did_key_from_signing_key, stable_id_from_did_key
from awid.id_certificates import verify_id_chain
from awid.registry import RegistryClient, RegistryError
from nacl.signing import SigningKey

pytestmark = pytest.mark.asyncio
ROOT = Path(__file__).resolve().parents[2]

SERVE = """
import sys, dns.asyncresolver, uvicorn
from importlib.metadata import version
from awid_service.main import create_app
if sys.argv[3] != 'source':
    assert version('awid-service') == sys.argv[3]
resolver = dns.asyncresolver.Resolver(configure=False)
resolver.nameservers = ['127.0.0.1']
resolver.port = int(sys.argv[1])
dns.asyncresolver.default_resolver = resolver
uvicorn.run(create_app(), fd=int(sys.argv[2]), log_level='warning')
"""


@pytest.mark.parametrize("registry_version", ["source", "0.5.39"])
async def test_controller_continuity_and_explicit_reset_preserve_distinct_semantics(
    registry_version, awid_db_infra
):
    keys = [bytes([i]) * 32 for i in (31, 32, 33, 34, 35)]
    dids = [did_key_from_signing_key(k) for k in keys]
    records = {"_awid.example.test.": dids[0]}

    class Authority(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, address):
            query = dns.message.from_wire(data)
            answer = dns.message.make_response(query)
            answer.flags |= dns.flags.AA
            name = str(query.question[0].name)
            if name in records:
                answer.answer.append(
                    dns.rrset.from_text(
                        name,
                        0,
                        "IN",
                        "TXT",
                        '"awid=v1; controller=' + records[name] + ';"',
                    )
                )
            else:
                answer.set_rcode(dns.rcode.NXDOMAIN)
            self.transport.sendto(answer.to_wire(), address)

    loop = asyncio.get_running_loop()
    dns_transport, _ = await loop.create_datagram_endpoint(
        Authority, local_addr=("127.0.0.1", 0)
    )
    dns_port = dns_transport.get_extra_info("sockname")[1]
    previous_resolver = dns.asyncresolver.default_resolver
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = dns_port
    dns.asyncresolver.default_resolver = resolver
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    project = ROOT / (
        "awid"
        if registry_version == "source"
        else "scripts/test-egress/production-awid"
    )
    env = {
        **os.environ,
        "AWID_DATABASE_URL": awid_db_infra.get_manager().config.get_dsn(),
        "AWID_DB_SCHEMA": "sdk_version_" + registry_version.replace(".", "_"),
        "AWID_REDIS_URL": os.environ["REDIS_URL"],
        "AWID_PUBLIC_ORIGINS": origin,
        # This standalone peer owns its default per-client budget; other tests
        # sharing Redis must not spend it before this journey registers its DID.
        "AWID_RATE_LIMIT_BACKEND": "memory",
        "AWID_RATE_LIMIT_DISABLED": "0",
        "UV_PROJECT_ENVIRONMENT": str(project / ".venv"),
    }
    env.pop("PYTHONPATH", None)
    controller = ControllerDescriptor("namespace", "example.test", dids[0], "0", 0)

    def signer(context):
        seed = keys[int(context.controller.key_reference)]
        return did_key_from_signing_key(seed), SigningKey(seed).sign(
            context.signing_bytes()
        ).signature

    sdk = RegistryClient(origin)
    process = None
    with tempfile.TemporaryFile() as output:
        try:
            process = await asyncio.create_subprocess_exec(
                "uv",
                "run",
                "--frozen",
                "--project",
                str(project),
                "python",
                "-I",
                "-c",
                SERVE,
                str(dns_port),
                str(listener.fileno()),
                registry_version,
                env=env,
                pass_fds=(listener.fileno(),),
                stdout=output,
                stderr=output,
            )
            listener.close()
            async with httpx.AsyncClient(timeout=1) as http:
                async with asyncio.timeout(45):
                    while True:
                        if process.returncode is not None:
                            output.seek(0)
                            pytest.fail(output.read().decode())
                        try:
                            if (await http.get(origin + "/health")).status_code == 200:
                                break
                        except httpx.TransportError:
                            pass
                        await asyncio.sleep(0.1)

            async def run(operation, descriptor=controller, **parameters):
                return await sdk.controller_request(
                    parse_controller_request(
                        {"operation": operation, "domain": "example.test", **parameters}
                    ),
                    controllers={"controller": descriptor},
                    signer=signer,
                )

            await run("namespace_register", controller_did=dids[0])
            await run(
                "namespace_update", default_delivery_origin="https://delivery.example"
            )
            assert (
                await sdk.get_namespace("example.test")
            ).default_delivery_origin == "https://delivery.example"
            child = ControllerDescriptor(
                "namespace", "child.example.test", dids[3], "3", 0
            )
            await sdk.controller_request(
                parse_controller_request(
                    {
                        "operation": "namespace_register",
                        "domain": child.domain,
                        "controller_did": child.did_key,
                        "parent_domain": controller.domain,
                    }
                ),
                controllers={"controller": child, "parent": controller},
                signer=signer,
            )
            assert (
                await sdk.get_namespace(child.domain)
            ).controller_did == child.did_key

            subject_seed = bytes([41]) * 32
            subject_key = did_key_from_signing_key(subject_seed)
            subject = stable_id_from_did_key(subject_key)
            await sdk.register_did(subject_key, subject_seed)
            cert = {
                "v": 1,
                "type": "aweb.id-certificate",
                "id": subject,
                "domain": controller.domain,
                "parent": {"kind": "namespace", "id": controller.domain},
                "kind": "human",
                "issuer_key": controller.did_key,
                "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            signed = await sign_controller_object(
                parse_controller_object(
                    {
                        "operation": "namespace_id_issue",
                        "domain": controller.domain,
                        "kind": "human",
                        "certificate": cert,
                    }
                ),
                controller=controller,
                signer=signer,
            )
            bundle = {"v": 1, "type": "aweb.id-chain", "certificates": [signed]}
            await sdk.register_id_certificate(
                bundle,
                signer=lambda b: (
                    subject_key,
                    SigningKey(subject_seed).sign(b).signature,
                ),
                expected_head=None,
                invitation_id=None,
            )

            async def valid():
                evidence = await sdk.id_chain_evidence(
                    bundle,
                    {"id": subject, "did_key": subject_key},
                    domain=controller.domain,
                )
                return verify_id_chain(
                    bundle,
                    subject={"id": subject, "did_key": subject_key},
                    evidence=evidence,
                    domain=controller.domain,
                )["identity_valid"]

            assert await valid() is True
            records["_awid.example.test."] = dids[1]
            next_controller = ControllerDescriptor(
                "namespace", controller.domain, dids[1], "1", 1
            )
            rotation = parse_controller_request(
                {
                    "operation": "namespace_rotate",
                    "domain": controller.domain,
                    "from_seq": 1,
                    "previous_did_key": dids[0],
                    "new_did_key": dids[1],
                }
            )
            await sdk.controller_request(
                rotation,
                controllers={
                    "controller": controller,
                    "new_controller": next_controller,
                },
                signer=signer,
            )
            assert await valid() is True
            with pytest.raises(RegistryError) as refused:
                await sdk.controller_request(
                    rotation,
                    controllers={
                        "controller": controller,
                        "new_controller": next_controller,
                    },
                    signer=signer,
                )
            assert refused.value.status_code == 409
            assert (await sdk.get_namespace(controller.domain)).controller_did == dids[
                1
            ]
            child_reset = ControllerDescriptor(
                "namespace", child.domain, dids[4], "4", 1
            )
            await sdk.controller_request(
                parse_controller_request(
                    {
                        "operation": "namespace_reset",
                        "domain": child.domain,
                        "new_controller_did": child_reset.did_key,
                        "parent_domain": controller.domain,
                    }
                ),
                controllers={"controller": child_reset, "parent": next_controller},
                signer=signer,
            )
            assert (
                await sdk.get_namespace(child.domain)
            ).controller_did == child_reset.did_key
            records["_awid.example.test."] = dids[2]
            reset = ControllerDescriptor(
                "namespace", controller.domain, dids[2], "2", 2
            )
            await run("namespace_reset", reset, new_controller_did=dids[2])
            assert await valid() is False
        finally:
            listener.close()
            await sdk.aclose()
            if process and process.returncode is None:
                process.terminate()
                await asyncio.wait_for(process.wait(), 10)
            dns.asyncresolver.default_resolver = previous_resolver
            dns_transport.close()
