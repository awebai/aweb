from __future__ import annotations

import asyncio
import hashlib
import json
import ssl
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import aweb
import pytest
import pytest_asyncio
from aweb.federation.authority import AuthorityClaim, FederationAuthorityCore
from aweb.federation.authority_state import (
    AddressAuthorityCandidate,
    AuthorityRepository,
    CheckpointCandidate,
)
from aweb.federation.authority_work import AuthorityWorkRepository
from aweb.federation.envelope import FederatedDeliveryRequest
from awid.external_authority import DNSLookup, OriginContext, compare_claim_to_evidence
from awid.external_registry import StrictExternalRegistry
from awid.federation_errors import FederationAuthorityError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pgdbm import AsyncMigrationManager

_ROOT = Path(__file__).resolve().parents[2]
_MANIFEST = _ROOT / "test-vectors" / "federation" / "preactivation-harness-v1.json"
_DIRECT_CORE_CASES = {
    *range(10, 17),
    *range(23, 40),
    *range(47, 50),
}
_ACTIVATION_FIXTURE_CASES = (
    set(range(1, 10)) | set(range(17, 23)) | set(range(40, 47)) | {50, 51}
)


def test_all_51_contract_rows_have_exact_preactivation_dispositions() -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    assert set(manifest) == {
        "schema",
        "contract",
        "topology",
        "canonical_inputs",
        "activation_inputs",
        "cases",
    }
    assert manifest["schema"] == "aweb.federation-preactivation-harness.v1"
    assert manifest["contract"] == "aweb-aazd.2.1"

    cases = manifest["cases"]
    assert [case["id"] for case in cases] == list(range(1, 52))
    assert len({case["name"] for case in cases}) == 51
    assert {case["id"] for case in cases if case["mode"] == "direct_core"} == (
        _DIRECT_CORE_CASES
    )
    assert {
        case["id"] for case in cases if case["mode"] == "activation_fixture"
    } == _ACTIVATION_FIXTURE_CASES
    for case in cases:
        expected_fields = {
            "id",
            "name",
            "mode",
            "owner",
            "evidence",
            "mutation_disposition",
        }
        if case["mode"] == "activation_fixture":
            expected_fields |= {"fixture_refs", "expected_contract", "deferred_task"}
        assert set(case) == expected_fields
        assert case["owner"] == (
            "aweb-aazd.4" if case["mode"] == "direct_core" else "aweb-aazd.6"
        )
        assert case["evidence"]
        assert case["mutation_disposition"] in {
            "executed_core_mutation",
            "activation_owned_fixture",
            "not_applicable_positive_control",
        }
        if case["mode"] == "activation_fixture":
            assert case["mutation_disposition"] != "executed_core_mutation"
            assert case["fixture_refs"]
            assert set(case["fixture_refs"]) <= set(manifest["activation_inputs"])
            assert case["evidence"] == [
                f"activation_inputs:{fixture}" for fixture in case["fixture_refs"]
            ]
            assert case["expected_contract"] == case["name"]
            assert case["deferred_task"] == "aweb-aazd.6"


def test_disposable_real_stack_script_has_guarded_non_activation_contract() -> None:
    source = (_ROOT / "scripts" / "e2e-federation-authority.sh").read_text()
    for service in (
        "awid-a",
        "awid-b",
        "aweb-a-1",
        "aweb-a-2",
        "aweb-b-1",
        "aweb-b-2",
        "postgres-a",
        "postgres-b",
    ):
        assert service in source
    assert "down -v --remove-orphans" in source
    assert 'com.docker.compose.project="$PROJECT"' in source
    assert "/v1/federation/messages" not in source
    assert "/v1/federation/chat" not in source
    assert "openssl req" in source
    assert "HARNESS_CA_FILE" in source
    assert "federation-authority-worker.py" in source
    assert '[[ "$ALPHA_DID_AW" != "$BETA_DID_AW" ]]' in source


def test_topology_and_canonical_input_artifacts_are_exact() -> None:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    topology = manifest["topology"]
    assert topology == {
        "awid_registries": ["awid-a", "awid-b"],
        "receiver_services": ["aweb-a", "aweb-b"],
        "receiver_processes": ["aweb-a-1", "aweb-a-2", "aweb-b-1", "aweb-b-2"],
        "postgresql_authority_stores": ["postgres-a", "postgres-b"],
        "runtime_generated_tls": True,
        "strict_ingress_calls": False,
    }

    expected_inputs = {
        "docs/vectors/federation-origin-ip-v1.json": (
            12746,
            "6d6ec789c4d994913ae84a26021a8e8fe0c7eb3aaf008ee10ce623db7a87cb18",
        ),
        "docs/vectors/federation-discovery-v1.json": (
            18774,
            "42fc649d28f097d22073d10e01c800ca653e177ec055a9cd2f40b047eb6a22da",
        ),
        "docs/vectors/federation-authority-state-v1.json": (
            24926,
            "dbfae045d87a947ba5e9add41b03832159eb584c1ab1d8644ec5a34f27f8d616",
        ),
        "docs/vectors/identity-log-v1.json": (
            4169,
            "bf49643f2986753ec91297b928f23ddeaa84a9138b65fa21fd9708b9d7df552e",
        ),
        "docs/vectors/message-signing-v1.json": (
            2558,
            "c19418cf505c22c4782b9840f89a2dabea02751515c4a59a014f520ba152bc92",
        ),
        "docs/vectors/e2ee-v2-cross-language.json": (
            11591,
            "6aacf482e22889f633d6bbf91b327d61837fe48ec54769924defbb4ccb2b6339",
        ),
    }
    inputs = manifest["canonical_inputs"]
    assert {item["path"] for item in inputs} == set(expected_inputs)
    for item in inputs:
        assert set(item) == {"path", "bytes", "sha256", "purpose", "embedded"}
        body = (_ROOT / item["path"]).read_bytes()
        assert (item["bytes"], item["sha256"]) == expected_inputs[item["path"]]
        assert len(body) == item["bytes"]
        assert hashlib.sha256(body).hexdigest() == item["sha256"]
        assert item["embedded"] is False
        assert item["purpose"]

    assert manifest["activation_inputs"] == {
        "plaintext": {
            "canonical_vector": "docs/vectors/message-signing-v1.json",
            "canonical_case": "mail_with_stable_ids_unicode",
            "schema_consumer": "aweb.federation.envelope.FederatedDeliveryRequest",
            "signed_address_source": "signed_payload.from",
            "wrapper_address_role": "transport_consistency_only",
            "sender_delivery_origin": "https://sender.fixture.test",
            "target_delivery_origin": "https://receiver.fixture.test",
        },
        "encrypted_v2": {
            "canonical_vector": "docs/vectors/e2ee-v2-cross-language.json",
            "canonical_case": "python_mail_envelope",
            "schema_consumer": "aweb.federation.envelope.FederatedDeliveryRequest",
            "signed_address_source": "encrypted_envelope.from.address",
            "plaintext_fallback": False,
            "sender_delivery_origin": "https://sender.fixture.test",
            "target_delivery_origin": "https://receiver.fixture.test",
        },
        "replay_globality": {
            "sole_key": "message_id",
            "kinds": ["mail", "chat"],
            "conflict_dimensions": [
                "envelope_hash",
                "kind",
                "sender",
                "target",
                "conversation_or_session",
                "signature",
                "signed_or_protected_bytes",
            ],
            "runtime_owner": "aweb-aazd.6",
        },
    }

    plaintext_meta = manifest["activation_inputs"]["plaintext"]
    plaintext_cases = json.loads(
        (_ROOT / plaintext_meta["canonical_vector"]).read_text(encoding="utf-8")
    )
    plaintext_case = next(
        case
        for case in plaintext_cases
        if case["name"] == plaintext_meta["canonical_case"]
    )
    plaintext_message = plaintext_case["message"]
    plaintext_request = FederatedDeliveryRequest.model_validate(
        {
            "envelope": {
                "version": 1,
                "type": plaintext_message["type"],
                "sender_did_aw": plaintext_message["from_stable_id"],
                "sender_current_did_key": plaintext_message["from_did"],
                "sender_address": plaintext_message["from"],
                "sender_delivery_origin": plaintext_meta["sender_delivery_origin"],
                "target_address": plaintext_message["to"],
                "target_did_aw": plaintext_message["to_stable_id"],
                "target_current_did_key": plaintext_message["to_did"],
                "target_delivery_origin": plaintext_meta["target_delivery_origin"],
                "body": plaintext_message["body"],
                "message_id": plaintext_message["message_id"],
                "timestamp": plaintext_message["timestamp"],
                "signed_payload": plaintext_case["canonical_payload"],
                "subject": plaintext_message["subject"],
            },
            "signature": plaintext_case["signature_b64"],
        }
    )
    assert (
        plaintext_request.envelope.signed_payload.encode()
        == plaintext_case["canonical_payload"].encode()
    )

    encrypted_meta = manifest["activation_inputs"]["encrypted_v2"]
    encrypted_corpus = json.loads(
        (_ROOT / encrypted_meta["canonical_vector"]).read_text(encoding="utf-8")
    )
    encrypted = encrypted_corpus[encrypted_meta["canonical_case"]]
    recipient = encrypted["recipients"][0]
    encrypted_request = FederatedDeliveryRequest.model_validate(
        {
            "envelope": {
                "version": 1,
                "type": encrypted["kind"],
                "sender_did_aw": encrypted["from"]["stable_id"],
                "sender_current_did_key": encrypted["from"]["did"],
                "sender_address": encrypted["from"]["address"],
                "sender_delivery_origin": encrypted_meta["sender_delivery_origin"],
                "target_address": recipient["address"],
                "target_did_aw": recipient["stable_id"],
                "target_current_did_key": recipient["did"],
                "target_delivery_origin": encrypted_meta["target_delivery_origin"],
                "body": "",
                "message_id": encrypted["message_id"],
                "timestamp": encrypted["created_at"],
                "conversation_id": encrypted["conversation_id"],
                "content_mode": "encrypted_v2",
                "message_version": encrypted["message_version"],
                "encrypted_envelope": encrypted,
            },
            "signature": encrypted["signature"],
        }
    )
    assert encrypted_request.envelope.encrypted_envelope == encrypted
    assert encrypted_request.envelope.signed_payload is None


async def _receiver_database(test_db_factory, suffix: str):
    db = await test_db_factory.create_db(suffix=suffix, schema="aweb")
    migrations = AsyncMigrationManager(
        db,
        migrations_path=str(Path(aweb.__file__).parent / "migrations" / "aweb"),
        module_name="aweb-aweb",
        migrations_table="schema_migrations",
    )
    await migrations.apply_pending_migrations()
    return db


@pytest_asyncio.fixture
async def two_receiver_databases(test_db_factory):
    return (
        await _receiver_database(test_db_factory, "federation_alpha"),
        await _receiver_database(test_db_factory, "federation_beta"),
    )


def _checkpoint(
    *,
    did_aw: str,
    seq: int = 1,
    revision: int | None = None,
    current_did_key: str = "did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
):
    return CheckpointCandidate(
        did_aw=did_aw,
        seq=seq,
        entry_hash=hashlib.sha256(f"{did_aw}:{seq}:entry".encode()).hexdigest(),
        state_hash=hashlib.sha256(f"{did_aw}:{seq}:state".encode()).hexdigest(),
        current_did_key=current_did_key,
        contains_snapshot=seq > 1,
        expected_revision=revision,
        expected_entry_hash=(
            hashlib.sha256(f"{did_aw}:{seq - 1}:entry".encode()).hexdigest()
            if revision is not None
            else None
        ),
    )


def _cohort(
    checkpoint: CheckpointCandidate,
    *,
    address: str,
    origin: str,
    checkpoint_revision: int,
    fence: int = 1,
):
    return AddressAuthorityCandidate(
        canonical_address=address,
        authority_selection="dns",
        authority_name="_awid." + address.split("/", 1)[0],
        controller_did="did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
        authority_statement_version="aweb.federation-authority.dns.v1",
        authority_statement_digest="sha256:" + "a" * 64,
        inherited=False,
        registry_explicit=True,
        registry_origin="https://registry.test",
        address_id="address-fixture",
        bound_did_aw=checkpoint.did_aw,
        bound_current_did_key=checkpoint.current_did_key,
        checkpoint_seq=checkpoint.seq,
        checkpoint_entry_hash=checkpoint.entry_hash,
        checkpoint_revision=checkpoint_revision,
        authoritative_delivery_origin=origin,
        publishing_fence=fence,
        reuse_seconds=60,
    )


@pytest.mark.asyncio
async def test_two_workers_share_checkpoint_and_invalidation(
    two_receiver_databases,
) -> None:
    alpha_db, beta_db = two_receiver_databases
    alpha_workers = [AuthorityRepository(alpha_db), AuthorityRepository(alpha_db)]
    beta_workers = [AuthorityRepository(beta_db), AuthorityRepository(beta_db)]
    did_aw = "did:aw:2CiZ88hVF4JuQim8nnSuyeiV2HF2"
    first = _checkpoint(did_aw=did_aw)
    alpha_address = "alpha.test/Alice"
    alpha_origin = "https://aweb-alpha.test"

    first_token = await alpha_workers[0].commit_phase_a(
        first,
        _cohort(
            first,
            address=alpha_address,
            origin=alpha_origin,
            checkpoint_revision=1,
        ),
    )
    assert (
        await alpha_workers[1].authorize_from_cohort(
            canonical_address=alpha_address,
            did_aw=did_aw,
            current_did_key=first.current_did_key,
            delivery_origin=alpha_origin,
        )
        == first_token
    )

    second = _checkpoint(
        did_aw=did_aw,
        seq=2,
        revision=1,
        current_did_key="did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
    )
    await alpha_workers[1].commit_phase_a(
        second,
        _cohort(
            second,
            address=alpha_address,
            origin=alpha_origin,
            checkpoint_revision=2,
            fence=2,
        ),
    )
    assert (
        await alpha_workers[0].authorize_from_cohort(
            canonical_address=alpha_address,
            did_aw=did_aw,
            current_did_key=first.current_did_key,
            delivery_origin=alpha_origin,
        )
        is None
    )
    assert await beta_workers[0].get_checkpoint(did_aw) is None
    assert (
        await beta_workers[1].authorize_from_cohort(
            canonical_address=alpha_address,
            did_aw=did_aw,
            current_did_key=second.current_did_key,
            delivery_origin=alpha_origin,
        )
        is None
    )


@pytest.mark.asyncio
async def test_two_workers_singleflight_one_real_chain_and_non_poisoning(
    two_receiver_databases,
) -> None:
    alpha_db, _ = two_receiver_databases
    repositories = [
        AuthorityWorkRepository(alpha_db),
        AuthorityWorkRepository(alpha_db),
    ]
    domain, name = "alpha.test", "Alice"
    delivery = "https://aweb-alpha.test"
    mapping, responses = _identity_registry_responses(domain, name, delivery)
    async with _TLSRegistry("registry-a.test", responses) as registry:
        dns = _RecordedDNS(domain, mapping["initial_did_key"], registry.origin)
        hosts = _LoopbackHosts()
        resolver = StrictExternalRegistry(
            txt_resolver=dns,
            host_resolver=hosts,
            origin_context=OriginContext(
                app_env="development",
                federation_test_enabled=True,
                listener_origin="http://receiver.test",
            ),
            ssl_context=registry.client_context,
        )
        scope = "evidence:one-real-chain"
        barrier = asyncio.Barrier(2)
        claims = (
            ("wrong", "did:aw:wrong"),
            ("correct", mapping["did_aw"]),
        )

        async def run_worker(index: int, label: str, did_aw: str):
            await barrier.wait()
            lease = await repositories[index].acquire_lease(
                scope, owner_id=uuid4(), ttl_seconds=5
            )
            if lease.acquired:
                evidence = await resolver.fetch_evidence(
                    f"{domain}/{name}", authority_generation=7
                )
                await repositories[index].publish_result(
                    lease,
                    status="verified_evidence",
                    evidence=evidence.claim_evidence(),
                    ttl_seconds=5,
                )
            shared = await repositories[index].wait_for_result(
                scope, deadline_seconds=2
            )
            assert shared is not None
            try:
                compared = compare_claim_to_evidence(
                    shared.evidence,
                    did_aw=did_aw,
                    current_did_key=mapping["rotated_did_key"],
                    delivery_origin=delivery,
                )
            except FederationAuthorityError as exc:
                return label, lease.acquired, exc.reason
            return label, lease.acquired, compared

        try:
            results = await asyncio.gather(
                *(run_worker(index, *claim) for index, claim in enumerate(claims))
            )
        finally:
            await resolver.aclose()

    by_label = {label: (leader, result) for label, leader, result in results}
    assert sum(leader for leader, _result in by_label.values()) == 1
    assert by_label["wrong"][1] == "sender_address_did_mismatch"
    assert by_label["correct"][1]["did_aw"] == mapping["did_aw"]
    assert dns.queries == ["_awid." + domain]
    assert len(registry.requests) == 4
    assert (
        await alpha_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_authority_results}} WHERE scope_key = $1",
            scope,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_two_workers_race_exact_shared_limits_and_token_bucket(
    two_receiver_databases,
) -> None:
    alpha_db, _ = two_receiver_databases
    workers = [AuthorityWorkRepository(alpha_db), AuthorityWorkRepository(alpha_db)]

    async def race_at_limit(kind: str, key: str, limit: int) -> None:
        for index in range(limit - 1):
            await workers[index % 2].acquire_permits(
                owner_id=uuid4(), scopes=((kind, key, limit),), ttl_seconds=60
            )
        barrier = asyncio.Barrier(2)

        async def contender(index: int):
            await barrier.wait()
            try:
                await workers[index].acquire_permits(
                    owner_id=uuid4(), scopes=((kind, key, limit),), ttl_seconds=60
                )
            except FederationAuthorityError as exc:
                return exc.reason
            return "admitted"

        results = await asyncio.gather(contender(0), contender(1))
        assert sorted(results) == ["admitted", "federation_resolver_busy"]
        assert (
            await alpha_db.fetch_value(
                "SELECT COUNT(*) FROM {{tables.federation_authority_permits}} "
                "WHERE scope_kind = $1 AND scope_key = $2 "
                "AND expires_at > clock_timestamp()",
                kind,
                key,
            )
            == limit
        )

    await race_at_limit("global", "receiver-exact-32", 32)
    await race_at_limit("domain", "alpha-exact-2.test", 2)
    await race_at_limit("origin", "https://registry-exact-4.test", 4)

    with pytest.raises(FederationAuthorityError) as atomic:
        await workers[1].acquire_permits(
            owner_id=uuid4(),
            scopes=(
                ("global", "receiver-exact-32", 32),
                ("domain", "atomic-unused.test", 2),
                ("origin", "https://atomic-unused.test", 4),
            ),
            ttl_seconds=60,
        )
    assert atomic.value.reason == "federation_resolver_busy"
    assert (
        await alpha_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_authority_permits}} "
            "WHERE scope_key IN ($1, $2)",
            "atomic-unused.test",
            "https://atomic-unused.test",
        )
        == 0
    )

    for index in range(5):
        await workers[index % 2].consume_token(
            bucket_kind="domain",
            bucket_key="alpha.test",
            burst=5,
            refill_per_minute=1,
        )
    with pytest.raises(FederationAuthorityError) as limited:
        await workers[1].consume_token(
            bucket_kind="domain",
            bucket_key="alpha.test",
            burst=5,
            refill_per_minute=1,
        )
    assert limited.value.reason == "federation_rate_limited"


@pytest.mark.asyncio
async def test_real_postgresql_lock_timeout_fails_closed_without_publication(
    two_receiver_databases,
) -> None:
    alpha_db, _ = two_receiver_databases
    scope = "lock-timeout:blocked"
    blocked = AuthorityWorkRepository(alpha_db)
    claim = AuthorityClaim(
        canonical_address="lock-timeout.test/Alice",
        did_aw="did:aw:2CiZ88hVF4JuQim8nnSuyeiV2Lock",
        current_did_key="did:key:z6Mkgxj2R3HLtQRpPnvfvpuKEceSqf3tZHBjdmZ3fFz3JHGG",
        delivery_origin="https://lock-timeout.test",
    )
    async with alpha_db.transaction() as blocker:
        await blocker.fetch_value(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            "federation-authority:lease:" + scope,
        )
        with pytest.raises(FederationAuthorityError) as timeout:
            await blocked.acquire_lease(scope, owner_id=uuid4(), ttl_seconds=5)
    assert timeout.value.reason == "federation_authority_coordination_unavailable"
    assert timeout.value.http_status == 503
    assert timeout.value.retryable is True
    assert (
        await FederationAuthorityCore(
            AuthorityRepository(alpha_db)
        ).authorize_from_shared_cohort(claim)
        is None
    )
    assert (
        await alpha_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_authority_leases}} WHERE scope_key = $1",
            scope,
        )
        == 0
    )
    assert (
        await alpha_db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.federation_authority_results}} WHERE scope_key = $1",
            scope,
        )
        == 0
    )


class _RecordedDNS:
    def __init__(self, domain: str, controller_did: str, registry_origin: str):
        self.domain = domain
        self.controller_did = controller_did
        self.registry_origin = registry_origin
        self.queries: list[str] = []

    async def lookup_txt(self, name: str) -> DNSLookup:
        self.queries.append(name)
        assert name == "_awid." + self.domain
        record = (
            f"awid=v1; controller={self.controller_did}; "
            f"registry={self.registry_origin};"
        )
        return DNSLookup("record", (record,))


class _LoopbackHosts:
    def __init__(self):
        self.queries: list[str] = []

    async def resolve_all(self, hostname: str) -> tuple[str, ...]:
        self.queries.append(hostname)
        return ("127.0.0.1",)


class _TLSRegistry:
    def __init__(self, hostname: str, responses: dict[str, object]):
        self.hostname = hostname
        self.responses = responses
        self.requests: list[bytes] = []
        self.sni: list[str | None] = []
        self.server = None
        self.client_context = None
        self.origin = ""

    async def __aenter__(self):
        self._temporary_directory = tempfile.TemporaryDirectory()
        directory = Path(self._temporary_directory.name)
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aweb test CA")])
        now = datetime.now(UTC)
        ca_certificate = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, self.hostname)]
        )
        server_certificate = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.hostname)]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        ca_path = directory / "ca.pem"
        cert_path = directory / "server.pem"
        key_path = directory / "server.key"
        ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
        cert_path.write_bytes(
            server_certificate.public_bytes(serialization.Encoding.PEM)
        )
        key_path.write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        server_context.set_servername_callback(
            lambda _socket, name, _context: self.sni.append(name)
        )
        self.client_context = ssl.create_default_context(cafile=str(ca_path))
        self.server = await asyncio.start_server(
            self._handle,
            "127.0.0.1",
            0,
            ssl=server_context,
        )
        port = self.server.sockets[0].getsockname()[1]
        self.origin = f"https://{self.hostname}:{port}"
        return self

    async def __aexit__(self, *_exc):
        self.server.close()
        await self.server.wait_closed()
        self._temporary_directory.cleanup()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        request = await reader.readuntil(b"\r\n\r\n")
        self.requests.append(request)
        path = request.split(b" ", 2)[1].decode()
        value = self.responses[path]
        body = json.dumps(value, separators=(",", ":")).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()


def _identity_registry_responses(domain: str, name: str, delivery_origin: str):
    vector = json.loads(
        (_ROOT / "docs" / "vectors" / "identity-log-v1.json").read_text()
    )
    mapping = vector["mapping"]
    entries = [
        {
            **item["entry_payload"],
            "entry_hash": item["entry_hash"],
            "signature": item["signature_b64"],
        }
        for item in vector["entries"]
    ]
    escaped_did = mapping["did_aw"].replace(":", "%3A")
    return mapping, {
        f"/v1/namespaces/{domain}": {
            "domain": domain,
            "controller_did": mapping["initial_did_key"],
        },
        f"/v1/namespaces/{domain}/addresses/{name}": {
            "address_id": f"address-{domain}-{name}",
            "domain": domain,
            "name": name,
            "did_aw": mapping["did_aw"],
            "current_did_key": mapping["rotated_did_key"],
            "delivery": {"origin": delivery_origin},
        },
        f"/v1/did/{escaped_did}/key": {
            "did_aw": mapping["did_aw"],
            "current_did_key": mapping["rotated_did_key"],
            "log_head": entries[-1],
            "status": "OK_DEGRADED",
        },
        f"/v1/did/{escaped_did}/log": entries,
    }


@pytest.mark.asyncio
async def test_two_registries_record_exact_dns_http_tls_and_share_side_cohorts(
    two_receiver_databases,
) -> None:
    alpha_db, beta_db = two_receiver_databases
    sides = (
        (
            "alpha.test",
            "Alice",
            "https://aweb-alpha.test",
            "registry-a.test",
            alpha_db,
        ),
        (
            "beta.test",
            "Bob",
            "https://aweb-beta.test",
            "registry-b.test",
            beta_db,
        ),
    )
    for generation, (domain, name, delivery, hostname, db) in enumerate(sides, 1):
        mapping, responses = _identity_registry_responses(domain, name, delivery)
        async with _TLSRegistry(hostname, responses) as registry:
            dns = _RecordedDNS(domain, mapping["initial_did_key"], registry.origin)
            hosts = _LoopbackHosts()
            resolver = StrictExternalRegistry(
                txt_resolver=dns,
                host_resolver=hosts,
                origin_context=OriginContext(
                    app_env="development",
                    federation_test_enabled=True,
                    listener_origin="http://receiver.test",
                ),
                ssl_context=registry.client_context,
            )
            workers = [
                FederationAuthorityCore(AuthorityRepository(db)),
                FederationAuthorityCore(AuthorityRepository(db)),
            ]
            claim = AuthorityClaim(
                canonical_address=f"{domain}/{name}",
                did_aw=mapping["did_aw"],
                current_did_key=mapping["rotated_did_key"],
                delivery_origin=delivery,
            )
            try:
                token = await workers[0].resolve_and_commit(
                    claim,
                    resolver,
                    authority_generation=generation,
                    publishing_fence=generation,
                )
                assert await workers[1].authorize_from_shared_cohort(claim) == token
            finally:
                await resolver.aclose()

            escaped_did = mapping["did_aw"].replace(":", "%3A")
            expected_paths = [
                f"/v1/namespaces/{domain}",
                f"/v1/namespaces/{domain}/addresses/{name}",
                f"/v1/did/{escaped_did}/key",
                f"/v1/did/{escaped_did}/log",
            ]
            observed_paths = [
                request.split(b" ", 2)[1].decode() for request in registry.requests
            ]
            assert dns.queries == ["_awid." + domain]
            assert hosts.queries == [hostname]
            assert observed_paths == expected_paths
            assert registry.sni == [hostname] * len(expected_paths)
            for request in registry.requests:
                assert (
                    f"Host: {hostname}:{registry.origin.rsplit(':', 1)[1]}".encode()
                    in request
                )
                assert b"Accept-Encoding: identity" in request
                assert b"Authorization:" not in request
                assert b"Cookie:" not in request
