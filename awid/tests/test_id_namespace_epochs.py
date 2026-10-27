"""Namespace controller epochs (docs/id-certificates.md §3 "Key rotation").

Every controller change is retained as one history per domain. Only an epoch
proven by the exact _awid.<domain> TXT record is identity-tree evidence; an
inherited ancestor record, a parent-namespace authorization, the skip-DNS
bypass and the reserved local domain are recorded but never exact.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.dns_verify import DomainAuthority
from awid_service.deps import get_domain_verifier

from conftest import build_signed_headers as _sign

DOMAIN = "epochs.example"
MICROSECOND = timedelta(microseconds=1)


def _keypair():
    signing_key, public_key = generate_keypair()
    return signing_key, did_from_public_key(public_key)


def _dns(client, controller_did, *, inherited=False):
    async def _verify(domain: str) -> DomainAuthority:
        return DomainAuthority(
            controller_did=controller_did,
            registry_url="https://api.awid.ai",
            dns_name=f"_awid.{domain}",
            inherited=inherited,
        )

    client.app.dependency_overrides[get_domain_verifier] = lambda: _verify


async def _epochs(awid_db_infra, domain=DOMAIN):
    db = awid_db_infra.get_manager("aweb")
    return await db.fetch_all(
        """
        SELECT seq, did_key, established_by, registered_at, retired_at
        FROM {{tables.id_namespace_epochs}}
        WHERE domain = $1
        ORDER BY seq
        """,
        domain,
    )


async def _register(client, key, did, domain=DOMAIN, extra_headers=None):
    headers = _sign(key, did, domain=domain, operation="register")
    headers.update(extra_headers or {})
    resp = await client.post("/v1/namespaces", json={"domain": domain}, headers=headers)
    assert resp.status_code == 200, resp.text


async def _rotate(client, new_key, new_did, domain=DOMAIN, extra_headers=None):
    headers = _sign(
        new_key, new_did, domain=domain, operation="rotate_controller", new_controller_did=new_did,
    )
    headers.update(extra_headers or {})
    resp = await client.put(
        f"/v1/namespaces/{domain}", json={"new_controller_did": new_did}, headers=headers,
    )
    assert resp.status_code == 200, resp.text


async def _reverify(client, domain=DOMAIN):
    resp = await client.post(f"/v1/namespaces/{domain}/reverify")
    assert resp.status_code == 200, resp.text


def _parent_authorization(parent_key, parent_did, *, domain, operation, **claims):
    headers = _sign(parent_key, parent_did, domain=domain, operation=operation, **claims)
    return {
        "X-AWEB-Parent-Authorization": headers["Authorization"],
        "X-AWEB-Parent-Timestamp": headers["X-AWEB-Timestamp"],
    }


@pytest.mark.asyncio
async def test_exact_dns_registration_opens_the_first_exact_epoch(clocked_client, awid_db_infra, manual_clock):
    key, did = _keypair()
    _dns(clocked_client, did)
    await _register(clocked_client, key, did)

    [epoch] = await _epochs(awid_db_infra)
    assert (epoch["seq"], epoch["did_key"], epoch["established_by"]) == (1, did, "dns_exact")
    assert epoch["registered_at"] == manual_clock.now
    assert epoch["retired_at"] is None


@pytest.mark.asyncio
async def test_inherited_dns_registration_is_recorded_but_not_exact(clocked_client, awid_db_infra):
    key, did = _keypair()
    _dns(clocked_client, did, inherited=True)
    await _register(clocked_client, key, did)

    [epoch] = await _epochs(awid_db_infra)
    assert (epoch["did_key"], epoch["established_by"]) == (did, "dns_inherited")


@pytest.mark.asyncio
async def test_skip_dns_and_local_registrations_are_unverified(clocked_client, awid_db_infra, monkeypatch):
    key, did = _keypair()
    await _register(clocked_client, key, did, domain="local")
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await _register(clocked_client, key, did)

    assert [e["established_by"] for e in await _epochs(awid_db_infra, "local")] == ["unverified"]
    assert [e["established_by"] for e in await _epochs(awid_db_infra)] == ["unverified"]


@pytest.mark.asyncio
async def test_parent_authorized_subdomain_is_not_exact(clocked_client, awid_db_infra):
    parent_key, parent_did = _keypair()
    _dns(clocked_client, parent_did)
    await _register(clocked_client, parent_key, parent_did)

    child_domain = f"child.{DOMAIN}"
    child_key, child_did = _keypair()
    await _register(
        clocked_client, child_key, child_did, domain=child_domain,
        extra_headers=_parent_authorization(
            parent_key, parent_did, domain=child_domain,
            operation="authorize_subdomain_registration",
            child_domain=child_domain, controller_did=child_did,
        ),
    )

    [epoch] = await _epochs(awid_db_infra, child_domain)
    assert (epoch["did_key"], epoch["established_by"]) == (child_did, "parent_authorization")


@pytest.mark.asyncio
async def test_rotation_retires_the_old_epoch_and_keeps_it(clocked_client, awid_db_infra, manual_clock):
    old_key, old_did = _keypair()
    _dns(clocked_client, old_did)
    await _register(clocked_client, old_key, old_did)
    registered = manual_clock.now

    new_key, new_did = _keypair()
    manual_clock.now = registered + timedelta(minutes=10)
    _dns(clocked_client, new_did)
    await _rotate(clocked_client, new_key, new_did)

    first, second = await _epochs(awid_db_infra)
    assert (first["seq"], first["did_key"], first["registered_at"]) == (1, old_did, registered)
    assert first["retired_at"] == manual_clock.now
    assert (second["seq"], second["did_key"], second["established_by"]) == (2, new_did, "dns_exact")
    assert second["registered_at"] == manual_clock.now
    assert second["retired_at"] is None


@pytest.mark.asyncio
async def test_witness_times_stay_monotone_when_the_clock_goes_back(clocked_client, awid_db_infra, manual_clock):
    old_key, old_did = _keypair()
    _dns(clocked_client, old_did)
    await _register(clocked_client, old_key, old_did)
    registered = manual_clock.now

    new_key, new_did = _keypair()
    manual_clock.now = registered - timedelta(minutes=5)
    _dns(clocked_client, new_did)
    await _rotate(clocked_client, new_key, new_did)

    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] == registered + MICROSECOND
    assert second["registered_at"] == registered + MICROSECOND


@pytest.mark.asyncio
async def test_non_exact_rotation_closes_the_exact_epoch(clocked_client, awid_db_infra, monkeypatch):
    old_key, old_did = _keypair()
    _dns(clocked_client, old_did)
    await _register(clocked_client, old_key, old_did)

    new_key, new_did = _keypair()
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await _rotate(clocked_client, new_key, new_did)

    first, second = await _epochs(awid_db_infra)
    assert (first["established_by"], first["retired_at"] is not None) == ("dns_exact", True)
    assert (second["did_key"], second["established_by"], second["retired_at"]) == (new_did, "unverified", None)


@pytest.mark.asyncio
async def test_non_exact_reassertion_of_the_same_key_keeps_the_exact_epoch(
    clocked_client, awid_db_infra, monkeypatch,
):
    key, did = _keypair()
    _dns(clocked_client, did)
    await _register(clocked_client, key, did)

    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await _rotate(clocked_client, key, did)

    [epoch] = await _epochs(awid_db_infra)
    assert (epoch["established_by"], epoch["retired_at"]) == ("dns_exact", None)


@pytest.mark.asyncio
async def test_exact_reverify_witnesses_the_current_key_once(
    clocked_client, awid_db_infra, manual_clock, monkeypatch,
):
    key, did = _keypair()
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await _register(clocked_client, key, did)
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY")

    manual_clock.now += timedelta(minutes=1)
    _dns(clocked_client, did)
    await _reverify(clocked_client)
    manual_clock.now += timedelta(minutes=1)
    await _reverify(clocked_client)

    first, second = await _epochs(awid_db_infra)
    assert (first["established_by"], first["retired_at"] is not None) == ("unverified", True)
    assert (second["did_key"], second["established_by"], second["retired_at"]) == (did, "dns_exact", None)
    assert second["registered_at"] == manual_clock.now - timedelta(minutes=1)


@pytest.mark.asyncio
async def test_exact_reverify_to_a_new_key_opens_a_new_epoch(clocked_client, awid_db_infra):
    old_key, old_did = _keypair()
    _dns(clocked_client, old_did)
    await _register(clocked_client, old_key, old_did)

    _, new_did = _keypair()
    _dns(clocked_client, new_did)
    await _reverify(clocked_client)

    first, second = await _epochs(awid_db_infra)
    assert first["retired_at"] is not None
    assert (second["seq"], second["did_key"], second["established_by"]) == (2, new_did, "dns_exact")


@pytest.mark.asyncio
async def test_inherited_reverify_records_nothing(clocked_client, awid_db_infra, monkeypatch):
    key, did = _keypair()
    monkeypatch.setenv("AWID_SKIP_DNS_VERIFY", "1")
    await _register(clocked_client, key, did)
    monkeypatch.delenv("AWID_SKIP_DNS_VERIFY")

    _, ancestor_did = _keypair()
    _dns(clocked_client, ancestor_did, inherited=True)
    await _reverify(clocked_client)

    [epoch] = await _epochs(awid_db_infra)
    assert (epoch["did_key"], epoch["established_by"], epoch["retired_at"]) == (did, "unverified", None)


@pytest.mark.asyncio
async def test_deletion_retires_the_epoch_and_history_spans_reregistration(
    clocked_client, awid_db_infra, manual_clock,
):
    key, did = _keypair()
    _dns(clocked_client, did)
    await _register(clocked_client, key, did)

    manual_clock.now += timedelta(minutes=1)
    headers = _sign(key, did, domain=DOMAIN, operation="delete_namespace")
    resp = await clocked_client.request("DELETE", f"/v1/namespaces/{DOMAIN}", headers=headers)
    assert resp.status_code == 200, resp.text
    deleted_at = manual_clock.now

    manual_clock.now += timedelta(minutes=1)
    await _register(clocked_client, key, did)

    first, second = await _epochs(awid_db_infra)
    assert (first["seq"], first["retired_at"]) == (1, deleted_at)
    assert (second["seq"], second["did_key"], second["retired_at"]) == (2, did, None)
