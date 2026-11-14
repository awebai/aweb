"""aweb-adbb D2f: every retained request stays reachable from the served owner
page. Past one page, each list links to its older page through the real
route, behind the same sign-in; an older not-mailed request and an older
approved-but-unconfirmed recovery link are reached only that way."""

import html as htmllib
import re
from datetime import UTC, datetime, timedelta

import pytest

from aweb.protected_signing.owner import HISTORY_LIMIT
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_owner_initiation_native import owner_http
from tests.test_protected_owner_removal_native import legacy_member

pytest_plugins = ("tests.test_independent_protected_signer",)

COPIES = HISTORY_LIMIT + 2


async def copies(a, template, state, count):
    """``count`` rows in one state, copied from a real prepared operation of
    this scope, each with its own ids and an expiry one minute older than the
    last. Returns their handoff ids, newest first."""
    signed = "jsonb_build_object('signing','c2lnbmluZw==','signature','c2ln')" if state == "unresolved" else "NULL"
    rows = await a.w.db.fetch_all(
        "INSERT INTO {{tables.protected_signer_operations}} "
        "(operation_id,handoff_id,requester,intent,request,digest,approval_id,candidate_links,expires_at,scope,"
        "signed_result) "
        "SELECT gen_random_uuid()::text,gen_random_uuid()::text,requester,intent,request,digest,"
        f"gen_random_uuid()::text,'{{}}'::jsonb,$2::timestamptz - make_interval(mins => g),scope,{signed} "
        "FROM {{tables.protected_signer_operations}}, generate_series(1, $3) g WHERE operation_id=$1 "
        "RETURNING handoff_id,operation_id,expires_at", template, datetime.now(UTC) + timedelta(hours=1), count)
    return [r["handoff_id"] for r in sorted(rows, key=lambda r: r["expires_at"], reverse=True)], rows


def older_link(page, listing):
    match = re.search(rf'data-older="{listing}" href="([^"]+)"', page)
    return htmllib.unescape(match.group(1)) if match else None


@pytest.mark.asyncio
async def test_every_waiting_and_unconfirmed_request_is_reachable_from_the_served_page(admissions, tmp_path):
    from tests.test_protected_owner_initiation_native import selection

    a = admissions
    _, certificate = await legacy_member(a, "unknown")
    async with owner_http(a, tmp_path) as (client, headers, _):
        body = selection(certificate)
        assert (await client.post("/governance/operations", json=body, headers=headers)).status_code == 200
        template = body["operation_id"]
        pending, pending_rows = await copies(a, template, "pending", COPIES)
        unresolved, _ = await copies(a, template, "unresolved", COPIES)
        oldest_pending = min(pending_rows, key=lambda r: r["expires_at"])
        await a.w.db.execute(
            "INSERT INTO {{tables.protected_signer_notice_reservations}} "
            "(operation_id,service_id,authority_id,requester,notices,suppressed,reserved_at) "
            "SELECT operation_id,'s','a',requester,0,true,now() FROM {{tables.protected_signer_operations}} "
            "WHERE operation_id=$1", oldest_pending["operation_id"])

        first = (await client.get("/")).text
        assert f'/handoff/{pending[-1]}"' not in first and f'/handoff/{unresolved[-1]}"' not in first
        for listing, handoffs in (("pending", pending), ("unresolved", unresolved)):
            seen, page = set(), first
            while True:
                seen |= {h for h in handoffs if f'/handoff/{h}"' in page}
                link = older_link(page, listing)
                if link is None:
                    break
                response = await client.get(link)
                assert response.status_code == 200, response.text
                page = response.text
            assert seen == set(handoffs), (listing, len(seen))
            if listing == "pending":
                # The oldest, not-mailed request is reached, marked as such.
                assert f'/handoff/{oldest_pending["handoff_id"]}"' in page and 'data-notice="not-mailed"' in page


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["list=everything&after=x", "list=pending&after=not-a-cursor",
                                   "list=history&after=2026-01-01T00:00:00+00:00|not-an-id"])
async def test_a_malformed_older_page_is_refused(admissions, tmp_path, query):
    async with owner_http(admissions, tmp_path) as (client, _, _):
        assert (await client.get("/older?" + query)).status_code == 400


@pytest.mark.asyncio
async def test_an_older_page_needs_the_signed_in_owner(admissions, tmp_path):
    async with owner_http(admissions, tmp_path) as (client, _, _):
        client.cookies.clear()
        cursor = datetime.now(UTC).isoformat() + "|00000000-0000-4000-8000-000000000000"
        response = await client.get("/older", params={"list": "pending", "after": cursor})
        assert response.status_code in (302, 303, 307), response.status_code
