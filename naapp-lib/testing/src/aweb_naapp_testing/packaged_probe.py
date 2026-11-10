"""Runs inside a naapp's packaged image against the lab's real DNS, TLS and AWID.

The lab (:mod:`aweb_naapp_testing.package_lab`) copies this file next to the
service's own probe, which calls :func:`run`. It imports only what every naapp
image carries, never the rest of ``aweb_naapp_testing``.
"""

import asyncio
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import asyncpg
import httpx
from fastapi import HTTPException
from packaged_identity import PackagedIdentityError, require_commit

from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.team_server import TeamServerUnavailable


async def probe(
    configured: Any,
    *,
    runtime: Callable[[Any], NaappRuntime],
    host: str,
    port: int,
    health: tuple[str, ...],
    served: str,
) -> None:
    """``configured`` is the service's settings as the image reads them;
    ``runtime`` builds the service's runtime from settings. ``health`` names the
    checks that must pass, and ``served`` is the line printed once they do."""
    public = json.loads(Path("/lab/authority.json").read_text())
    async with httpx.AsyncClient() as client:
        health_response = await client.get(
            f"http://127.0.0.1:{port}/health", headers={"Host": host}
        )
        health_response.raise_for_status()
        image_identity = json.loads(Path("/lab/image-identity.json").read_text())
        require_commit(image_identity["commit"], image_identity["revision"])
        require_commit(image_identity["commit"], health_response.json()["build"]["git_sha"])
        print("packaged served build identity PASS", flush=True)
        checks = health_response.json()["checks"]
        assert all(checks[name]["ok"] for name in health)
        ready = await client.get(f"http://127.0.0.1:{port}/ready", headers={"Host": host})
        assert ready.status_code == 200
        assert (
            await client.get(f"http://127.0.0.1:{port}/manifests/v2.json", headers={"Host": host})
        ).json()["app"]["id"] == configured.app_id
        print(served, flush=True)

        # Only external authority fixture rows are seeded. The public signed
        # server publication and every discovery/status read use real routes.
        db = await asyncpg.connect(configured.database_url)
        try:
            await db.execute(
                "INSERT INTO awid.teams(domain,name,team_did_key,visibility) VALUES($1,$2,$3,$4)",
                "customer.lab.test",
                "lab",
                public["team_did_key"],
                "public",
            )
            await db.execute(
                "INSERT INTO awid.team_certificates(team_uuid,certificate_id,member_did_key,alias,issued_at) SELECT team_uuid,$1,$2,$3,now() FROM awid.teams WHERE domain=$4 AND name=$5",
                public["certificate_id"],
                public["member_did_key"],
                "lab-member",
                "customer.lab.test",
                "lab",
            )
            published = await client.put(
                configured.awid_registry_url + "/v1/namespaces/customer.lab.test/teams/lab/server",
                json=public["publication"],
            )
            published.raise_for_status()

            mismatch = runtime(
                configured.model_copy(
                    update={"awid_registry_url": "https://other-registry.lab.test:8010"}
                )
            )
            try:
                await mismatch.team_server_directory().resolve(
                    public["team_id"], public["certificate_id"]
                )
            except TeamServerUnavailable as exc:
                assert exc.code == "registry_mismatch"
            else:
                raise AssertionError("mismatched configured registry accepted")
            service = runtime(configured)
            directory, cache = service.team_server_directory(), service.team_cache()
            resolved = await directory.resolve(public["team_id"], public["certificate_id"])
            assert resolved.server_url == "https://coordinator.lab.test"
            assert resolved.team_did_key == public["team_did_key"]
            first_discovery = time.monotonic()
            await cache.check_current_member(
                public["team_id"],
                certificate_id=public["certificate_id"],
                team_did_key=public["team_did_key"],
            )
            print(
                "real TXT-selected customer registry + signed discovery + mismatch refusal PASS",
                flush=True,
            )
            await db.execute(
                "UPDATE awid.team_certificates SET revoked_at=now() WHERE certificate_id=$1",
                public["certificate_id"],
            )
            await asyncio.sleep(1.1)
            try:
                await cache.check_current_member(
                    public["team_id"],
                    certificate_id=public["certificate_id"],
                    team_did_key=public["team_did_key"],
                )
            except HTTPException as exc:
                assert exc.status_code == 403
            else:
                raise AssertionError("revoked certificate accepted")
            print("real registry revocation after configured cache expiry PASS", flush=True)
            await db.execute(
                "UPDATE awid.team_certificates SET revoked_at=NULL WHERE certificate_id=$1",
                public["certificate_id"],
            )
            await asyncio.sleep(1.1)
            await cache.check_current_member(
                public["team_id"],
                certificate_id=public["certificate_id"],
                team_did_key=public["team_did_key"],
            )
            Path("/lab/outage-requested").touch()
            async with asyncio.timeout(30):
                while not Path("/lab/outage-ready").exists():
                    await asyncio.sleep(0.1)
            await asyncio.sleep(max(0, 61 - (time.monotonic() - first_discovery)))
            try:
                await directory.resolve(public["team_id"], public["certificate_id"])
            except TeamServerUnavailable as exc:
                assert exc.code == "authority_unavailable"
            else:
                raise AssertionError("expired discovery reused after authority outage")
            try:
                await cache.check_current_member(
                    public["team_id"],
                    certificate_id=public["certificate_id"],
                    team_did_key=public["team_did_key"],
                )
            except HTTPException as exc:
                assert exc.status_code == 503
            else:
                raise AssertionError("expired membership reused after authority outage")
            print("real directory TTL expiry + stopped registry: fail closed PASS", flush=True)
        finally:
            await db.close()


def run(configured: Callable[[], Any], **options: Any) -> None:
    """Run the probe as the image's process. ``configured`` reads the service's
    settings; ``options`` are :func:`probe`'s."""
    try:
        asyncio.run(probe(configured(), **options))
    except PackagedIdentityError as exc:
        print(str(exc), flush=True)
        raise SystemExit(1) from None
    except Exception as exc:
        # No credential-bearing environment, response bodies or tracebacks.
        print("packaging probe failed: " + type(exc).__name__, flush=True)
        raise SystemExit(1) from None
