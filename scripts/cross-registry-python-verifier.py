"""Anonymous outsider, run in the foreign AWID container, with its real DNS."""

import asyncio
import json
import sys

from redis.asyncio import Redis
from awid.external_authority import OriginContext
from awid.id_certificates import verify_id_chain
from awid.registry import CachedRegistryClient


def outsider_client(redis):
    # Only this isolated journey opts in; DNS still selects each foreign route.
    return CachedRegistryClient(
        "https://api.awid.ai",
        redis,
        registry_origin_context=OriginContext(
            app_env="development",
            federation_test_enabled=True,
            listener_origin="http://awid-b:8010",
        ),
    )


async def main():
    redis = Redis.from_url("redis://redis-b:6379/9")
    client = outsider_client(redis)
    try:
        for case in json.load(sys.stdin):
            subject = {"id": case["ID"], "did_key": case["DIDKey"]}
            evidence = await client.id_chain_evidence(
                case["Bundle"], subject, domain=case["Domain"]
            )
            result = verify_id_chain(
                case["Bundle"],
                subject=subject,
                evidence=evidence,
                domain=case["Domain"],
            )
            if case.get("Reason") == "revoked":
                assert result == {
                    "outcome": "unknown",
                    "human_id": None,
                    "identity_valid": False,
                    "kind": None,
                    "reason": "revoked",
                }, result
                print(
                    f"PASS: Python outsider revoked {case['Kind']} {case['ID']}",
                    flush=True,
                )
                continue
            assert result["identity_valid"] is True, result
            assert result["outcome"] == case["Outcome"], result
            assert result["human_id"] == (case["HumanID"] or None), result
            assert result["kind"] == case["Kind"] and result["reason"] == "verified", (
                result
            )
            print(
                f"PASS: Python outsider {case['Kind']} {result['outcome']} {case['ID']}",
                flush=True,
            )
    finally:
        await client.aclose()
        await redis.aclose()


if __name__ == "__main__":
    asyncio.run(main())
