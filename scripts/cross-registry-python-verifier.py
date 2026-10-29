"""Anonymous outsider, run in the foreign AWID container, with its real DNS."""
import asyncio
import json
import sys

from redis.asyncio import Redis
from awid.id_certificates import verify_id_chain
from awid.registry import CachedRegistryClient


async def main():
    redis = Redis.from_url("redis://redis-b:6379/9")
    client = CachedRegistryClient("https://api.awid.ai", redis)
    try:
        for case in json.load(sys.stdin):
            subject = {"id": case["ID"], "did_key": case["DIDKey"]}
            evidence = await client.id_chain_evidence(case["Bundle"], subject, domain=case["Domain"])
            result = verify_id_chain(case["Bundle"], subject=subject, evidence=evidence, domain=case["Domain"])
            assert result["identity_valid"] is True, result
            assert result["outcome"] == case["Outcome"], result
            assert result["human_id"] == (case["HumanID"] or None), result
            assert result["kind"] == case["Kind"] and result["reason"] == "verified", result
            print(f"PASS: Python outsider {case['Kind']} {result['outcome']} {case['ID']}", flush=True)
    finally:
        await client.aclose()
        await redis.aclose()


asyncio.run(main())
