"""Register one disposable child through the public parent-signed SDK path.

Runs inside awid-a at the CoreDNS journey barrier. Both keys are created by
aw's prepare-controller command in the disposable fixture HOME and copied
here by the harness; no credentials come from the host's real keychain.
"""
import asyncio
import base64
from pathlib import Path

import httpx

from awid.dns_verify import verify_domain
from awid.registry import RegistryClient, _did_key_from_signing_key

DOMAIN = "delegated.alpha.example.com"
PARENT = "alpha.example.com"


def controller_seed(path):
    lines = Path(path).read_text().strip().splitlines()
    assert lines[0] == "-----BEGIN ED25519 PRIVATE KEY-----"
    assert lines[-1] == "-----END ED25519 PRIVATE KEY-----"
    seed = base64.b64decode("".join(lines[1:-1]), validate=True)
    assert len(seed) == 32
    return seed


async def main():
    authority = await verify_domain(DOMAIN)
    assert authority.inherited and authority.dns_name == "_awid." + PARENT
    parent_seed = controller_seed("/tmp/journey-parent-controller.key")
    child_seed = controller_seed("/tmp/journey-child-controller.key")
    parent_key = _did_key_from_signing_key(parent_seed)
    child_key = _did_key_from_signing_key(child_seed)
    assert authority.controller_did == parent_key and child_key != parent_key
    # A discovered ancestor alone cannot establish an unregistered child.
    async with httpx.AsyncClient() as http:
        response = await http.post("http://awid-a:8010/v1/id-certificates/status",
                                   json={"v": 1, "domain": DOMAIN, "ids": []})
        assert response.status_code == 503, response.text
        assert response.json()["detail"]["code"] == "evidence_unavailable"
    client = RegistryClient("http://awid-a:8010")
    try:
        await client.register_namespace(DOMAIN, child_key, child_seed, parent_signing_key=parent_seed)
    finally:
        await client.aclose()
    async with httpx.AsyncClient() as http:
        response = await http.post("http://awid-a:8010/v1/id-certificates/status",
                                   json={"v": 1, "domain": DOMAIN, "ids": []})
        assert response.status_code == 200, response.text
        namespace = response.json()["namespace"]
        assert namespace["delegation"] == {"parent_domain": PARENT,
            "parent_controller_key": parent_key, "controller_key": child_key}
        assert namespace["epochs"][-1]["did_key"] == child_key
    print("PASS: ancestor TXT refuses a missing child, then parent-signed registration establishes its distinct controller", flush=True)


asyncio.run(main())
