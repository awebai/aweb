"""Incremental pin-enrichment cost, using actual AWID/PG/DNS and its limiter.

The controlled minute clock advances both the real fixed-window limiter and
pin memo. Every active, admitted team is read once per second for three minutes.
This measures pin enrichment only, excluding normal metadata/status acquisition.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import httpx
import pytest

import awid.ratelimit as rate_module
import awid.team_key_acts as candidate
from awid.registry import RegistryClient
import test_team_key_baseline as baseline

ObservedRegistry = baseline.ObservedRegistry
world = baseline.world

MAIN = "56d513923dc86a7dc4019502332a4e5e1365647a"


def main_module(tmp_path):
    root = Path(__file__).resolve().parents[2]
    source = subprocess.check_output(
        ["git", "show", MAIN + ":awid/src/awid/team_key_acts.py"], cwd=root
    )
    path = tmp_path / "main_team_key_acts.py"
    path.write_bytes(source)
    name = "_baseline_" + tmp_path.name.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, hashlib.sha256(source).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("teams", [1, 100, 400])
@pytest.mark.parametrize("variant", ["main", "head"])
async def test_admitted_no_act_cost_per_minute(
    world, tmp_path, monkeypatch, teams, variant
):
    module, digest = main_module(tmp_path) if variant == "main" else (candidate, None)
    await world.db.execute("DELETE FROM {{tables.team_key_acts}}")
    if teams > 1:
        await world.db.execute(
            "INSERT INTO {{tables.teams}} (domain,name,team_did_key,visibility) SELECT $1,'load-'||n,$2,'public' FROM generate_series(1,$3::int) n",
            world.domain,
            world.team[1],
            teams - 1,
        )
    names = ["base"] + [f"load-{n}" for n in range(1, teams)]
    pins = module.MemoryTeamKeyPins()
    for name in names:
        await pins.first_sight(name + ":" + world.domain, world.team[1])
    clock = [float(int(time.time() // 60 + 1) * 60)]
    monkeypatch.setattr(rate_module, "time", SimpleNamespace(time=lambda: clock[0]))
    world.app.state.rate_limiter = rate_module.MemoryFixedWindowRateLimiter()
    memo = module.TeamKeyMemo(clock=lambda: clock[0])
    parameters = inspect.signature(module.pinned_team_key).parameters
    transport = ObservedRegistry(world.app)
    sdk = RegistryClient(world.sdk.registry_url, transport=transport)
    rows = []
    try:
        # Verify the actual UDP counter before measuring a zero-DNS path.
        await world.resolver.lookup_txt("_awid." + world.domain)
        assert world.dns.queries > 0
        start = clock[0]
        for minute in range(3):
            transport.calls.clear()
            world.dns.queries = 0
            for second in range(60):
                clock[0] = start + minute * 60 + second
                for name in names:
                    kwargs = dict(
                        pins=pins,
                        fetch_act=lambda name=name: sdk.get_team_key_act(
                            world.domain, name
                        ),
                        resolver=world.resolver,
                        enforce=False,
                    )
                    if "memo" in parameters:
                        kwargs["memo"] = memo
                    if "fetch_namespace_evidence" in parameters:
                        kwargs["fetch_namespace_evidence"] = sdk.namespace_evidence
                    assert (
                        await module.pinned_team_key(
                            name + ":" + world.domain, world.team[1], **kwargs
                        )
                        == world.team[1]
                    )
            rows.append(
                {
                    "minute": minute + 1,
                    "registry_requests": len(transport.calls),
                    "dns_queries": world.dns.queries,
                    "http_statuses": dict(
                        Counter(status for _, status in transport.calls)
                    ),
                }
            )
        print(
            "ADFL_BASELINE_MEASUREMENTS="
            + json.dumps(
                {
                    "variant": variant,
                    "baseline": MAIN if variant == "main" else None,
                    "baseline_module_sha256": digest,
                    "teams": teams,
                    "requests_per_team_per_minute": 60,
                    "bucket": "team_get",
                    "bucket_limit": "60/minute/IP",
                    "minutes": rows,
                },
                sort_keys=True,
            )
        )
        assert all(row["registry_requests"] == row["dns_queries"] == 0 for row in rows)

        # Positive control: the unexempted production limiter really admits 60
        # key-act reads then refuses the 61st in this minute, not a no-op limiter.
        world.app.state.rate_limiter = rate_module.MemoryFixedWindowRateLimiter()
        async with httpx.AsyncClient(
            transport=transport, base_url=world.sdk.registry_url
        ) as client:
            statuses = [
                (
                    await client.get(
                        f"/v1/namespaces/{world.domain}/teams/base/key-act"
                    )
                ).status_code
                for _ in range(61)
            ]
        assert statuses == [404] * 60 + [429]
    finally:
        await sdk.aclose()
