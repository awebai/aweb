"""A hook drain process for the crash test: it materializes the pending event
and sends it to the test's TLS target, which holds the request until the test
kills this process.

Usage: hook_drain_child.py <database dsn> <schema, or "" for none> <unused>
       <target name> <dns port> <ca file> <target address> <target origin> <seed hex>
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

from pgdbm import AsyncDatabaseManager, DatabaseConfig

from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.producer import HOOKS_CHANNEL, Registration, RegistrationView, hook_targets
from aweb_naapp.hooks.transport import HookTransport
from aweb_naapp.outbox import RetryPolicy, drain

TEAM = "backend:example.com"
BINDING = "6f9619ff-8b86-4011-b42d-00c04fc964ff"


class Views:
    def __init__(self, origin: str) -> None:
        self.origin = origin

    async def view(self, team_id: str, hook: str) -> RegistrationView:
        return RegistrationView(
            team_id=TEAM,
            hook=hook,
            as_of=datetime.now(UTC),
            max_age=timedelta(seconds=60),
            registrations=(
                Registration(
                    binding_id=BINDING,
                    origin=self.origin,
                    method="POST",
                    path="/hooks/ingest",
                    active_from=datetime.now(UTC) - timedelta(minutes=5),
                ),
            ),
        )


async def main(argv: list[str]) -> None:
    dsn, schema, _, _name, dns_port, ca_file, address, origin, seed = argv
    db = AsyncDatabaseManager(DatabaseConfig(connection_string=dsn, schema=schema or None))
    await db.connect()
    views = Views(origin)
    egress = Egress(
        addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
        resolver=DnsResolver(nameservers=["127.0.0.1"], port=int(dns_port)),
        user_agent="hooks-test/1",
        ca_file=Path(ca_file),
    )
    await drain(
        db,
        channel=HOOKS_CHANNEL,
        resolver=hook_targets(views),
        transport=HookTransport(
            seed=bytes.fromhex(seed),
            egress=egress,
            registrations=views,
            internal_cidr=ip_network(f"{address}/32"),
        ),
        policy=RetryPolicy(stalled_after=timedelta(hours=1)),
    )


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
