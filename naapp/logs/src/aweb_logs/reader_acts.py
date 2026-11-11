"""``logs.reader``, the one role a team owner designates in logs
(owner-act-delivery.md; audit-substrate.md §B5).

The owner designates a reader, replaces the reader's credential and revokes the
reader by a human-role act delivered to logs' console origin, where the
reader's passkey is bound. A reader takes no notice contact.
"""

from __future__ import annotations

from typing import Any

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS

from aweb_logs.readers import READER_ROLE

# logs' manifest version 3 ``owner_acts``; the runtime fills its origin with
# the console origin.
OWNER_ACTS: dict[str, Any] = {
    "roles": [
        {
            "name": READER_ROLE,
            "label": "Log reader",
            "acts": sorted(HUMAN_ROLE_ACTS),
            "notice_contact": False,
        }
    ]
}
