"""A standalone B3 cancellation mail omits its abandoned future schedule.

This tests B3's real ceremonies and the TLS mail adapter. Production-root
self-contact/cancellation governance is explicitly outside this checkpoint;
its required sink must keep refusing those uncomposed stages.
"""

import email
import email.policy
import secrets
from datetime import UTC, datetime

from aweb_naapp.runtime.audit import AuditKind
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.passkey_email import PasskeyEmailDelivery
from tests.test_approval_email import mailer
from tests.test_owner_directory import ORIGIN
from tests.test_owner_directory import world as _world

world = _world


async def test_cancelled_contact_notice_does_not_present_the_old_schedule(world, tmp_path):
    contact, new_contact = "finance@example.com", "new-finance@example.com"
    from tests.test_owner_directory import Audit, designate_contact

    scope = await designate_contact(world, "finance", contact)
    device = world.devices[contact]
    # This file deliberately tests the standalone B3 mail component; the
    # production root continues to refuse uncomposed self-contact governance.
    world.passkeys._audit = Audit(world.db)
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        world.passkeys._delivery = PasskeyEmailDelivery(
            mailer=mailer(smtp, tmp_path), console_origin=ORIGIN
        )
        options = await world.passkeys.contact_change_options(scope, new_contact)
        abandoned = await world.passkeys.change_contact(scope, new_contact, device.get(options))
        assert abandoned > datetime.now(UTC)
        before = len(smtp.received)
        options = await world.passkeys.contact_cancel_options(scope)
        await world.passkeys.cancel_pending_contact(scope, device.get(options))
        current = await world.passkeys.designated_approver(scope)
        assert current.contact == contact
        pending = await world.db.fetch_one(
            "SELECT pending_contact,pending_contact_at FROM {{tables.passkey_approvers}} WHERE scope=$1 AND subject=$2",
            scope,
            current.subject,
        )
        assert pending["pending_contact"] is None and pending["pending_contact_at"] is None
        kinds = await world.db.fetch_all("SELECT kind FROM {{tables.audit_outbox}} ORDER BY id")
        assert [row["kind"] for row in kinds][-2:] == [
            AuditKind.APPROVER_CONTACT_CHANGE_SCHEDULED.value,
            AuditKind.APPROVER_CONTACT_CHANGE_CANCELLED.value,
        ]
        notices = smtp.received[before:]
        assert {tuple(m.rcpt_tos) for m in notices} == {(contact,), (new_contact,)}
        for received in notices:
            message = email.message_from_bytes(received.content, policy=email.policy.default)
            for content_type in ("plain", "html"):
                assert abandoned.isoformat() not in message.get_body((content_type,)).get_content()
