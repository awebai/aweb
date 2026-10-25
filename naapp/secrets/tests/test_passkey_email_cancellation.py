"""A real B3 cancellation does not advertise its abandoned future schedule."""

import email
import email.policy
import secrets
from datetime import UTC, datetime

from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.passkey_email import PasskeyEmailDelivery
from tests.test_approval_email import mailer
from tests.test_change_sets import ALICE, ORIGIN, enrol_owner
from tests.test_change_sets import world as _world

world = _world


async def test_cancelled_contact_notice_does_not_present_the_old_schedule(world, tmp_path):
    contact, new_contact = "owner@example.com", "new-owner@example.com"
    scope = await enrol_owner(world, ALICE, contact)
    device = world.devices[contact]
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
        assert (await world.passkeys.designated_approver(scope)).contact == contact
        notices = smtp.received[before:]
        assert {tuple(m.rcpt_tos) for m in notices} == {(contact,), (new_contact,)}
        for received in notices:
            message = email.message_from_bytes(received.content, policy=email.policy.default)
            for content_type in ("plain", "html"):
                assert abandoned.isoformat() not in message.get_body((content_type,)).get_content()
