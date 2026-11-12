"""B3 mail and locator-only B2 notices through the configured TLS mailer."""

from html import escape

from aweb_naapp.email import EmailNotSent, Message
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.passkeys.email import PasskeyEmailDelivery


class ProtectedNotifications(PasskeyEmailDelivery):
    def __init__(self, *, db, mailer, human_origin):
        super().__init__(
            mailer=mailer,
            console_origin=human_origin,
            product="Protected signing",
            link_text="Open protected signing",
        )
        self.db = db

    async def deliver_approval_link(self, approver, link_token, approval):
        # Post-commit only: self.db's fresh read cannot see the preparing
        # transaction's uncommitted handoff. The shared signer currently does
        # not dispatch this port; future wiring must call after commit.
        # Shared prepare retains the candidate tokens privately. The public
        # handoff is only a locator: actual LOGIN and distinct act UV remain
        # mandatory. Never put a candidate bearer token or payload in mail.
        if not approver.contact:
            return DeliveryStatus.FAILED
        handoff_id = await self.db.fetch_value(
            "SELECT handoff_id FROM {{tables.protected_signer_operations}} "
            "WHERE approval_id=$1",
            approval.approval_id,
        )
        if handoff_id is None:
            return DeliveryStatus.FAILED
        url = f"{self._origin}/handoff/{handoff_id}"
        try:
            await self._mailer.send(
                Message(
                    to=approver.contact,
                    subject="Protected signing approval requested",
                    text=f"Review the request with your passkey.\n\n{url}\n",
                    html=f'<p><a href="{escape(url, quote=True)}">Review the request</a></p>',
                )
            )
        except EmailNotSent:
            return DeliveryStatus.FAILED
        return DeliveryStatus.DELIVERED
