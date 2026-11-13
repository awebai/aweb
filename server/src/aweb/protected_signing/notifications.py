"""B3 mail and locator-only B2 notices through the configured TLS mailer."""

from datetime import UTC
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
        # Called by the shared signer after prepare commits, so this fresh read
        # sees the committed handoff. The personal token rides in the URL
        # fragment, which browsers never send to a server; the page posts it.
        # Revealing the request needs that token, and deciding it still needs
        # this approver's own fresh exact-act passkey assertion
        # (human-assurance-contract.md, "Mailed approval links").
        if not approver.contact:
            return DeliveryStatus.FAILED
        handoff_id = await self.db.fetch_value(
            "SELECT handoff_id FROM {{tables.protected_signer_operations}} "
            "WHERE approval_id=$1",
            approval.approval_id,
        )
        if handoff_id is None:
            return DeliveryStatus.FAILED
        url = f"{self._origin}/handoff/{handoff_id}#k={link_token}"
        expires = approval.expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        text = (
            "A request is waiting for your approval. Open it to see what it asks for, "
            "then approve or deny it with your passkey.\n\n"
            f"{url}\n\n"
            f"It expires at {expires}. Deny also asks for your passkey.\n"
            "If you did not expect this request, open it and choose Deny.\n"
        )
        html = (
            "<p>A request is waiting for your approval. Open it to see what it asks for, "
            "then approve or deny it with your passkey.</p>"
            f'<p><a href="{escape(url, quote=True)}">Review the request</a></p>'
            f"<p>It expires at {escape(expires)}. Deny also asks for your passkey.</p>"
            "<p>If you did not expect this request, open it and choose Deny.</p>"
        )
        try:
            await self._mailer.send(
                Message(
                    to=approver.contact,
                    subject="A request is waiting for your approval",
                    text=text,
                    html=html,
                )
            )
        except EmailNotSent:
            return DeliveryStatus.FAILED
        return DeliveryStatus.DELIVERED
