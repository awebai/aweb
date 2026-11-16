"""B3 mail and locator-only B2 notices through the configured TLS mailer."""

import json
from datetime import UTC
from html import escape

from aweb_naapp.email import EmailNotSent, Message
from aweb_naapp.runtime.approvals import DeliveryStatus
from aweb_naapp.runtime.passkeys.email import PasskeyEmailDelivery
from aweb_naapp.runtime.protected_signer import SignerRefused
from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS


class ProtectedNotifications(PasskeyEmailDelivery):
    def __init__(self, *, db, mailer, human_origin, policies=None):
        super().__init__(
            mailer=mailer,
            console_origin=human_origin,
            product="Protected signing",
            link_text="Open protected signing",
        )
        self.db = db
        # The B2 policy source of the signer this notice serves. Without it a
        # notice names nothing about the request.
        self._policies = policies

    def with_policies(self, policies):
        return ProtectedNotifications(
            db=self.db, mailer=self._mailer, human_origin=self._origin, policies=policies
        )

    async def _title(self, request, approval):
        """The definition's question for the frozen request, only when its
        whole request is classified revealable and the approval's own frozen
        policy version lets the link reveal it (human-assurance-contract.md,
        "Mailed approval links"). Otherwise None: the notice stays
        locator-only. A later policy never widens an older notice."""
        spec = OPERATIONS.get((request.get("operation"), request.get("variant")))
        if spec is None or not spec.link_revealable or self._policies is None:
            return None
        try:
            policy = await self._policies.current(approval.policy_ref)
        except SignerRefused:
            return None
        if policy is None or policy.version != approval.policy_version or not policy.reveals_request_on_link():
            return None
        try:
            return spec.display.render(request)["title"]
        except SignerRefused:
            return None

    async def deliver_approval_link(self, approver, link_token, approval):
        # Called by the shared signer after prepare commits, so this fresh read
        # sees the committed handoff. The personal token rides in the URL
        # fragment, which browsers never send to a server; the page posts it.
        # Revealing the request needs that token, and deciding it still needs
        # this approver's own fresh exact-act passkey assertion
        # (human-assurance-contract.md, "Mailed approval links").
        if not approver.contact:
            return DeliveryStatus.FAILED
        row = await self.db.fetch_one(
            "SELECT handoff_id,request FROM {{tables.protected_signer_operations}} "
            "WHERE approval_id=$1",
            approval.approval_id,
        )
        if row is None:
            return DeliveryStatus.FAILED
        request = row["request"]
        title = await self._title(json.loads(request) if isinstance(request, (str, bytes)) else request, approval)
        url = f"{self._origin}/handoff/{row['handoff_id']}#k={link_token}"
        expires = approval.expires_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")
        asks = f"It asks: {title}\n\n" if title else ""
        text = (
            "A request is waiting for your approval. Open it to see what it asks for, "
            "then approve or deny it with your passkey.\n\n"
            f"{asks}"
            f"{url}\n\n"
            f"It expires at {expires}. Deny also asks for your passkey.\n"
            "If you did not expect this request, open it and choose Deny.\n"
        )
        html = (
            "<p>A request is waiting for your approval. Open it to see what it asks for, "
            "then approve or deny it with your passkey.</p>"
            + (f"<p>It asks: <strong>{escape(title, quote=True)}</strong></p>" if title else "")
            + f'<p><a href="{escape(url, quote=True)}">Review the request</a></p>'
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
