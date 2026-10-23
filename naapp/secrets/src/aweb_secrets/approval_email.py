"""Locator-only B2 notices for use and change approvals.

Composition supplies the trusted console's absolute /approvals endpoint, never
an agent request. The notice contains only a locator: B3 authentication is still
required to see the frozen request and decide. The token stays in the fragment;
the console posts it to its ceremony routes in JSON.
"""

from html import escape
from urllib.parse import quote, urlsplit, urlunsplit

from aweb_naapp.email import EmailNotSent, Mailer, Message
from aweb_naapp.runtime.approvals import Approval, Approver, DeliveryStatus
from aweb_naapp.runtime.passkeys import RelyingParty


class ApprovalEmailDelivery:
    """B2's ApprovalDelivery for both use and change approvals.

    Call through Approvals.deliver after the minting transaction commits.
    Mail goes only to the supplied designated approver's registered contact.
    SMTP refusal is FAILED; this adapter never retries or changes authority.
    """

    def __init__(self, *, mailer: Mailer, approval_url: str) -> None:
        parts = urlsplit(approval_url)
        if (
            not parts.path.startswith("/")
            or parts.query
            or parts.fragment
            or parts.username
            or parts.password
            or any(c.isspace() for c in approval_url)
        ):
            raise ValueError(
                "approval endpoint must be an absolute console URL without query or fragment"
            )
        # Use the same secure-origin rule as the app's WebAuthn relying party.
        RelyingParty(origin=urlunsplit((parts.scheme, parts.netloc, "", "", "")), name="secrets")
        self._mailer = mailer
        self._approval_url = approval_url

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus:
        url = f"{self._approval_url}#token={quote(link_token, safe='')}"
        try:
            await self._mailer.send(
                Message(
                    to=approver.contact,
                    subject="Approval requested",
                    text=f"A request is waiting for review in the console.\n\n{url}\n",
                    html=(
                        "<p>A request is waiting for review in the console.</p>"
                        f'<p><a href="{escape(url, quote=True)}">Open the console</a></p>'
                    ),
                )
            )
        except EmailNotSent:
            return DeliveryStatus.FAILED
        return DeliveryStatus.DELIVERED
