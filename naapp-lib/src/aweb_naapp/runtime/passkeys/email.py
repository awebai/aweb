"""B3's contact-bound mail through the deployment's one TLS mailer."""

from html import escape
from urllib.parse import quote

from aweb_naapp.email import EmailNotSent, Mailer, Message
from aweb_naapp.runtime.approvals import Approver, DeliveryStatus
from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.runtime.passkeys.service import Notice, NoticeKind


class PasskeyEmailDelivery:
    """Send only after the ceremony transaction commits, to its recorded contact.

    A fragment locator grants no console session. The browser submits it to
    the existing one-use B3 ceremony; scope, subject and credential identifiers
    never enter the message. ``product`` names the app in the copy and
    ``link_text`` labels the link.
    """

    def __init__(
        self, *, mailer: Mailer, console_origin: str, product: str, link_text: str
    ) -> None:
        try:
            if any(char.isspace() for char in console_origin):
                raise ValueError
            RelyingParty(origin=console_origin, name=product)
        except ValueError:
            raise ValueError("passkey mail requires the exact secure console origin") from None
        self._mailer = mailer
        self._origin = console_origin
        self._product = product
        self._link_text = link_text

    async def _send(self, message: Message) -> DeliveryStatus:
        try:
            await self._mailer.send(message)
        except EmailNotSent:
            return DeliveryStatus.FAILED
        return DeliveryStatus.DELIVERED

    async def _link(
        self, *, contact: str, path: str, token: str, subject: str, instruction: str
    ) -> DeliveryStatus:
        url = f"{self._origin}/{path}#token={quote(token, safe='')}"
        return await self._send(
            Message(
                to=contact,
                subject=subject,
                text=f"{instruction}\n\n{url}\n",
                html=f'<p>{escape(instruction)}</p><p><a href="{escape(url, quote=True)}">'
                f"{escape(self._link_text)}</a></p>",
            )
        )

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        return await self._link(
            contact=approver.contact,
            path="enrolment",
            token=link_token,
            subject=f"Set up your {self._product} passkey",
            instruction=f"Your team owner has invited you to set up a passkey for {self._product}.",
        )

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        return await self._link(
            contact=contact,
            path="contact-proof",
            token=proof_token,
            subject=f"Confirm your {self._product} contact",
            instruction="Confirm that you can receive messages at this contact address.",
        )

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus:
        subject, explanation = {
            NoticeKind.RECOVERY_STARTED: (
                f"{self._product} passkey recovery started",
                "A replacement passkey holder has been designated.",
            ),
            NoticeKind.CONTACT_CHANGE_SCHEDULED: (
                f"{self._product} contact change scheduled",
                f"A change to your {self._product} contact has been scheduled.",
            ),
            NoticeKind.CONTACT_CHANGE_CANCELLED: (
                f"{self._product} contact change cancelled",
                f"The pending change to your {self._product} contact has been cancelled.",
            ),
        }[notice.kind]
        text = f"{explanation}\n"
        if notice.kind is not NoticeKind.CONTACT_CHANGE_CANCELLED:
            text += f"Effective time: {notice.effective_at.isoformat()}\n"
        return await self._send(
            Message(to=contact, subject=subject, text=text, html=f"<p>{escape(text)}</p>")
        )
