"""Contact-bound bootstrap mail through the deployment's one TLS mailer."""

from html import escape
from urllib.parse import quote

from aweb_naapp.email import EmailNotSent, Mailer, Message
from aweb_naapp.runtime.approvals import Approver, DeliveryStatus
from aweb_naapp.runtime.passkeys import Notice, NoticeKind, RelyingParty


class PasskeyEmailDelivery:
    """Send only after the ceremony transaction commits, to its recorded contact.

    A fragment locator grants no console session. The browser submits it to
    the existing one-use B3 ceremony; scope, subject and credential identifiers
    never enter the message. The same Mailer also serves approval notices.
    """

    def __init__(self, *, mailer: Mailer, console_origin: str) -> None:
        try:
            if any(char.isspace() for char in console_origin):
                raise ValueError
            RelyingParty(origin=console_origin, name="Secrets")
        except ValueError:
            raise ValueError("bootstrap mail requires the exact secure console origin") from None
        self._mailer = mailer
        self._origin = console_origin

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
                html=f'<p>{escape(instruction)}</p><p><a href="{escape(url, quote=True)}">Open Secrets</a></p>',
            )
        )

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        return await self._link(
            contact=approver.contact,
            path="enrolment",
            token=link_token,
            subject="Set up your Secrets passkey",
            instruction="Your team owner has invited you to set up a passkey for Secrets.",
        )

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        return await self._link(
            contact=contact,
            path="contact-proof",
            token=proof_token,
            subject="Confirm your Secrets contact",
            instruction="Confirm that you can receive messages at this contact address.",
        )

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus:
        subject, explanation = {
            NoticeKind.RECOVERY_STARTED: (
                "Secrets passkey recovery started",
                "A replacement passkey holder has been designated.",
            ),
            NoticeKind.CONTACT_CHANGE_SCHEDULED: (
                "Secrets contact change scheduled",
                "A change to your Secrets contact has been scheduled.",
            ),
            NoticeKind.CONTACT_CHANGE_CANCELLED: (
                "Secrets contact change cancelled",
                "The pending change to your Secrets contact has been cancelled.",
            ),
        }[notice.kind]
        text = f"{explanation}\nEffective time: {notice.effective_at.isoformat()}\n"
        return await self._send(
            Message(to=contact, subject=subject, text=text, html=f"<p>{escape(text)}</p>")
        )
