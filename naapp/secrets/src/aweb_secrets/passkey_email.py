"""Contact-bound bootstrap mail through the deployment's one TLS mailer."""

from aweb_naapp.email import Mailer
from aweb_naapp.runtime.passkeys import email


class PasskeyEmailDelivery(email.PasskeyEmailDelivery):
    """B3's ceremony links and credential notices, in secrets' copy."""

    def __init__(self, *, mailer: Mailer, console_origin: str) -> None:
        super().__init__(
            mailer=mailer,
            console_origin=console_origin,
            product="Secrets",
            link_text="Open Secrets",
        )
