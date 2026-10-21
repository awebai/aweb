"""Sending a naapp's links and notices by email, over SMTP with TLS required.

:meth:`EmailSettings.from_env` reads the configuration under the app's prefix
and fails at startup if anything is missing or malformed: ``<PREFIX>EMAIL_SMTP_HOST``,
``_SMTP_PORT``, ``_TLS`` (``starttls`` or ``implicit``; there is no plaintext),
``_USERNAME``, ``_PASSWORD_FILE`` (a key file, read with
:func:`aweb_naapp.key_file.read_key_file`; the password is never taken from the
environment), ``_FROM``, and optionally ``_CA_FILE`` for a private CA.

:meth:`Mailer.send` sends one message to one recipient, text and HTML as
multipart/alternative, through the standard library's smtplib in a worker
thread. The server's certificate is verified; if TLS cannot be had, nothing is
sent. There are no retries: the caller decides. A failure raises
:class:`EmailNotSent` with a code. Neither errors nor logs ever carry the body,
which may hold a bearer link, or the password; logs name the recipient masked.

Imports only the standard library.
"""

from __future__ import annotations

import asyncio
import logging
import os
import smtplib
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import parseaddr
from pathlib import Path
from typing import Literal

from aweb_naapp.key_file import read_key_file

logger = logging.getLogger(__name__)

Tls = Literal["starttls", "implicit"]
TLS_MODES: tuple[Tls, ...] = ("starttls", "implicit")
DEFAULT_TIMEOUT_SECONDS = 10.0


class EmailNotSent(Exception):
    """A message was not delivered. ``code`` is one of ``tls_unavailable``,
    ``auth_failed``, ``recipient_refused``, ``message_refused``,
    ``connection_failed`` or ``timeout``; the message never carries the body."""

    def __init__(self, code: str) -> None:
        super().__init__(f"email not sent: {code}")
        self.code = code


@dataclass(frozen=True)
class Message:
    """One message to one recipient."""

    to: str
    subject: str
    text: str
    html: str


@dataclass(frozen=True)
class EmailSettings:
    host: str
    port: int
    tls: Tls
    username: str
    sender: str
    password: str = field(repr=False)
    ca_file: Path | None = None

    @classmethod
    def from_env(cls, prefix: str, *, environ: Mapping[str, str] | None = None) -> EmailSettings:
        """The settings under ``prefix``; raises ValueError naming the setting, never its value."""
        env = os.environ if environ is None else environ

        def required(name: str) -> str:
            value = env.get(prefix + name, "").strip()
            if not value:
                raise ValueError(f"{prefix}{name} is required")
            return value

        if prefix + "EMAIL_PASSWORD" in env:
            raise ValueError(
                f"{prefix}EMAIL_PASSWORD is not read; give the password in {prefix}EMAIL_PASSWORD_FILE"
            )
        host = required("EMAIL_SMTP_HOST")
        port_text = required("EMAIL_SMTP_PORT")
        if not port_text.isdigit() or not 0 < int(port_text) < 65536:
            raise ValueError(f"{prefix}EMAIL_SMTP_PORT must be a port number")
        tls = env.get(prefix + "EMAIL_TLS", "starttls").strip()
        if tls not in TLS_MODES:
            raise ValueError(f"{prefix}EMAIL_TLS must be one of {', '.join(TLS_MODES)}")
        sender = required("EMAIL_FROM")
        if "@" not in parseaddr(sender)[1]:
            raise ValueError(f"{prefix}EMAIL_FROM must hold an email address")
        content = read_key_file(Path(required("EMAIL_PASSWORD_FILE")))
        try:
            password = content.decode("utf-8").removesuffix("\n")
        except UnicodeDecodeError:
            raise ValueError(f"{prefix}EMAIL_PASSWORD_FILE must hold UTF-8 text") from None
        if not password:
            raise ValueError(f"{prefix}EMAIL_PASSWORD_FILE is empty")
        ca_text = env.get(prefix + "EMAIL_CA_FILE", "").strip()
        return cls(
            host=host,
            port=int(port_text),
            tls=tls,  # type: ignore[arg-type]
            username=required("EMAIL_USERNAME"),
            sender=sender,
            password=password,
            ca_file=Path(ca_text) if ca_text else None,
        )


def masked(address: str) -> str:
    """An address as logs may show it: its first character and its domain."""
    local, at, domain = address.partition("@")
    return f"{local[:1]}***@{domain}" if at and local else "***"


class Mailer:
    def __init__(
        self, settings: EmailSettings, *, timeout: float = DEFAULT_TIMEOUT_SECONDS
    ) -> None:
        if timeout <= 0:
            raise ValueError("the email timeout must be positive")
        self._settings = settings
        self._timeout = timeout

    async def send(self, message: Message) -> None:
        """Deliver ``message``, or raise :class:`EmailNotSent`. A header holding a
        line break raises ValueError before anything is sent."""
        prepared = self._prepared(message)
        try:
            await asyncio.to_thread(self._deliver, prepared, message.to)
        except EmailNotSent as error:
            logger.warning("email to %s not sent: %s", masked(message.to), error.code)
            raise
        logger.info("email sent to %s", masked(message.to))

    def _prepared(self, message: Message) -> EmailMessage:
        prepared = EmailMessage()
        prepared["From"] = self._settings.sender
        prepared["To"] = message.to
        prepared["Subject"] = message.subject
        prepared.set_content(message.text)
        prepared.add_alternative(message.html, subtype="html")
        return prepared

    def _deliver(self, prepared: EmailMessage, to: str) -> None:
        s = self._settings
        context = ssl.create_default_context(cafile=str(s.ca_file) if s.ca_file else None)
        smtp: smtplib.SMTP | None = None
        try:
            if s.tls == "implicit":
                smtp = smtplib.SMTP_SSL(s.host, s.port, timeout=self._timeout, context=context)
            else:
                smtp = smtplib.SMTP(s.host, s.port, timeout=self._timeout)
            # Debug output would echo the conversation, body included.
            smtp.set_debuglevel(0)
            if s.tls == "starttls":
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise EmailNotSent("tls_unavailable")
                smtp.starttls(context=context)
                smtp.ehlo()
            smtp.login(s.username, s.password)
            smtp.send_message(prepared, from_addr=parseaddr(s.sender)[1], to_addrs=[to])
        except EmailNotSent:
            raise
        except (smtplib.SMTPAuthenticationError, smtplib.SMTPNotSupportedError):
            # NotSupported here is login against a server that offers no AUTH.
            raise EmailNotSent("auth_failed") from None
        except smtplib.SMTPRecipientsRefused:
            raise EmailNotSent("recipient_refused") from None
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError):
            raise EmailNotSent("message_refused") from None
        except ssl.SSLError:
            raise EmailNotSent("tls_unavailable") from None
        except TimeoutError:
            raise EmailNotSent("timeout") from None
        except (OSError, smtplib.SMTPException) as error:
            # smtplib reports a read that timed out as a lost connection.
            if isinstance(error.__context__, TimeoutError):
                raise EmailNotSent("timeout") from None
            raise EmailNotSent("connection_failed") from None
        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except (OSError, smtplib.SMTPException):
                    smtp.close()


__all__ = ["EmailNotSent", "EmailSettings", "Mailer", "Message", "masked"]
