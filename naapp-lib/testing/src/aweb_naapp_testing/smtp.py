"""A real SMTP server on this host for tests (aiosmtpd), so mail is delivered
and refused by an actual server rather than a stand-in.

The server listens on 127.0.0.1 with a throwaway certificate for ``localhost``
(:func:`aweb_naapp_testing.network.make_certificates`). It offers STARTTLS,
implicit TLS, or neither, and accepts one username and password, only over
TLS. Recipients in ``refuse`` are rejected; every accepted message is kept in
``received``. :class:`SilentServer` accepts connections and never answers, for
timeouts.
"""

from __future__ import annotations

import logging
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword

from aweb_naapp_testing.network import Certificates, make_certificates

Mode = Literal["starttls", "implicit", "plain"]
# aiosmtpd 1.4.6 logs a deprecation of its own Session.login_data on every
# successful AUTH, even through the current authenticator API.
logging.getLogger("mail.log").setLevel(logging.ERROR)
HOST = "localhost"
ADDRESS = "127.0.0.1"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind((ADDRESS, 0))
        return int(probe.getsockname()[1])


@dataclass
class Received:
    mail_from: str
    rcpt_tos: list[str]
    content: bytes


@dataclass
class SmtpServer:
    """A running SMTP server; use it as a context manager."""

    directory: Path
    mode: Mode = "starttls"
    username: str = "mailer"
    password: str = "smtp-test-password"
    refuse: set[str] = field(default_factory=set)
    received: list[Received] = field(default_factory=list)
    port: int = 0
    certificates: Certificates | None = None
    _controller: Controller | None = None

    def __enter__(self) -> SmtpServer:
        self.directory.mkdir(parents=True, exist_ok=True)
        self.certificates = make_certificates(self.directory, [HOST], [ADDRESS])
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.certificates.cert_file, self.certificates.key_file)
        self.port = _free_port()
        options: dict[str, Any] = dict(
            hostname=ADDRESS,
            port=self.port,
            server_hostname=HOST,
            authenticator=self._authenticate,
            # aiosmtpd counts only STARTTLS as TLS, so an implicit-TLS session
            # would be refused AUTH if it were required here.
            auth_require_tls=self.mode == "starttls",
        )
        if self.mode == "starttls":
            options.update(tls_context=context, require_starttls=True)
        elif self.mode == "implicit":
            options.update(ssl_context=context)
        self._controller = Controller(self, **options)
        self._controller.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._controller is not None:
            self._controller.stop()
            self._controller = None

    @property
    def ca_file(self) -> Path:
        assert self.certificates is not None
        return self.certificates.ca_file

    def _authenticate(
        self, server: Any, session: Any, envelope: Any, mechanism: str, auth_data: Any
    ) -> AuthResult:
        ok = (
            isinstance(auth_data, LoginPassword)
            and auth_data.login.decode() == self.username
            and auth_data.password.decode() == self.password
        )
        return AuthResult(success=ok, handled=False)

    async def handle_RCPT(
        self, server: Any, session: Any, envelope: Any, address: str, rcpt_options: list[str]
    ) -> str:
        if address in self.refuse:
            return "550 5.1.1 recipient refused"
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        self.received.append(
            Received(envelope.mail_from, list(envelope.rcpt_tos), bytes(envelope.original_content))
        )
        return "250 Message accepted"


class SilentServer:
    """Accepts connections and never sends a greeting; use it as a context manager."""

    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((ADDRESS, 0))
        self.port = int(self._socket.getsockname()[1])
        self._accepted: list[socket.socket] = []
        self._stop = threading.Event()

    def __enter__(self) -> SilentServer:
        self._socket.listen()
        self._socket.settimeout(0.1)
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self._socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self._accepted.append(connection)

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        for connection in self._accepted:
            connection.close()
        self._socket.close()
