"""B3's enrolment and contact-proof links and credential notices, through the
shared mailer to a real TLS SMTP server started in the test."""

from __future__ import annotations

import email
import email.policy
import secrets
from datetime import UTC, datetime
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from aweb_naapp_testing.smtp import SmtpServer

from aweb_naapp.runtime.approvals import Approver, DeliveryStatus
from aweb_naapp.runtime.passkeys import Notice, NoticeKind
from aweb_naapp.runtime.passkeys.email import PasskeyEmailDelivery

from .test_email import _environ, _mailer

ORIGIN = "https://console.app.test"
CONTACT = "owner@example.com"


class Links(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs)["href"]

    def handle_data(self, data):
        if self._href is not None:
            self.links.append((self._href, data))
            self._href = None


def delivery(server: SmtpServer, tmp_path: Path) -> PasskeyEmailDelivery:
    return PasskeyEmailDelivery(
        mailer=_mailer(_environ(server, tmp_path)),
        console_origin=ORIGIN,
        product="App",
        link_text="Open the app",
    )


def contents(server: SmtpServer) -> tuple[EmailMessage, str, str, list[tuple[str, str]]]:
    [received] = server.received
    message = email.message_from_bytes(received.content, policy=email.policy.default)
    assert isinstance(message, EmailMessage)
    text = message.get_body(("plain",)).get_content()
    html = message.get_body(("html",)).get_content()
    return message, text, html, Links(html).links


@pytest.mark.parametrize("ceremony", ["enrolment", "contact-proof"])
async def test_a_ceremony_mail_carries_only_a_console_fragment_locator(tmp_path, ceremony, caplog):
    token = secrets.token_urlsafe(32) + '+/&="#?'
    approver = Approver("restricted-scope", "restricted-subject", "app_local", CONTACT)
    with SmtpServer(tmp_path / "smtp") as server:
        sender = delivery(server, tmp_path)
        if ceremony == "enrolment":
            status = await sender.deliver_enrolment_link(approver, token)
        else:
            status = await sender.deliver_contact_proof(CONTACT, token)
        assert status is DeliveryStatus.DELIVERED
        assert server.received[0].rcpt_tos == [CONTACT]
        message, text, html, links = contents(server)
    [(url, link_text)] = links
    assert link_text == "Open the app"
    assert url in text
    parts = urlsplit(url)
    assert parts._replace(fragment="").geturl() == ORIGIN + "/" + ceremony
    assert parse_qs(parts.fragment) == {"token": [token]}
    assert message["Cc"] is None and message["Bcc"] is None
    for restricted in (approver.scope, approver.subject):
        assert restricted not in text and restricted not in html
    assert token not in caplog.text and CONTACT not in caplog.text


@pytest.mark.parametrize("kind", list(NoticeKind))
async def test_a_notice_discloses_neither_the_scope_nor_a_link(tmp_path, kind):
    with SmtpServer(tmp_path / "smtp") as server:
        notice = Notice(kind, "restricted-scope", datetime.now(UTC))
        assert (
            await delivery(server, tmp_path).deliver_notice(CONTACT, notice)
            is DeliveryStatus.DELIVERED
        )
        assert server.received[0].rcpt_tos == [CONTACT]
        assert notice.scope.encode() not in server.received[0].content
        _, text, _, links = contents(server)
    assert links == []
    assert ORIGIN not in text


@pytest.mark.parametrize("mode", ["plain", "starttls"])
async def test_a_failed_mail_is_a_failure_without_a_retry_or_a_logged_token(tmp_path, mode, caplog):
    token = secrets.token_urlsafe(32)
    with SmtpServer(tmp_path / "smtp", mode=mode, refuse={CONTACT}) as server:
        assert (
            await delivery(server, tmp_path).deliver_contact_proof(CONTACT, token)
            is DeliveryStatus.FAILED
        )
        assert server.received == []
    assert token not in caplog.text and CONTACT not in caplog.text


@pytest.mark.parametrize(
    "origin",
    [
        "http://console.test",
        "https://user@console.test",
        "https://console.test/path",
        "https://console.test?token=x",
        "https://console.test#token=x",
        "https://console .test",
    ],
)
def test_the_console_origin_must_be_exact_and_secure(origin):
    with pytest.raises(ValueError):
        PasskeyEmailDelivery(mailer=None, console_origin=origin, product="App", link_text="Open")
