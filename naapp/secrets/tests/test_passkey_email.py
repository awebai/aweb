"""Bootstrap links and credential notices traverse a real TLS SMTP server."""

import secrets
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest
from aweb_naapp.runtime.approvals import Approver, DeliveryStatus
from aweb_naapp.runtime.passkeys import Notice, NoticeKind
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.passkey_email import PasskeyEmailDelivery
from tests.test_approval_email import contents, mailer

ORIGIN = "https://console.secrets.test"
CONTACT = "owner@example.com"


@pytest.mark.parametrize("ceremony", ["enrolment", "contact-proof"])
async def test_bootstrap_mail_has_only_a_console_fragment_locator(tmp_path, ceremony, caplog):
    token = secrets.token_urlsafe(32) + '+/&="#?'
    approver = Approver("restricted-scope", "restricted-subject", "app_local", CONTACT)
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        delivery = PasskeyEmailDelivery(mailer=mailer(smtp, tmp_path), console_origin=ORIGIN)
        if ceremony == "enrolment":
            status = await delivery.deliver_enrolment_link(approver, token)
        else:
            status = await delivery.deliver_contact_proof(CONTACT, token)
        assert status is DeliveryStatus.DELIVERED
        [received] = smtp.received
        assert received.rcpt_tos == [CONTACT]
        message, text, html, url = contents(received)
        parts = urlsplit(url)
        assert parts._replace(fragment="").geturl() == ORIGIN + "/" + ceremony
        assert parse_qs(parts.fragment) == {"token": [token]}
        assert message["Cc"] is None and message["Bcc"] is None
        assert all(
            value not in text and value not in html for value in (approver.scope, approver.subject)
        )
        assert token not in caplog.text and CONTACT not in caplog.text


@pytest.mark.parametrize("kind", list(NoticeKind))
async def test_notices_disclose_neither_scope_nor_a_link_token(tmp_path, kind):
    with SmtpServer(tmp_path / "smtp", password=secrets.token_urlsafe(32)) as smtp:
        delivery = PasskeyEmailDelivery(mailer=mailer(smtp, tmp_path), console_origin=ORIGIN)
        notice = Notice(kind, "restricted-scope", datetime.now(UTC))
        assert await delivery.deliver_notice(CONTACT, notice) is DeliveryStatus.DELIVERED
        [received] = smtp.received
        assert received.rcpt_tos == [CONTACT]
        assert notice.scope.encode() not in received.content


@pytest.mark.parametrize("mode", ["plain", "starttls"])
async def test_failed_bootstrap_mail_is_a_failure_without_a_retry_or_token_log(
    tmp_path, mode, caplog
):
    token = secrets.token_urlsafe(32)
    with SmtpServer(
        tmp_path / "smtp", mode=mode, refuse={CONTACT}, password=secrets.token_urlsafe(32)
    ) as smtp:
        delivery = PasskeyEmailDelivery(mailer=mailer(smtp, tmp_path), console_origin=ORIGIN)
        assert await delivery.deliver_contact_proof(CONTACT, token) is DeliveryStatus.FAILED
        assert smtp.received == []
        assert token not in caplog.text and CONTACT not in caplog.text


@pytest.mark.parametrize(
    "origin",
    [
        "http://console.test",
        "https://user@console.test",
        "https://console.test/path",
        "https://console.test?token=x",
        "https://console.test#token=x",
    ],
)
def test_bootstrap_origin_must_be_the_exact_secure_console_origin(origin):
    with pytest.raises(ValueError):
        PasskeyEmailDelivery(mailer=None, console_origin=origin)
