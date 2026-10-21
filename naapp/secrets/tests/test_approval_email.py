"""Locator-only approval notices through real SMTP, PostgreSQL and passkeys."""

from __future__ import annotations

import email
import email.policy
import secrets
from email.message import EmailMessage
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.runtime.approvals import (
    Approvals,
    ApprovalState,
    Assurance,
    Decision,
    DeliveryStatus,
    PgApprovalStore,
)
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.approval_email import ApprovalEmailDelivery
from aweb_secrets.use_approvals import UseApprovers, UsePolicies
from tests.test_change_sets import (
    ALICE,
    BOB,
    ORIGIN,
    by_member,
    change_set,
    enrol_owner,
    grant_role,
    world,  # noqa: F401
)
from tests.test_use_approvals import (
    REQUESTER,
    admit,
    designate,
    install,
    request,
    uses,  # noqa: F401
)

ENDPOINT = f"{ORIGIN}/approvals"
FINANCE = "finance@acme.com"
OPS = "ops@acme.com"


def mailer(smtp: SmtpServer, tmp_path: Path) -> Mailer:
    password = tmp_path / "smtp-password"
    password.write_text(smtp.password)
    password.chmod(0o600)
    return Mailer(
        EmailSettings.from_env(
            "SECRETS_",
            environ={
                "SECRETS_EMAIL_SMTP_HOST": "localhost",
                "SECRETS_EMAIL_SMTP_PORT": str(smtp.port),
                "SECRETS_EMAIL_USERNAME": smtp.username,
                "SECRETS_EMAIL_PASSWORD_FILE": str(password),
                "SECRETS_EMAIL_FROM": "noreply@secrets.example.com",
                "SECRETS_EMAIL_CA_FILE": str(smtp.ca_file),
            },
        )
    )


def use_email(context, delivery: ApprovalEmailDelivery) -> None:
    w = context.world
    context.approvals = Approvals(
        store=PgApprovalStore(w.db),
        policies=UsePolicies(w.db),
        approvers=UseApprovers(w.db, w.passkeys, w.directory),
        delivery=delivery,
        authenticators=[w.passkeys.authenticator()],
        audit=w.approvals._audit,
        clock=context.clock,
    )


class Links(HTMLParser):
    def __init__(self, html: str) -> None:
        super().__init__()
        self.urls: list[str] = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.urls.extend(value for key, value in attrs if key == "href")


def contents(received) -> tuple[EmailMessage, str, str, str]:
    message = email.message_from_bytes(received.content, policy=email.policy.default)
    assert isinstance(message, EmailMessage)
    text = message.get_body(("plain",)).get_content()
    html = message.get_body(("html",)).get_content()
    [url] = Links(html).urls
    assert url in text
    return message, text, html, url


async def test_locator_email_is_per_approver_and_still_requires_a_passkey(uses, tmp_path):  # noqa: F811
    await designate(uses, "finance", FINANCE)
    await designate(uses, "ops", OPS)
    await install(uses, approvers=["finance", "ops"])
    with SmtpServer(tmp_path / "smtp") as smtp:
        use_email(uses, ApprovalEmailDelivery(mailer=mailer(smtp, tmp_path), approval_url=ENDPOINT))
        admitted, dispatch_id, pending = await request(uses, reason="untrusted-reason-canary")
        approval_id = pending.pending.approval.approval_id
        assert len(smtp.received) == 2
        assert {tuple(m.rcpt_tos) for m in smtp.received} == {(FINANCE,), (OPS,)}
        tokens = {}
        for received in smtp.received:
            message, text, html, url = contents(received)
            [contact] = received.rcpt_tos
            assert message["To"] == contact
            assert message["Cc"] is None and message["Bcc"] is None
            parts = urlsplit(url)
            assert parts._replace(fragment="").geturl() == ENDPOINT
            [token] = parse_qs(parts.fragment)["token"]
            assert token not in parts.path and token not in parts.query
            assert token not in repr(pending.pending.view)
            for private in (
                "untrusted-reason-canary",
                "staging-api",
                "api.payments.example",
                "amount_minor_units",
                REQUESTER.did_key,
                approval_id,
                pending.pending.approval.request_sha256,
            ):
                assert (
                    private not in text
                    and private not in html
                    and private not in message["Subject"]
                )
            tokens[contact] = token
            opened = await uses.approvals.open_link(token)
            assert opened.request is None and opened.approval.state is ApprovalState.PENDING
        assert len(set(tokens.values())) == 2
        token = tokens[FINANCE]
        options = await uses.approvals.challenge(
            approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
        )
        await uses.approvals.decide(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            uses.world.devices[FINANCE].get(dict(options)),
            link_token=token,
        )
        result = await admit(uses, admitted, dispatch_id)
        assert result.refusal is None and result.admission.first and result.admission.may_send


@pytest.mark.parametrize("mode", ["starttls", "plain"])
async def test_email_failure_is_recorded_without_admission_or_retry(uses, tmp_path, caplog, mode):  # noqa: F811
    await designate(uses, "finance", FINANCE)
    await install(uses)
    with SmtpServer(tmp_path / "smtp", mode=mode, refuse={FINANCE}) as smtp:
        use_email(uses, ApprovalEmailDelivery(mailer=mailer(smtp, tmp_path), approval_url=ENDPOINT))
        admitted, dispatch_id, pending = await request(uses)
        approval = await uses.approvals.get(pending.pending.approval.approval_id)
        assert approval.delivery_status is DeliveryStatus.FAILED
        assert approval.state is ApprovalState.PENDING and approval.consumed_operation_id is None
        assert smtp.received == []
        assert (await admit(uses, admitted, dispatch_id)).refusal == "approval_pending"
        for delivery in pending.pending.deliveries:
            assert delivery.link_token not in caplog.text
        assert FINANCE not in caplog.text


async def test_the_same_adapter_delivers_change_approvals(world, tmp_path):  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    with SmtpServer(tmp_path / "smtp") as smtp:
        world.approvals._delivery = ApprovalEmailDelivery(
            mailer=mailer(smtp, tmp_path), approval_url=ENDPOINT
        )
        change = change_set(drafter=by_member(BOB), changes=[grant_role(BOB)])
        async with world.db.transaction() as tx:
            pending = await world.change_sets.draft(tx, change)
            assert smtp.received == []
        view = await world.approvals.deliver(pending)
        assert view.delivery_status is DeliveryStatus.DELIVERED
        [received] = smtp.received
        _, text, html, url = contents(received)
        assert received.rcpt_tos == ["alice@acme.com"]
        assert change["change_id"] not in text and change["change_id"] not in html
        [token] = parse_qs(urlsplit(url).fragment)["token"]
        assert (
            await world.approvals.open_link(token)
        ).approval.approval_id == pending.approval.approval_id


async def test_opaque_tokens_are_url_encoded_in_the_fragment_only(uses, tmp_path):  # noqa: F811
    await designate(uses, "finance", FINANCE)
    await install(uses)
    _, _, pending = await request(uses)
    candidate = pending.pending.deliveries[0].approver
    token = secrets.token_urlsafe(24) + '+/&="#?'
    with SmtpServer(tmp_path / "smtp") as smtp:
        delivery = ApprovalEmailDelivery(mailer=mailer(smtp, tmp_path), approval_url=ENDPOINT)
        assert (
            await delivery.deliver_approval_link(candidate, token, pending.pending.approval)
            is DeliveryStatus.DELIVERED
        )
        [received] = smtp.received
        _, _, _, url = contents(received)
        parts = urlsplit(url)
        assert parts._replace(fragment="").geturl() == ENDPOINT
        assert parse_qs(parts.fragment) == {"token": [token]}


@pytest.mark.parametrize(
    "endpoint",
    [
        "/approvals",
        "http://console.example/approvals",
        "https://user@console.example/approvals",
        f"{ENDPOINT}?token=ignored",
        f"{ENDPOINT}#ignored",
        "javascript:alert(1)",
    ],
)
def test_the_console_endpoint_is_validated_at_composition(endpoint):
    with pytest.raises(ValueError):
        ApprovalEmailDelivery(mailer=None, approval_url=endpoint)
