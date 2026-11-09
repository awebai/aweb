"""The generator of the public owner-act delivery vector
(docs/owner-act-delivery.md).

Every signed delivery case is built with ``owner_act_signing_bytes`` and a
synthetic team key, so the vector's bytes and signatures come from the same
code a signer uses. The manifest, credential and delivery outcomes are the
contract's expectations, written out case by case.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import cbor2
from awid.did import did_from_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, owner_act_signing_bytes
from aweb_naapp.hooks.strictjson import canonical, encode_signature

TEAM_SEED = bytes(range(0x21, 0x41))
ADMIN_SEED = bytes(range(0x41, 0x61))
TEAM_ID = "demo:example.com"
APP_ORIGIN = "https://logs.example.com"
CONSOLE_ORIGIN = "https://console.logs.example.com"
SECRETS_ORIGIN = "https://secrets.example.com"
SECRETS_CONSOLE = "https://console.secrets.example.com"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
SECRETS_INSTALLATION = "2c5f39cb-3fb2-4e4c-b4f6-f02ac6b8744c"
PRINCIPAL = "did:aw:2Zf4Lq8m3VYb9nKc5RjTs7Hd"
NOTICE_CONTACT = "owner@example.com"
OTHER_CONTACT = "someone-else@example.com"
ISSUED = "2026-11-07T12:00:00Z"
EXPIRES = "2026-11-07T12:05:00Z"
NOW = "2026-11-07T12:01:00Z"
REPLACEMENT_EFFECTIVE = "2026-11-10T12:01:00Z"  # the 72-hour cooling-off period
ACTS = sorted(HUMAN_ROLE_ACTS)
CREDENTIAL_PREFIX = b"aweb.human-credential/1\n"
LONGEST_NAME = "logs." + "r" * 59  # 64 bytes, owner-act/1's role bound


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def did_key(seed: bytes) -> str:
    return did_from_public_key(bytes(SigningKey(seed).verify_key))


def cose_key(scalar: int, *, with_private: bool = False) -> bytes:
    """A COSE EC2 P-256 key, as an authenticator registers it."""
    private = ec.derive_private_key(scalar, ec.SECP256R1())
    numbers = private.public_key().public_numbers()
    key: dict[int, Any] = {
        1: 2,
        3: -7,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    if with_private:
        key[-4] = private.private_numbers().private_value.to_bytes(32, "big")
    return cbor2.dumps(key, canonical=True)


def credential(rp_id: str, *, scalar: int = 0x1F2E3D4C, with_private: bool = False) -> dict:
    return {
        "credential_id": b64url(hashlib.sha256(f"credential {scalar}".encode()).digest()),
        "public_key": b64url(cose_key(scalar, with_private=with_private)),
        "rp_id": rp_id,
    }


def credential_sha256(value: dict[str, Any]) -> str:
    return hashlib.sha256(CREDENTIAL_PREFIX + canonical(value)).hexdigest()


def fingerprint(digest: str) -> str:
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


READER_CREDENTIAL = credential("console.logs.example.com")
OWNER_CREDENTIAL = credential("console.secrets.example.com", scalar=0x5A6B7C8D)
REPLACEMENT_CREDENTIAL = credential("console.secrets.example.com", scalar=0x0A0B0C0D)
SECURITY_KEY_CREDENTIAL = credential("aweb:", scalar=0x11223344)


def reader_role(**changes: Any) -> dict[str, Any]:
    role: dict[str, Any] = {
        "name": "logs.reader",
        "label": "Log reader",
        "description": "Reads the team's audit log in a passkey session on the console.",
        "acts": list(ACTS),
        "notice_contact": False,
    }
    role.update(changes)
    return role


def owner_role(**changes: Any) -> dict[str, Any]:
    role: dict[str, Any] = {
        "name": "secrets.owner",
        "label": "Secrets owner",
        "acts": list(ACTS),
        "notice_contact": True,
    }
    role.update(changes)
    return role


def without(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    return {k: v for k, v in mapping.items() if k != key}


def manifest_case(
    name: str, *, owner_acts: Any, app_origin: str = APP_ORIGIN, error: str | None = None
) -> dict[str, Any]:
    return {"name": name, "app_origin": app_origin, "owner_acts": owner_acts, "error": error}


def manifest_cases() -> list[dict[str, Any]]:
    logs = {"origin": CONSOLE_ORIGIN, "roles": [reader_role()]}
    secrets = {"origin": SECRETS_CONSOLE, "roles": [owner_role()]}

    def with_roles(*roles: dict[str, Any]) -> dict[str, Any]:
        return {"origin": CONSOLE_ORIGIN, "roles": list(roles)}

    def origin(value: str) -> dict[str, Any]:
        return {"origin": value, "roles": [reader_role()]}

    invalid = "owner_acts_invalid"
    return [
        manifest_case("logs_reader", owner_acts=logs),
        manifest_case("secrets_owner", owner_acts=secrets, app_origin=SECRETS_ORIGIN),
        manifest_case(
            "origin_shares_the_app_host", owner_acts=origin(APP_ORIGIN + ":8443"), error=invalid
        ),
        manifest_case(
            "origin_with_a_path", owner_acts=origin(CONSOLE_ORIGIN + "/console"), error=invalid
        ),
        manifest_case(
            "origin_with_a_trailing_slash", owner_acts=origin(CONSOLE_ORIGIN + "/"), error=invalid
        ),
        manifest_case(
            "origin_over_http",
            owner_acts=origin("http://console.logs.example.com"),
            error=invalid,
        ),
        manifest_case(
            "origin_with_an_upper_case_host",
            owner_acts=origin("https://Console.logs.example.com"),
            error=invalid,
        ),
        manifest_case("no_roles", owner_acts=with_roles(), error=invalid),
        manifest_case(
            "duplicate_role", owner_acts=with_roles(reader_role(), reader_role()), error=invalid
        ),
        manifest_case(
            "role_name_of_64_bytes", owner_acts=with_roles(reader_role(name=LONGEST_NAME))
        ),
        manifest_case(
            "role_name_of_65_bytes",
            owner_acts=with_roles(reader_role(name=LONGEST_NAME + "s")),
            error=invalid,
        ),
        manifest_case(
            "role_name_with_a_leading_digit",
            owner_acts=with_roles(reader_role(name="1logs.reader")),
            error=invalid,
        ),
        manifest_case(
            "role_name_of_one_segment",
            owner_acts=with_roles(reader_role(name="reader")),
            error=invalid,
        ),
        manifest_case(
            "a_subset_of_the_acts",
            owner_acts=with_roles(reader_role(acts=["human-role.designate", "human-role.revoke"])),
        ),
        manifest_case(
            "acts_out_of_order",
            owner_acts=with_roles(reader_role(acts=["human-role.revoke", "human-role.designate"])),
            error=invalid,
        ),
        manifest_case("no_acts", owner_acts=with_roles(reader_role(acts=[])), error=invalid),
        manifest_case(
            "a_contact_act",
            owner_acts=with_roles(reader_role(acts=["app-role.designate"])),
            error=invalid,
        ),
        manifest_case(
            "act_outside_the_app_vocabulary",
            owner_acts=with_roles(reader_role(acts=["hook-binding.activate"])),
            error=invalid,
        ),
        manifest_case(
            "no_notice_contact_member",
            owner_acts=with_roles(without(reader_role(), "notice_contact")),
            error=invalid,
        ),
        manifest_case(
            "notice_contact_not_a_boolean",
            owner_acts=with_roles(reader_role(notice_contact="false")),
            error=invalid,
        ),
        manifest_case(
            "a_principal_member",
            owner_acts=with_roles(reader_role(principal="required")),
            error=invalid,
        ),
        manifest_case(
            "a_prepare_tool_member",
            owner_acts=with_roles(reader_role(prepare_tool="owner-act-prepare")),
            error=invalid,
        ),
        manifest_case("owner_acts_null", owner_acts=None, error="manifest_invalid"),
    ]


def credential_cases() -> list[dict[str, Any]]:
    cases = []
    for name, value in (
        ("browser_passkey", READER_CREDENTIAL),
        ("browser_passkey_of_another_origin", OWNER_CREDENTIAL),
        ("security_key", SECURITY_KEY_CREDENTIAL),
    ):
        digest = credential_sha256(value)
        cases.append(
            {
                "name": name,
                "credential": value,
                "credential_sha256": digest,
                "fingerprint": fingerprint(digest),
            }
        )
    return cases


def signed(act: dict[str, Any], seed: bytes) -> tuple[str, str]:
    signing = owner_act_signing_bytes(act)
    signature = encode_signature(SigningKey(seed).sign(signing).signature)
    return base64.b64encode(signing).decode("ascii"), signature


def owner_act(name: str, aud: str, subject: dict[str, Any], *, seed: bytes = TEAM_SEED) -> dict:
    return {
        "v": 1,
        "type": "aweb.owner-act",
        "act": name,
        "team_id": TEAM_ID,
        "aud": aud,
        "team_key_did": did_key(seed),
        "subject": subject,
        "issued_at": ISSUED,
        "expires_at": EXPIRES,
        "nonce": "02020202020202020202020202020202",
    }


def holding(
    app_id: str,
    installation_id: str,
    role: str,
    value: dict[str, Any] | None = None,
    notice_contact: str | None = None,
) -> dict[str, Any]:
    """The subject of an act: with a credential for designate and replace, and
    a notice contact's hash when the role declares one."""
    subject: dict[str, Any] = {
        "app_id": app_id,
        "installation_id": installation_id,
        "role": role,
        "principal": PRINCIPAL,
    }
    if value is not None:
        subject["credential_sha256"] = credential_sha256(value)
    if notice_contact is not None:
        subject["notice_contact_sha256"] = sha256_hex(notice_contact)
    return subject


def expected_subject(act: dict[str, Any], body: dict[str, Any]) -> dict[str, Any] | None:
    """The subject the app builds from its own installation, the act's role and
    principal, and the body's credential and notice contact; None for an act
    outside the human-role acts, which names no principal."""
    if act["act"] not in ACTS:
        return None
    subject = act["subject"]
    return holding(
        subject["app_id"],
        subject["installation_id"],
        subject["role"],
        body.get("credential"),
        body.get("notice_contact"),
    )


def delivery_case(
    name: str,
    *,
    act: dict[str, Any],
    role: dict[str, Any],
    credential_value: dict[str, Any] | None = None,
    notice_contact: str | None = None,
    status: int,
    detail: str | None = None,
    response: dict[str, Any] | None = None,
    verifier_code: str | None = None,
    seed: bytes = TEAM_SEED,
    nonce_used: bool = False,
    registry: str = "available",
    principal_status: str = "member_human",
    holding_current: bool | None = None,
    security_key: bool = False,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signing, signature = signed(act, seed)
    if body is None:
        body = {"signing": signing, "signature": signature}
        if credential_value is not None:
            body["credential"] = credential_value
        if notice_contact is not None:
            body["notice_contact"] = notice_contact
    if holding_current is None:
        holding_current = act["act"] != "human-role.designate"
    app_id = act["subject"]["app_id"]
    return {
        "name": name,
        "app": {
            "app_id": app_id,
            "owner_acts_origin": CONSOLE_ORIGIN if app_id == "logs" else SECRETS_CONSOLE,
            "role": role,
            "security_key": security_key,
        },
        "verifier": {
            "team_id": TEAM_ID,
            "current_team_key_did": did_key(TEAM_SEED),
            "audience": CONSOLE_ORIGIN if app_id == "logs" else SECRETS_CONSOLE,
            "acts": ACTS,
            "now": NOW,
            "nonce_used": nonce_used,
            "registry": registry,
        },
        "state": {"holding": holding_current, "principal_status": principal_status},
        "act": act,
        "body": body,
        "expected_subject": expected_subject(act, body) if status != 400 else None,
        "verifier_code": verifier_code,
        "result": {"status": status, "detail": detail, "response": response},
    }


def accepted(act: dict[str, Any], effective_at: str = NOW) -> dict[str, Any]:
    return {
        "act": act["act"],
        "role": act["subject"]["role"],
        "principal": act["subject"]["principal"],
        "effective_at": effective_at,
    }


def delivery_cases() -> list[dict[str, Any]]:
    reader, owner = reader_role(), owner_role()
    reader_subject = holding("logs", INSTALLATION, "logs.reader", READER_CREDENTIAL)
    owner_subject = holding(
        "secrets", SECRETS_INSTALLATION, "secrets.owner", OWNER_CREDENTIAL, NOTICE_CONTACT
    )
    designate = owner_act("human-role.designate", CONSOLE_ORIGIN, reader_subject)
    designate_owner = owner_act("human-role.designate", SECRETS_CONSOLE, owner_subject)
    replace = owner_act(
        "human-credential.replace",
        SECRETS_CONSOLE,
        holding(
            "secrets",
            SECRETS_INSTALLATION,
            "secrets.owner",
            REPLACEMENT_CREDENTIAL,
            NOTICE_CONTACT,
        ),
    )
    revoke = owner_act(
        "human-role.revoke", CONSOLE_ORIGIN, holding("logs", INSTALLATION, "logs.reader")
    )
    security_key = owner_act(
        "human-role.designate",
        CONSOLE_ORIGIN,
        holding("logs", INSTALLATION, "logs.reader", SECURITY_KEY_CREDENTIAL),
    )
    other_host = credential("logs.example.com")
    with_private = credential("console.logs.example.com", with_private=True)
    padded = {**READER_CREDENTIAL, "credential_id": READER_CREDENTIAL["credential_id"] + "="}
    designate_signing, designate_signature = signed(designate, TEAM_SEED)
    contact_act = owner_act(
        "app-role.designate",
        CONSOLE_ORIGIN,
        {
            "app_id": "logs",
            "installation_id": INSTALLATION,
            "role": "logs.reader.00112233445566778899aabbccddeeff",
            "contact_sha256": sha256_hex(NOTICE_CONTACT),
        },
    )
    refused = {"status": 403, "detail": "owner_required"}
    return [
        delivery_case(
            "designate_a_reader",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            status=200,
            response=accepted(designate),
        ),
        delivery_case(
            "designate_an_owner_with_a_notice_contact",
            act=designate_owner,
            role=owner,
            credential_value=OWNER_CREDENTIAL,
            notice_contact=NOTICE_CONTACT,
            status=200,
            response=accepted(designate_owner),
        ),
        delivery_case(
            "replace_an_owner_credential_after_the_cooling_off_period",
            act=replace,
            role=owner,
            credential_value=REPLACEMENT_CREDENTIAL,
            notice_contact=NOTICE_CONTACT,
            status=200,
            response=accepted(replace, REPLACEMENT_EFFECTIVE),
        ),
        delivery_case(
            "revoke_a_reader", act=revoke, role=reader, status=200, response=accepted(revoke)
        ),
        delivery_case(
            "revoke_a_former_member",
            act=revoke,
            role=reader,
            principal_status="not_member",
            status=200,
            response=accepted(revoke),
        ),
        delivery_case(
            "revoke_while_the_principal_status_is_unavailable",
            act=revoke,
            role=reader,
            principal_status="unavailable",
            status=200,
            response=accepted(revoke),
        ),
        delivery_case(
            "security_key_where_the_app_enables_it",
            act=security_key,
            role=reader,
            credential_value=SECURITY_KEY_CREDENTIAL,
            security_key=True,
            status=200,
            response=accepted(security_key),
        ),
        delivery_case(
            "security_key_where_the_app_does_not_enable_it",
            act=security_key,
            role=reader,
            credential_value=SECURITY_KEY_CREDENTIAL,
            **refused,
        ),
        delivery_case(
            "credential_for_the_agent_host",
            act=owner_act(
                "human-role.designate",
                CONSOLE_ORIGIN,
                holding("logs", INSTALLATION, "logs.reader", other_host),
            ),
            role=reader,
            credential_value=other_host,
            **refused,
        ),
        delivery_case(
            "credential_with_a_private_key_parameter",
            act=owner_act(
                "human-role.designate",
                CONSOLE_ORIGIN,
                holding("logs", INSTALLATION, "logs.reader", with_private),
            ),
            role=reader,
            credential_value=with_private,
            **refused,
        ),
        delivery_case(
            "credential_that_does_not_match_the_act",
            act=designate,
            role=reader,
            credential_value=credential("console.logs.example.com", scalar=0x99),
            verifier_code="subject_mismatch",
            **refused,
        ),
        delivery_case(
            "notice_contact_that_does_not_match_the_act",
            act=designate_owner,
            role=owner,
            credential_value=OWNER_CREDENTIAL,
            notice_contact=OTHER_CONTACT,
            verifier_code="subject_mismatch",
            **refused,
        ),
        delivery_case(
            "principal_not_a_member",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            principal_status="not_member",
            status=403,
            detail="principal_not_member",
        ),
        delivery_case(
            "principal_not_human",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            principal_status="not_human",
            status=403,
            detail="principal_not_human",
        ),
        delivery_case(
            "principal_status_unavailable",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            principal_status="unavailable",
            status=503,
            detail="principal_status_unavailable",
        ),
        delivery_case(
            "designate_a_current_holder",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            holding_current=True,
            **refused,
        ),
        delivery_case(
            "replace_without_a_holding",
            act=replace,
            role=owner,
            credential_value=REPLACEMENT_CREDENTIAL,
            notice_contact=NOTICE_CONTACT,
            holding_current=False,
            **refused,
        ),
        delivery_case(
            "revoke_without_a_holding",
            act=revoke,
            role=reader,
            holding_current=False,
            **refused,
        ),
        delivery_case(
            "a_contact_act",
            act=contact_act,
            role=reader,
            verifier_code="act_not_allowed",
            **refused,
        ),
        delivery_case(
            "role_not_declared",
            act=designate,
            role=reader_role(name="logs.auditor"),
            credential_value=READER_CREDENTIAL,
            **refused,
        ),
        delivery_case(
            "act_not_declared_for_the_role",
            act=replace,
            role=owner_role(acts=["human-role.designate", "human-role.revoke"]),
            credential_value=REPLACEMENT_CREDENTIAL,
            notice_contact=NOTICE_CONTACT,
            **refused,
        ),
        delivery_case(
            "aud_is_the_agent_origin",
            act=owner_act("human-role.designate", APP_ORIGIN, reader_subject),
            role=reader,
            credential_value=READER_CREDENTIAL,
            verifier_code="audience_mismatch",
            **refused,
        ),
        delivery_case(
            "signed_by_an_admin_key",
            act=owner_act("human-role.designate", CONSOLE_ORIGIN, reader_subject, seed=ADMIN_SEED),
            seed=ADMIN_SEED,
            role=reader,
            credential_value=READER_CREDENTIAL,
            verifier_code="owner_required",
            **refused,
        ),
        delivery_case(
            "nonce_already_used",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            nonce_used=True,
            verifier_code="nonce_reused",
            **refused,
        ),
        delivery_case(
            "credential_on_revoke",
            act=revoke,
            role=reader,
            credential_value=READER_CREDENTIAL,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "no_credential_on_designate",
            act=designate,
            role=reader,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "notice_contact_for_a_role_that_declares_none",
            act=designate,
            role=reader,
            credential_value=READER_CREDENTIAL,
            notice_contact=NOTICE_CONTACT,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "no_notice_contact_for_a_role_that_declares_one",
            act=designate_owner,
            role=owner,
            credential_value=OWNER_CREDENTIAL,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "credential_id_with_padding",
            act=designate,
            role=reader,
            credential_value=padded,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "credential_with_another_field",
            act=designate,
            role=reader,
            credential_value={**READER_CREDENTIAL, "transports": "usb"},
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "a_field_outside_the_body",
            act=designate,
            role=reader,
            body={
                "signing": designate_signing,
                "signature": designate_signature,
                "credential": READER_CREDENTIAL,
                "team_id": TEAM_ID,
            },
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "signing_in_url_safe_base64_without_padding",
            act=designate,
            role=reader,
            body={
                "signing": b64url(owner_act_signing_bytes(designate)),
                "signature": designate_signature,
                "credential": READER_CREDENTIAL,
            },
            status=400,
            detail="request_invalid",
        ),
        *forged_signature_pairs(designate, reader),
    ]


def forged_signature_pairs(act: dict[str, Any], role: dict[str, Any]) -> list[dict[str, Any]]:
    """An act claiming the team key but signed by another key, with and
    without a current holding, with the registry readable and not: the holding
    never changes the answer."""
    cases = []
    for registry, status, detail, code in (
        ("available", 403, "owner_required", "bad_signature"),
        ("unavailable", 503, "team_key_unavailable", None),
    ):
        for label, current in (("with_a_holding", True), ("without_a_holding", False)):
            cases.append(
                delivery_case(
                    f"forged_signature_{label}_registry_{registry}",
                    act=act,
                    seed=ADMIN_SEED,
                    role=role,
                    credential_value=READER_CREDENTIAL,
                    registry=registry,
                    holding_current=current,
                    status=status,
                    detail=detail,
                    verifier_code=code,
                )
            )
    return cases


def role_cases() -> list[dict[str, Any]]:
    return [
        {"name": "reader", "role": "logs.reader", "valid": True},
        {"name": "owner", "role": "secrets.owner", "valid": True},
        {"name": "longest_name", "role": LONGEST_NAME, "valid": True},
        {"name": "name_one_byte_too_long", "role": LONGEST_NAME + "s", "valid": False},
        {"name": "leading_digit", "role": "1logs.reader", "valid": False},
    ]


def build_vector() -> dict[str, Any]:
    return {
        "name": "owner-act-delivery",
        "version": 1,
        "status": "specified (aweb-acgh.16.38, aweb-acwd.4.1); not shipped",
        "scheme": {
            "authority": "docs/owner-act-delivery.md",
            "manifest": "manifest_cases: a version 3 manifest's owner_acts; error is the manifest refusal code, or null when it is valid",
            "credential": "credential_cases: credential_sha256 is the lowercase hex SHA-256 of 'aweb.human-credential/1' and a newline, then the credential's canonical JSON; fingerprint is its first 16 hex characters in groups of four",
            "delivery": "delivery_cases: a delivery body to the app's human origin; app is the app's declaration and whether it enables the optional security key; state is whether (installation, role, principal) has a current holding and what the registry reports for the principal (member_human, not_member, not_human, unavailable); expected_subject is the subject the app builds, null when the body is refused before it; verifier_code is the owner-act/1 refusal behind a 403, or null when the act verifies; result is the HTTP status, detail and response",
            "signing": "standard base64 with padding of the owner-act/1 signing bytes",
            "role": "role_cases pin the declared role name, which is the act's role, against the owner-act/1 signer: a leading letter, at most 64 bytes",
            "registry": "delivery_cases' verifier.registry says whether stage 2 can read the team key; the forged_signature cases pair a present and an absent holding under each, and the pair's results are equal",
        },
        "manifest_cases": manifest_cases(),
        "credential_cases": credential_cases(),
        "delivery_cases": delivery_cases(),
        "role_cases": role_cases(),
    }


def render(vector: dict[str, Any]) -> bytes:
    return (json.dumps(vector, indent=2, sort_keys=True) + "\n").encode("ascii")
