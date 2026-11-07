"""The generator of the public owner-act delivery vector
(docs/owner-act-delivery.md).

Every signed delivery case is built with ``owner_act_signing_bytes`` and a
synthetic team key, so the vector's bytes and signatures come from the same
code a signer uses. The manifest, prepare and client-check cases are the
contract's expectations, written out case by case.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_naapp.hooks.owner_act import owner_act_signing_bytes
from aweb_naapp.hooks.strictjson import encode_signature

TEAM_SEED = bytes(range(0x21, 0x41))
ADMIN_SEED = bytes(range(0x41, 0x61))
TEAM_ID = "demo:example.com"
APP_ORIGIN = "https://logs.example.com"
CONSOLE_ORIGIN = "https://console.logs.example.com"
SECRETS_ORIGIN = "https://secrets.example.com"
SECRETS_CONSOLE = "https://console.secrets.example.com"
INSTALLATION = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b"
SECRETS_INSTALLATION = "2c5f39cb-3fb2-4e4c-b4f6-f02ac6b8744c"
READER_TOKEN = "logs.reader.00112233445566778899aabbccddeeff"
OWNER_TOKEN = "secrets.owner.0123456789abcdef0123456789abcdef01234567"
PRINCIPAL = "did:aw:2Zf4Lq8m3VYb9nKc5RjTs7Hd"
HOLDER_REF = "b3:subject:7f3e9a1c"
CONTACT = "reader@example.com"
OTHER_CONTACT = "someone-else@example.com"
OWNER_CONTACT = "owner@example.com"
ISSUED = "2026-11-07T12:00:00Z"
EXPIRES = "2026-11-07T12:05:00Z"
NOW = "2026-11-07T12:01:00Z"
APP_ACTS = ["app-credential.recover", "app-role.designate", "app-role.revoke"]
PREPARE_PARAMS = ["act", "role", "contact_sha256", "principal", "holder"]
LONGEST_NAME = "logs.readers-of-records"  # 23 bytes: with a dot and 40 hex, 64


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def did_key(seed: bytes) -> str:
    return did_from_public_key(bytes(SigningKey(seed).verify_key))


def prepare_tool(**changes: Any) -> dict[str, Any]:
    tool: dict[str, Any] = {
        "name": "owner-act-prepare",
        "method": "POST",
        "path": "/v1/owner-act-subjects",
        "invocation_contexts": ["agent"],
        "body": {"mode": "json"},
        "params": [{"in": "body", "name": name} for name in PREPARE_PARAMS],
        "scopes": ["logs.readers"],
    }
    tool.update(changes)
    return tool


def reader_role(**changes: Any) -> dict[str, Any]:
    role: dict[str, Any] = {
        "name": "logs.reader",
        "label": "Log reader",
        "description": "Reads the team's audit log in a passkey session on the console.",
        "acts": list(APP_ACTS),
        "principal": "refused",
        "prepare_tool": "owner-act-prepare",
    }
    role.update(changes)
    return role


def owner_role(**changes: Any) -> dict[str, Any]:
    role: dict[str, Any] = {
        "name": "secrets.owner",
        "label": "Secrets owner",
        "acts": list(APP_ACTS),
        "principal": "required",
        "prepare_tool": "owner-act-prepare",
    }
    role.update(changes)
    return role


def manifest_case(
    name: str,
    *,
    owner_acts: Any,
    tools: list[dict[str, Any]] | None = None,
    app_origin: str = APP_ORIGIN,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "app_origin": app_origin,
        "tools": [prepare_tool()] if tools is None else tools,
        "owner_acts": owner_acts,
        "error": error,
    }


def manifest_cases() -> list[dict[str, Any]]:
    logs = {"origin": CONSOLE_ORIGIN, "roles": [reader_role()]}
    secrets_tool = prepare_tool(scopes=["secrets:owner-act"])
    secrets = {"origin": SECRETS_CONSOLE, "roles": [owner_role()]}

    def with_roles(*roles: dict[str, Any]) -> dict[str, Any]:
        return {"origin": CONSOLE_ORIGIN, "roles": list(roles)}

    return [
        manifest_case("logs_reader", owner_acts=logs),
        manifest_case(
            "secrets_owner", owner_acts=secrets, tools=[secrets_tool], app_origin=SECRETS_ORIGIN
        ),
        manifest_case(
            "origin_shares_the_app_host",
            owner_acts={"origin": "https://logs.example.com:8443", "roles": [reader_role()]},
            error="owner_acts_invalid",
        ),
        manifest_case(
            "origin_with_a_path",
            owner_acts={"origin": CONSOLE_ORIGIN + "/console", "roles": [reader_role()]},
            error="owner_acts_invalid",
        ),
        manifest_case(
            "origin_with_a_trailing_slash",
            owner_acts={"origin": CONSOLE_ORIGIN + "/", "roles": [reader_role()]},
            error="owner_acts_invalid",
        ),
        manifest_case(
            "origin_over_http",
            owner_acts={"origin": "http://console.logs.example.com", "roles": [reader_role()]},
            error="owner_acts_invalid",
        ),
        manifest_case(
            "origin_with_an_upper_case_host",
            owner_acts={"origin": "https://Console.logs.example.com", "roles": [reader_role()]},
            error="owner_acts_invalid",
        ),
        manifest_case("no_roles", owner_acts=with_roles(), error="owner_acts_invalid"),
        manifest_case(
            "duplicate_role",
            owner_acts=with_roles(reader_role(), reader_role()),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "role_name_of_23_bytes",
            owner_acts=with_roles(reader_role(name=LONGEST_NAME)),
        ),
        manifest_case(
            "role_name_of_24_bytes",
            owner_acts=with_roles(reader_role(name=LONGEST_NAME + "s")),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "role_name_with_a_leading_digit",
            owner_acts=with_roles(reader_role(name="1logs.reader")),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "role_name_of_one_segment",
            owner_acts=with_roles(reader_role(name="reader")),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "acts_out_of_order",
            owner_acts=with_roles(
                reader_role(acts=["app-role.designate", "app-credential.recover"])
            ),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "act_outside_the_app_vocabulary",
            owner_acts=with_roles(reader_role(acts=["hook-binding.activate"])),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "principal_neither_required_nor_refused",
            owner_acts=with_roles(reader_role(principal="optional")),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "prepare_tool_not_declared",
            owner_acts=with_roles(reader_role(prepare_tool="reader-slot")),
            error="owner_acts_invalid",
        ),
        manifest_case(
            "prepare_tool_also_a_surface_tool",
            owner_acts=logs,
            tools=[prepare_tool(invocation_contexts=["agent", "surface"])],
            error="owner_acts_invalid",
        ),
        manifest_case(
            "prepare_tool_is_a_get",
            owner_acts=logs,
            tools=[prepare_tool(method="GET")],
            error="owner_acts_invalid",
        ),
        manifest_case(
            "prepare_tool_params_differ",
            owner_acts=logs,
            tools=[
                prepare_tool(
                    params=[{"in": "body", "name": name} for name in ["act", "role", "contact"]]
                )
            ],
            error="owner_acts_invalid",
        ),
        manifest_case("owner_acts_null", owner_acts=None, error="manifest_invalid"),
    ]


def prepare_case(
    name: str, role: dict[str, Any], body: dict[str, Any], error: str | None = None
) -> dict[str, Any]:
    return {"name": name, "role": role, "body": body, "error": error}


def prepare_cases() -> list[dict[str, Any]]:
    reader = reader_role()
    owner = owner_role()
    designate = {
        "act": "app-role.designate",
        "role": "logs.reader",
        "contact_sha256": sha256_hex(CONTACT),
    }
    owner_designate = {
        "act": "app-role.designate",
        "role": "secrets.owner",
        "contact_sha256": sha256_hex(OWNER_CONTACT),
        "principal": PRINCIPAL,
    }
    revoke = {"act": "app-role.revoke", "role": "logs.reader", "holder": READER_TOKEN}
    return [
        prepare_case("designate_a_reader", reader, designate),
        prepare_case(
            "recover_a_reader",
            reader,
            {**designate, "act": "app-credential.recover", "holder": READER_TOKEN},
        ),
        prepare_case("revoke_a_reader", reader, revoke),
        prepare_case("designate_an_owner", owner, owner_designate),
        prepare_case(
            "recover_an_owner", owner, {**owner_designate, "act": "app-credential.recover"}
        ),
        prepare_case(
            "revoke_an_owner",
            owner,
            {"act": "app-role.revoke", "role": "secrets.owner", "principal": PRINCIPAL},
        ),
        prepare_case(
            "contact_on_revoke",
            reader,
            {**revoke, "contact_sha256": sha256_hex(CONTACT)},
            "request_invalid",
        ),
        prepare_case(
            "principal_for_a_role_that_refuses_one",
            reader,
            {**designate, "principal": PRINCIPAL},
            "request_invalid",
        ),
        prepare_case(
            "no_principal_for_a_role_that_requires_one",
            owner,
            {k: v for k, v in owner_designate.items() if k != "principal"},
            "request_invalid",
        ),
        prepare_case(
            "holder_on_designate", reader, {**designate, "holder": READER_TOKEN}, "request_invalid"
        ),
        prepare_case(
            "holder_for_a_principal_role",
            owner,
            {"act": "app-role.revoke", "role": "secrets.owner", "holder": OWNER_TOKEN},
            "request_invalid",
        ),
        prepare_case(
            "act_not_declared_for_the_role",
            reader_role(acts=["app-role.designate"]),
            revoke,
            "request_invalid",
        ),
        prepare_case(
            "role_not_declared", reader, {**designate, "role": "logs.writer"}, "request_invalid"
        ),
        prepare_case("null_field", reader, {**designate, "principal": None}, "request_invalid"),
        prepare_case(
            "contact_hash_in_upper_case",
            reader,
            {**designate, "contact_sha256": sha256_hex(CONTACT).upper()},
            "request_invalid",
        ),
    ]


def client_case(
    name: str,
    response: dict[str, Any],
    *,
    request: dict[str, Any] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "declared": {
            "app_id": "logs",
            "owner_acts_origin": CONSOLE_ORIGIN,
            "role": reader_role(),
        },
        "installation_id": INSTALLATION,
        "typed_contact": CONTACT,
        "request": request
        or {
            "act": "app-role.designate",
            "role": "logs.reader",
            "contact_sha256": sha256_hex(CONTACT),
        },
        "response": response,
        "error": error,
    }


def client_cases() -> list[dict[str, Any]]:
    good = {
        "act": "app-role.designate",
        "aud": CONSOLE_ORIGIN,
        "subject": {
            "app_id": "logs",
            "installation_id": INSTALLATION,
            "role": READER_TOKEN,
            "contact_sha256": sha256_hex(CONTACT),
        },
        "expires_at": "2026-11-07T13:00:00Z",
    }

    def changed(path: str, value: Any) -> dict[str, Any]:
        response = copy.deepcopy(good)
        target = response
        *parents, leaf = path.split(".")
        for parent in parents:
            target = target[parent]
        target[leaf] = value
        return response

    revoke_request = {"act": "app-role.revoke", "role": "logs.reader", "holder": READER_TOKEN}
    revoke = {
        "act": "app-role.revoke",
        "aud": CONSOLE_ORIGIN,
        "subject": {
            "app_id": "logs",
            "installation_id": INSTALLATION,
            "role": READER_TOKEN,
            "subject_ref": HOLDER_REF,
        },
        "expires_at": "2026-11-07T13:00:00Z",
    }
    other_holder = copy.deepcopy(revoke)
    other_holder["subject"]["role"] = "logs.reader.ffeeddccbbaa99887766554433221100"
    return [
        client_case("accepted", good),
        client_case("revoke_accepted", revoke, request=revoke_request),
        client_case(
            "aud_is_the_agent_origin", changed("aud", APP_ORIGIN), error="prepare_mismatch"
        ),
        client_case(
            "another_act", changed("act", "app-credential.recover"), error="prepare_mismatch"
        ),
        client_case("another_app", changed("subject.app_id", "secrets"), error="prepare_mismatch"),
        client_case(
            "another_installation",
            changed("subject.installation_id", SECRETS_INSTALLATION),
            error="prepare_mismatch",
        ),
        client_case(
            "token_of_another_role", changed("subject.role", OWNER_TOKEN), error="prepare_mismatch"
        ),
        client_case(
            "token_suffix_of_31_hex",
            changed("subject.role", READER_TOKEN[:-1]),
            error="prepare_mismatch",
        ),
        client_case(
            "contact_hash_of_another_contact",
            changed("subject.contact_sha256", sha256_hex(OTHER_CONTACT)),
            error="prepare_mismatch",
        ),
        client_case(
            "designation_naming_a_subject",
            changed("subject.subject_ref", HOLDER_REF),
            error="prepare_mismatch",
        ),
        client_case(
            "revoke_of_another_holder",
            other_holder,
            request=revoke_request,
            error="prepare_mismatch",
        ),
    ]


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


def delivery_case(
    name: str,
    *,
    act: dict[str, Any],
    row: dict[str, Any] | None,
    contact: str | None,
    status: int,
    detail: str | None = None,
    response: dict[str, Any] | None = None,
    verifier_code: str | None = None,
    seed: bytes = TEAM_SEED,
    nonce_used: bool = False,
    registry: str = "available",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signing, signature = signed(act, seed)
    if body is None:
        body = {"signing": signing, "signature": signature}
        if contact is not None:
            body["contact"] = contact
    return {
        "name": name,
        "verifier": {
            "team_id": TEAM_ID,
            "current_team_key_did": did_key(TEAM_SEED),
            "audience": CONSOLE_ORIGIN if act["subject"]["app_id"] == "logs" else SECRETS_CONSOLE,
            "acts": APP_ACTS,
            "now": NOW,
            "nonce_used": nonce_used,
            "registry": registry,
        },
        "row": row,
        "act": act,
        "body": body,
        "verifier_code": verifier_code,
        "result": {"status": status, "detail": detail, "response": response},
    }


def delivery_cases() -> list[dict[str, Any]]:
    reader = {
        "app_id": "logs",
        "installation_id": INSTALLATION,
        "role": READER_TOKEN,
        "contact_sha256": sha256_hex(CONTACT),
    }
    holder = {
        "app_id": "logs",
        "installation_id": INSTALLATION,
        "role": READER_TOKEN,
        "subject_ref": HOLDER_REF,
    }
    owner = {
        "app_id": "secrets",
        "installation_id": SECRETS_INSTALLATION,
        "role": OWNER_TOKEN,
        "contact_sha256": sha256_hex(OWNER_CONTACT),
    }
    designate = owner_act("app-role.designate", CONSOLE_ORIGIN, reader)
    revoke = owner_act("app-role.revoke", CONSOLE_ORIGIN, holder)
    recover = owner_act("app-credential.recover", SECRETS_CONSOLE, owner)
    designate_signing, designate_signature = signed(designate, TEAM_SEED)
    return [
        delivery_case(
            "designate_a_reader",
            act=designate,
            row=reader,
            contact=CONTACT,
            status=200,
            response={"act": "app-role.designate", "role": READER_TOKEN, "effective_at": NOW},
        ),
        delivery_case(
            "revoke_a_reader",
            act=revoke,
            row=holder,
            contact=None,
            status=200,
            response={"act": "app-role.revoke", "role": READER_TOKEN, "effective_at": NOW},
        ),
        delivery_case(
            "recover_an_owner_after_the_cooling_off_period",
            act=recover,
            row=owner,
            contact=OWNER_CONTACT,
            status=200,
            response={
                "act": "app-credential.recover",
                "role": OWNER_TOKEN,
                "effective_at": "2026-11-10T12:01:00Z",
            },
        ),
        delivery_case(
            "aud_is_the_agent_origin",
            act=owner_act("app-role.designate", APP_ORIGIN, reader),
            row=reader,
            contact=CONTACT,
            status=403,
            detail="owner_required",
            verifier_code="audience_mismatch",
        ),
        delivery_case(
            "signed_by_an_admin_key",
            act=owner_act("app-role.designate", CONSOLE_ORIGIN, reader, seed=ADMIN_SEED),
            seed=ADMIN_SEED,
            row=reader,
            contact=CONTACT,
            status=403,
            detail="owner_required",
            verifier_code="owner_required",
        ),
        delivery_case(
            "nonce_already_used",
            act=designate,
            row=reader,
            contact=CONTACT,
            nonce_used=True,
            status=403,
            detail="owner_required",
            verifier_code="nonce_reused",
        ),
        delivery_case(
            "row_for_another_contact",
            act=owner_act(
                "app-role.designate",
                CONSOLE_ORIGIN,
                {**reader, "contact_sha256": sha256_hex(OTHER_CONTACT)},
            ),
            row=reader,
            contact=CONTACT,
            status=403,
            detail="owner_required",
            verifier_code="subject_mismatch",
        ),
        delivery_case(
            "contact_that_does_not_match_the_row",
            act=designate,
            row=reader,
            contact=OTHER_CONTACT,
            status=403,
            detail="owner_required",
        ),
        delivery_case(
            "no_pending_row",
            act=designate,
            row=None,
            contact=CONTACT,
            status=403,
            detail="owner_required",
        ),
        delivery_case(
            "contact_on_revoke",
            act=revoke,
            row=holder,
            contact=CONTACT,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "no_contact_on_designate",
            act=designate,
            row=reader,
            contact=None,
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "a_field_outside_the_body",
            act=designate,
            row=reader,
            contact=CONTACT,
            body={
                "signing": designate_signing,
                "signature": designate_signature,
                "contact": CONTACT,
                "team_id": TEAM_ID,
            },
            status=400,
            detail="request_invalid",
        ),
        delivery_case(
            "signing_in_url_safe_base64_without_padding",
            act=designate,
            row=reader,
            contact=CONTACT,
            body={
                "signing": base64.urlsafe_b64encode(owner_act_signing_bytes(designate))
                .decode("ascii")
                .rstrip("="),
                "signature": designate_signature,
                "contact": CONTACT,
            },
            status=400,
            detail="request_invalid",
        ),
        *forged_signature_pairs(designate, reader),
    ]


def forged_signature_pairs(act: dict[str, Any], row: dict[str, Any]) -> list[dict[str, Any]]:
    """An act claiming the team key but signed by another key, with and
    without the app's row, with the registry readable and not: the row never
    changes the answer."""
    cases = []
    for registry, status, detail, code in (
        ("available", 403, "owner_required", "bad_signature"),
        ("unavailable", 503, "team_key_unavailable", None),
    ):
        for label, present in (("with_a_row", row), ("without_a_row", None)):
            cases.append(
                delivery_case(
                    f"forged_signature_{label}_registry_{registry}",
                    act=act,
                    seed=ADMIN_SEED,
                    row=present,
                    contact=CONTACT,
                    registry=registry,
                    status=status,
                    detail=detail,
                    verifier_code=code,
                )
            )
    return cases


def token_cases() -> list[dict[str, Any]]:
    hex40 = "0123456789abcdef0123456789abcdef01234567"
    return [
        {"name": "reader_token", "token": READER_TOKEN, "valid": True},
        {"name": "owner_token", "token": OWNER_TOKEN, "valid": True},
        {"name": "longest_name_and_suffix", "token": f"{LONGEST_NAME}.{hex40}", "valid": True},
        {"name": "name_one_byte_too_long", "token": f"{LONGEST_NAME}s.{hex40}", "valid": False},
        {"name": "leading_digit", "token": f"1logs.reader.{hex40}", "valid": False},
    ]


def build_vector() -> dict[str, Any]:
    return {
        "name": "owner-act-delivery",
        "version": 1,
        "status": "specified (aweb-acgh.16.38); not shipped",
        "scheme": {
            "authority": "docs/owner-act-delivery.md",
            "manifest": "manifest_cases: a version 3 manifest's owner_acts with the tools it names; error is the manifest refusal code, or null when it is valid",
            "prepare": "prepare_cases: the app's reading of a prepare body against the declared role; error is the 400 detail, or null when it records or reads a row",
            "client": "client_cases: the client's checks of a prepare response before it shows the owner anything; error is the local refusal code, or null when it may sign",
            "delivery": "delivery_cases: a delivery body against the app's own row (null when it has none); verifier_code is the owner-act/1 refusal behind a 403, or null when the act verifies; result is the HTTP status, detail and response",
            "signing": "standard base64 with padding of the owner-act/1 signing bytes",
            "role_token": "the declared role name (a leading letter, at most 23 bytes), a dot, and 32 to 40 lowercase hex characters; token_cases pin the bound against the owner-act/1 signer",
            "registry": "delivery_cases' verifier.registry says whether stage 2 can read the team key; the forged_signature cases pair a present and an absent row under each, and the pair's results are equal",
        },
        "manifest_cases": manifest_cases(),
        "prepare_cases": prepare_cases(),
        "client_cases": client_cases(),
        "delivery_cases": delivery_cases(),
        "token_cases": token_cases(),
    }


def render(vector: dict[str, Any]) -> bytes:
    return (json.dumps(vector, indent=2, sort_keys=True) + "\n").encode("ascii")
