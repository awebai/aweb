"""Write docs/vectors/team-certificate-verification-v1.json.

The cases are built from fixed seeds, so the file is the same on every run.
Run from the repository root with awid's environment:

    uv run --project awid python scripts/generate_team_certificate_vectors.py
    uv run --project awid python scripts/generate_team_certificate_vectors.py --check
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from awid.did import did_from_public_key
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

VECTOR = Path(__file__).resolve().parents[1] / "docs/vectors/team-certificate-verification-v1.json"
TEAM_ID = "backend:acme.com"

# What a verifier answers for a certificate it refuses. `None` is acceptance.
# `invalid_field` names a required field that is absent, empty or of the wrong
# type, from the certificate's own schema and never from what was presented. `bad_signature` is a signature that is present and
# does not verify under the team key the registry holds.
REASONS = [
    "malformed",
    "unsupported_version",
    "invalid_field",
    "member_key_mismatch",
    "bad_signature",
    "revoked",
    "unregistered",
]


def _key(name: str) -> dict[str, str]:
    seed = (name.encode() * 32)[:32]
    signing = SigningKey(seed)
    return {"seed_hex": seed.hex(), "did_key": did_from_public_key(bytes(signing.verify_key))}


KEYS = {name: _key(name) for name in ("team", "member", "another-team", "another-member")}


def _certificate(*, signed_by: str = "team", drop: tuple[str, ...] = (), **fields) -> dict:
    cert = {
        "version": 1,
        "certificate_id": "cert-001",
        "team_id": TEAM_ID,
        "team_did_key": KEYS["team"]["did_key"],
        "member_did_key": KEYS["member"]["did_key"],
        "member_did_aw": "",
        "member_address": "",
        "alias": "alice",
        "identity_scope": "global",
        "issued_at": "2026-11-01T00:00:00+00:00",
    }
    cert.update(fields)
    for name in drop:
        del cert[name]
    cert["signature"] = sign_message(bytes.fromhex(KEYS[signed_by]["seed_hex"]), canonical_json_bytes(cert))
    return cert


def _header(cert: object) -> str:
    return base64.b64encode(json.dumps(cert).encode()).decode()


def _tampered() -> dict:
    cert = _certificate()
    cert["alias"] = "mallory"
    return cert


def _unsigned() -> dict:
    cert = _certificate()
    del cert["signature"]
    return cert


def _case(name: str, about: str, header: str, expected: str | None, today: dict[str, str], **context) -> dict:
    reason, _, field = (expected or "").partition(":")
    assert expected is None or reason in REASONS, expected
    assert bool(field) == (reason == "invalid_field"), expected
    verdict = None if expected is None else {"reason": reason, **({"field": field} if field else {})}
    return {
        "name": name,
        "about": about,
        "certificate_header": header,
        "request_did_key": context.get("request_did_key", KEYS["member"]["did_key"]),
        "team_did_key": context.get("team_did_key", KEYS["team"]["did_key"]),
        "revoked_certificate_ids": context.get("revoked", []),
        "registered_certificate_ids": context.get("registered", ["cert-001"]),
        "expected": verdict,
        "today": today,
    }


ACCEPTED = {"awid": "accepted", "server": "accepted"}


def cases() -> list[dict]:
    refused = lambda awid, server: {"awid": awid, "server": server}
    return [
        _case("valid", "A current member certificate.", _header(_certificate()), None, ACCEPTED),
        _case(
            "valid_issued_long_ago",
            "Revocation is the only end of a certificate: none expires, and issued_at bounds nothing "
            "(docs/trust-model.md, owner decision 2026-08-17).",
            _header(_certificate(issued_at="2020-01-01T00:00:00+00:00")),
            None,
            ACCEPTED,
        ),
        *[
            _case(
                f"{name}_absent",
                f"{name} is not a required field: a certificate without it is accepted.",
                _header(_certificate(drop=(name,))),
                None,
                ACCEPTED,
            )
            for name in ("team_did_key", "identity_scope", "issued_at", "member_did_aw", "member_address")
        ],
        _case(
            "extra_signed_field",
            "A member the verifier does not know is signed with the rest, not injected: the certificate is accepted.",
            _header(_certificate(lifetime="persistent", note="from a later issuer")),
            None,
            ACCEPTED,
        ),
        _case("not_base64", "The header is not base64.", "%%%not-base64%%%", "malformed", refused("malformed", "refused")),
        _case("not_json", "The header decodes to text that is not JSON.", base64.b64encode(b"not json").decode(), "malformed", refused("malformed", "refused")),
        _case("not_an_object", "The header decodes to a JSON list.", _header([1, 2]), "malformed", refused("malformed", "refused")),
        _case(
            "oversized_header",
            "A correctly signed certificate whose header is longer than 8192 bytes.",
            _header(_certificate(note="x" * 9000)),
            "malformed",
            refused("malformed", "refused"),
        ),
        _case("version_2", "A version this verifier does not know.", _header(_certificate(version=2)), "unsupported_version", refused("accepted", "refused")),
        _case("version_string", 'version is the string "1".', _header(_certificate(version="1")), "unsupported_version", refused("accepted", "refused")),
        _case("version_true", "version is true, which equals 1 in some languages.", _header(_certificate(version=True)), "unsupported_version", refused("accepted", "accepted")),
        _case("version_absent", "No version.", _header(_certificate(drop=("version",))), "invalid_field:version", refused("accepted", "refused")),
        _case("alias_absent", "No alias.", _header(_certificate(drop=("alias",))), "invalid_field:alias", refused("accepted", "accepted")),
        _case("alias_empty", "An empty alias.", _header(_certificate(alias="")), "invalid_field:alias", refused("accepted", "accepted")),
        _case("alias_not_a_string", "alias is a number.", _header(_certificate(alias=7)), "invalid_field:alias", refused("accepted", "accepted")),
        _case("certificate_id_absent", "No certificate_id.", _header(_certificate(drop=("certificate_id",))), "invalid_field:certificate_id", refused("accepted", "refused")),
        _case("team_id_absent", "No team_id.", _header(_certificate(drop=("team_id",))), "invalid_field:team_id", refused("accepted", "refused")),
        _case("member_did_key_absent", "No member_did_key.", _header(_certificate(drop=("member_did_key",))), "invalid_field:member_did_key", refused("accepted", "refused")),
        _case(
            "member_key_mismatch",
            "The request is signed by a key the certificate does not name.",
            _header(_certificate()),
            "member_key_mismatch",
            refused("accepted", "refused"),
            request_did_key=KEYS["another-member"]["did_key"],
        ),
        _case("signature_absent", "No signature.", _header(_unsigned()), "invalid_field:signature", refused("missing_signature", "refused")),
        _case("signature_tampered", "A field was changed after signing.", _header(_tampered()), "bad_signature", refused("bad_signature", "refused")),
        _case(
            "signed_by_another_key",
            "Signed by a key that is not the team's current key at the registry.",
            _header(_certificate(signed_by="another-team")),
            "bad_signature",
            refused("bad_signature", "refused"),
        ),
        _case("revoked", "The registry lists the certificate as revoked.", _header(_certificate()), "revoked", refused("accepted", "refused"), revoked=["cert-001"]),
        _case(
            "unregistered",
            "A correctly signed certificate the registry never published.",
            _header(_certificate()),
            "unregistered",
            refused("accepted", "accepted"),
            registered=["cert-other"],
        ),
    ]


# What the naapp runtime verifier answers today for each case.
NAAPP_RUNTIME_TODAY = {
    "valid": "accepted",
    "team_did_key_absent": "accepted",
    "identity_scope_absent": "accepted",
    "issued_at_absent": "accepted",
    "member_did_aw_absent": "accepted",
    "member_address_absent": "accepted",
    "extra_signed_field": "accepted",
    "valid_issued_long_ago": "accepted",
    "not_base64": "refused",
    "not_json": "refused",
    "not_an_object": "refused",
    "oversized_header": "refused",
    "version_2": "accepted",
    "version_string": "accepted",
    "version_true": "accepted",
    "version_absent": "accepted",
    "alias_absent": "refused",
    "alias_empty": "refused",
    "alias_not_a_string": "accepted",
    "certificate_id_absent": "refused",
    "team_id_absent": "refused",
    "member_did_key_absent": "refused",
    "member_key_mismatch": "refused",
    "signature_absent": "refused",
    "signature_tampered": "refused",
    "signed_by_another_key": "refused",
    "revoked": "refused",
    "unregistered": "refused",
}


# What the library's own verifier answers today for each case.
LIBRARY_TODAY = {
    **NAAPP_RUNTIME_TODAY,
    "oversized_header": "accepted",
    "unregistered": "accepted",
}

# What the hook delivery receiver answers today: acceptance, or its refusal code.
# It leaves revocation to its caller and compares the certificate with the
# delivery's producer where the others compare it with the request's signer.
HOOKS_TODAY = {
    "valid": "accepted",
    "team_did_key_absent": "certificate_invalid",
    "identity_scope_absent": "accepted",
    "issued_at_absent": "accepted",
    "member_did_aw_absent": "accepted",
    "member_address_absent": "accepted",
    "extra_signed_field": "accepted",
    "valid_issued_long_ago": "accepted",
    "not_base64": "certificate_invalid",
    "not_json": "certificate_invalid",
    "not_an_object": "certificate_invalid",
    "oversized_header": "certificate_invalid",
    "version_2": "accepted",
    "version_string": "accepted",
    "version_true": "accepted",
    "version_absent": "accepted",
    "alias_absent": "accepted",
    "alias_empty": "accepted",
    "alias_not_a_string": "accepted",
    "certificate_id_absent": "certificate_mismatch",
    "team_id_absent": "certificate_mismatch",
    "member_did_key_absent": "certificate_mismatch",
    "member_key_mismatch": "certificate_mismatch",
    "signature_absent": "certificate_invalid",
    "signature_tampered": "certificate_invalid",
    "signed_by_another_key": "certificate_invalid",
    "revoked": "accepted",
    "unregistered": "accepted",
}


def document() -> str:
    doc = {
        "version": 1,
        "description": (
            "Verification of one team certificate, apart from the request that carries it: the header's shape, "
            "the certificate's fields, its binding to the request's signer, its signature under the team key the "
            "registry holds, and its standing at the registry. `expected` is the verdict every verifier is to "
            "give: null for acceptance, or a `reason` from `reasons`, with the `field` an `invalid_field` names: "
            "a required field that is absent, empty or of the wrong type. The required fields are version, "
            "certificate_id, team_id, member_did_key, alias and signature; any other member is signed with "
            "the rest and is not the verifier's to judge. "
            "`today` records what each verifier named there "
            "answers now, where that differs or has not been unified: accepted, refused, or the reason it gives."
        ),
        "team_id": TEAM_ID,
        "keys": KEYS,
        "reasons": REASONS,
        "today_verifiers": {
            "awid": "awid.team_certificate: decode_team_certificate, then verify_team_certificate_signature",
            "server": "aweb.team_auth.parse_and_verify_certificate",
            "naapp_runtime": "aweb_naapp.runtime.team_auth.authenticate_request, behind a correctly signed request",
            "library": "library.auth.authenticate_request, behind a correctly signed request",
            "hooks": "aweb_naapp.hooks.delivery: the client certificate of a delivery from the case's signer",
        },
        "cases": [
            {
                **case,
                "today": {
                    **case["today"],
                    "naapp_runtime": NAAPP_RUNTIME_TODAY[case["name"]],
                    "library": LIBRARY_TODAY[case["name"]],
                    "hooks": HOOKS_TODAY[case["name"]],
                },
            }
            for case in cases()
        ],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    text = document()
    if "--check" in argv:
        if not VECTOR.exists() or VECTOR.read_text() != text:
            print(f"{VECTOR} is not what this script writes; run it without --check", file=sys.stderr)
            return 1
        return 0
    VECTOR.write_text(text)
    print(f"wrote {VECTOR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
