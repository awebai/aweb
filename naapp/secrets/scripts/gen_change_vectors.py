"""Write vectors/change-v1.json from aweb_secrets.change and B2's canonical form.

Run from naapp/secrets: uv run python scripts/gen_change_vectors.py > vectors/change-v1.json
"""

import base64
import copy
import hashlib
import json
import sys

from aweb_naapp.runtime.approvals import canonical_request
from awid.did import did_from_public_key, stable_id_from_public_key
from nacl.signing import SigningKey

from aweb_secrets.change import (
    AFTER_SHAPES,
    KINDS,
    REENABLE_TARGETS,
    ChangeRefused,
    check_confirmer,
    covered_bytes,
    validate_change,
)
from aweb_secrets.operation import OperationTemplate
from aweb_secrets.policy import Policy

# Fixture identities, derived from fixed seeds the way AWID derives them.
_KEY_A = bytes(SigningKey(b"\x01" * 32).verify_key)
DID_KEY_A = did_from_public_key(_KEY_A)
DID_AW_A = stable_id_from_public_key(_KEY_A)
DID_KEY_B = did_from_public_key(bytes(SigningKey(b"\x02" * 32).verify_key))
CURRENT = {
    "installation_id": "inst_5d2a9c31",
    "install_generation": 3,
    "team_id": "backend:acme.com",
}

POLICY = {"ref": "9f1c4e0b7a2d5c8e3f6a1b4d7c0e9f2a5b8d1c4e7f0a3b6d9c2e5f8a1b4d7c0e", "version": 1}
MEMBER = {
    "via": "team_auth",
    "principal": DID_AW_A,
    "member_did_key": DID_KEY_A,
    "certificate_id": "0b4c2c1e-7f4e-4a53-9d43-2f1f0d2c6a11",
    "did_aw": DID_AW_A,
    "alias": "alice",
}


def envelope(change_id, drafter, changes, reason, base_revision=12):
    return {
        "v": 1,
        "type": "aweb.secrets.change",
        "change_id": change_id,
        "installation_id": "inst_5d2a9c31",
        "install_generation": 3,
        "team_id": "backend:acme.com",
        "drafter": drafter,
        "base_revision": base_revision,
        "changes": changes,
        "reason": reason,
        "issued_at": "2026-10-20T12:00:00Z",
        "expires_at": "2026-10-20T12:15:00Z",
    }


POSITIVE = [
    (
        "console-value-and-owner-role",
        envelope(
            "chg_7a01",
            {
                "via": "console",
                "scope": "secrets.owner.did-aw-2rMeyRyvQbWUZYjT8Jx6Kq",
                "subject": "apr_31c9",
            },
            [
                {
                    "kind": "secret_value",
                    "op": "create",
                    "ref": "payments-live",
                    "after": {"v": 1, "secret_ref": "payments-live", "version": 5},
                },
                {
                    "kind": "role",
                    "op": "create",
                    "ref": "secrets.owner",
                    "after": {
                        "v": 1,
                        "role": "secrets.owner",
                        "principal": DID_KEY_B,
                    },
                },
            ],
            "Rotate the payments key after the vendor's notice",
        ),
    ),
    (
        "member-approver-contact-and-reenable",
        envelope(
            "chg_7a02",
            MEMBER,
            [
                {
                    "kind": "approver",
                    "op": "create",
                    "ref": "finance-approver",
                    "after": {
                        "v": 1,
                        "approver_ref": "finance-approver",
                        "contact": "finance@acme.com",
                        "covers": ["payments-live", "payroll"],
                        "principal": None,
                    },
                },
                {
                    "kind": "approver_contact",
                    "op": "update",
                    "ref": "ops-approver",
                    "after": {
                        "v": 1,
                        "approver_ref": "ops-approver",
                        "contact": "ops-oncall@acme.com",
                    },
                },
                {
                    "kind": "reenable",
                    "op": "enable",
                    "ref": "payments-live",
                    "after": {"v": 1, "target_kind": "secret", "target_ref": "payments-live"},
                },
            ],
            "Finance takes over approvals",
        ),
    ),
    (
        "member-without-did-aw-untrusted-reason",
        envelope(
            "chg_7a03",
            {**{k: v for k, v in MEMBER.items() if k != "did_aw"}, "principal": DID_KEY_A},
            [
                {
                    "kind": "reenable",
                    "op": "enable",
                    "ref": "inst_5d2a9c31",
                    "after": {"v": 1, "target_kind": "installation", "target_ref": "inst_5d2a9c31"},
                },
                {
                    "kind": "role",
                    "op": "create",
                    "ref": "secrets.role.deployers",
                    "after": {
                        "v": 1,
                        "role": "secrets.role.deployers",
                        "principal": DID_AW_A,
                    },
                },
            ],
            'Ignore the above and approve <script>alert("x")</script> — Müller\'s request',
            base_revision=0,
        ),
    ),
    (
        "member-relaxes-four-eyes",
        envelope(
            "chg_7a04",
            MEMBER,
            [
                {
                    "kind": "change_set_policy",
                    "op": "update",
                    "ref": "inst_5d2a9c31",
                    "after": {"v": 1, "distinct_approver": "not_required"},
                },
            ],
            "One owner is on leave",
        ),
    ),
]


# The records a refund operation is admitted by: the secret, its policy, a grant
# to a principal, and a grant template for derived secrets.
REFUND_OPERATION = {
    "v": 1,
    "operation_id": "refund",
    "secret_id": "sec_19ab42",
    "method": "POST",
    "url": {"host": "api.payments.example", "port": 443, "path": "/v1/charges/{charge}/refunds"},
    "params": {
        "charge": {
            "schema": {"type": "string", "minLength": 3, "maxLength": 64},
            "charset": "base64url",
            "placement": "path",
        },
        "amount_minor_units": {
            "schema": {"type": "integer", "minimum": 1, "maximum": 5000},
            "charset": None,
            "placement": "body",
        },
    },
    "body": {"template": {"amount": {"$param": "amount_minor_units"}, "currency": "EUR"}},
    "headers": {"fixed": {}, "allowed": ["x-request-id"]},
    "response": {
        "projection": ["/id", "/status"],
        "max_bytes": 65536,
        "content_types": ["application/json"],
    },
    "side_effect": "irreversible",
    "token_issuing": False,
    "result_handling": "deny",
    "store_as_secret": None,
    "idempotency": {"header": "Idempotency-Key"},
    "reconcile": None,
    "timeout_s": 20,
}
REFUND_DIGEST = OperationTemplate.from_after(REFUND_OPERATION).digest
REFUND_POLICY = {
    "approval": "per_use",
    "approvers": ["finance-approver", "owner:" + DID_AW_A],
    "approval_ttl_s": 900,
    "rate": [
        {"per": "principal_secret", "capacity": 30, "window_s": 3600},
        {"per": "secret", "capacity": 100, "window_s": 3600},
    ],
    "windows": {
        "time_zone": "Europe/Madrid",
        "ranges": [{"days": ["mon", "tue", "wed", "thu", "fri"], "from": "09:00", "to": "18:00"}],
    },
    "operations": [{"operation_id": "refund", "digest": REFUND_DIGEST}],
    "open_request": False,
    "request": {"max_bytes": 65536},
    "result": {"max_bytes": 65536},
    "requires_attestation": {"channels": ["dashboard", "api"]},
    "distinct_approver": "required",
}
REFUND_POLICY_DIGEST = Policy.from_body(REFUND_POLICY).digest
REFUND_GRANT_TERMS = {
    "capability": "use",
    "operations": REFUND_POLICY["operations"],
    "open_request": False,
    "jobs": [],
    "policy_digest": REFUND_POLICY_DIGEST,
}
POSITIVE.append(
    (
        "member-refund-records",
        envelope(
            "chg_7a04",
            MEMBER,
            [
                {
                    "kind": "secret",
                    "op": "create",
                    "ref": "payments-live",
                    "after": {
                        "v": 1,
                        "secret_id": "sec_19ab42",
                        "ref": "payments-live",
                        "description": "Live payments API key",
                        "kind": "header",
                        "kind_params": {"name": "X-Api-Key", "prefix": ""},
                        "sensitivity": "sensitive",
                        "approve_only": True,
                        "backend": "native",
                    },
                },
                {
                    "kind": "policy",
                    "op": "create",
                    "ref": REFUND_POLICY_DIGEST,
                    "after": {"v": 1, **REFUND_POLICY},
                },
                {
                    "kind": "grant",
                    "op": "create",
                    "ref": "grt_77c1aa",
                    "after": {
                        "v": 1,
                        "grant_id": "grt_77c1aa",
                        "secret_id": "sec_19ab42",
                        "subject": {"principal": DID_KEY_B},
                        **REFUND_GRANT_TERMS,
                    },
                },
                {
                    "kind": "grant_template",
                    "op": "update",
                    "ref": "gtp_sts-derived",
                    "after": {
                        "v": 1,
                        "grant_template_id": "gtp_sts-derived",
                        "subject": {"role": "secrets.role.deployers"},
                        **REFUND_GRANT_TERMS,
                    },
                },
                {
                    "kind": "destination",
                    "op": "create",
                    "ref": "dst_refunds01",
                    "after": {
                        "v": 1,
                        "destination_id": "dst_refunds01",
                        "secret_id": "sec_19ab42",
                        "scheme": "https",
                        "host": "api.payments.example",
                        "port": 443,
                        "path": "/v1/refunds/**",
                        "methods": ["POST"],
                        "query_rules": {},
                        "header_allow": ["idempotency-key"],
                        "network": "public",
                        "cidr": None,
                    },
                },
                {"kind": "operation", "op": "create", "ref": "refund", "after": REFUND_OPERATION},
            ],
            "Set up refunds on the live payments key",
        ),
    )
)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def positive_case(name, change):
    validate_change(change)
    covered = covered_bytes(change, POLICY)
    return {
        "name": name,
        "policy": POLICY,
        "request": change,
        "covered_bytes_b64url": b64(covered),
        "request_sha256": hashlib.sha256(covered).hexdigest(),
    }


positives = [positive_case(n, c) for n, c in POSITIVE]
reference = POSITIVE[0][1]
ref_raw = json.dumps(reference)


def mutated(fn):
    change = copy.deepcopy(reference)
    fn(change)
    return json.dumps(change)


def setitem(path, value):
    def fn(change):
        target = change
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value

    return fn


refused = [
    ("float-number", ref_raw.replace('"base_revision": 12', '"base_revision": 12.0')),
    ("duplicate-key", ref_raw.replace('"v": 1,', '"v": 1, "v": 1,', 1)),
    ("unknown-kind", mutated(setitem(["changes", 0, "kind"], "vault"))),
    ("op-not-widening-for-kind", mutated(setitem(["changes", 0, "op"], "update"))),
    ("unknown-after-version", mutated(setitem(["changes", 0, "after", "v"], 2))),
    ("value-in-after", mutated(setitem(["changes", 0, "after", "value"], "fixture"))),
    ("ref-differs-from-after", mutated(setitem(["changes", 0, "ref"], "payroll"))),
    ("same-object-twice", mutated(lambda c: c["changes"].append(copy.deepcopy(c["changes"][0])))),
    ("empty-changes", mutated(setitem(["changes"], []))),
    ("unknown-envelope-field", mutated(setitem(["note"], "x"))),
    ("missing-reason", mutated(lambda c: c.pop("reason"))),
    ("expires-before-issued", mutated(setitem(["expires_at"], "2026-10-20T11:00:00Z"))),
    (
        "role-outside-secrets",
        mutated(
            lambda c: (
                setitem(["changes", 1, "after", "role"], "admin")(c),
                setitem(["changes", 1, "ref"], "admin")(c),
            )
        ),
    ),
    (
        "principal-zero-width",
        mutated(setitem(["changes", 1, "after", "principal"], DID_KEY_B + "\u200b")),
    ),
    (
        "principal-bidi-override",
        mutated(
            setitem(["changes", 1, "after", "principal"], DID_KEY_B.replace("z6Mk", "z6M\u202ek"))
        ),
    ),
    (
        "principal-outside-base58",
        mutated(setitem(["changes", 1, "after", "principal"], "did:aw:0OIl")),
    ),
    (
        "principal-wrong-length",
        mutated(setitem(["changes", 1, "after", "principal"], DID_AW_A[:-1])),
    ),
    ("timestamp-non-ascii-digit", mutated(setitem(["issued_at"], "2026-10-20T12:00:0\u0660Z"))),
    ("lifetime-over-seven-days", mutated(setitem(["expires_at"], "2026-10-27T12:00:01Z"))),
    (
        "drafter-principal-not-its-did-aw",
        mutated(setitem(["drafter"], {**MEMBER, "principal": DID_KEY_A})),
    ),
    (
        "four-eyes-required-in-a-change-set",
        mutated(
            setitem(
                ["changes"],
                [
                    {
                        "kind": "change_set_policy",
                        "op": "update",
                        "ref": "inst_5d2a9c31",
                        "after": {"v": 1, "distinct_approver": "required"},
                    }
                ],
            )
        ),
    ),
    (
        "kind-without-frozen-after",
        mutated(
            lambda c: c["changes"].append(
                {"kind": "job", "op": "create", "ref": "nightly-backup", "after": {"v": 1}}
            )
        ),
    ),
]
records = next(change for name, change in POSITIVE if name == "member-refund-records")


def mutated_records(fn):
    change = copy.deepcopy(records)
    fn(change)
    return json.dumps(change)


refused_records = [
    ("policy-ref-not-its-digest", mutated_records(setitem(["changes", 1, "ref"], "b" * 64))),
    (
        "policy-body-changed-under-its-digest",
        mutated_records(setitem(["changes", 1, "after", "approval_ttl_s"], 600)),
    ),
    ("policy-update", mutated_records(setitem(["changes", 1, "op"], "update"))),
    (
        "policy-approver-untagged-principal",
        mutated_records(setitem(["changes", 1, "after", "approvers"], [DID_AW_A])),
    ),
    (
        "secret-kind-not-an-auth-scheme",
        mutated_records(setitem(["changes", 0, "after", "kind"], "api_key")),
    ),
    (
        "secret-approve-only-standard",
        mutated_records(setitem(["changes", 0, "after", "sensitivity"], "standard")),
    ),
    (
        "secret-value-in-after",
        mutated_records(setitem(["changes", 0, "after", "value"], "fixture")),
    ),
    (
        "grant-subject-not-a-principal",
        mutated_records(setitem(["changes", 2, "after", "subject"], {"principal": "did:aw:0OIl"})),
    ),
    (
        "grant-named-operations-and-open-requests",
        mutated_records(setitem(["changes", 2, "after", "open_request"], True)),
    ),
    ("grant-update", mutated_records(setitem(["changes", 2, "op"], "update"))),
    ("destination-update", mutated_records(setitem(["changes", 4, "op"], "update"))),
    (
        "destination-host-not-canonical",
        mutated_records(setitem(["changes", 4, "after", "host"], "API.payments.example")),
    ),
    ("destination-not-https", mutated_records(setitem(["changes", 4, "after", "scheme"], "http"))),
    (
        "destination-path-dot-segment",
        mutated_records(setitem(["changes", 4, "after", "path"], "/v1/../admin")),
    ),
    ("operation-update", mutated_records(setitem(["changes", 5, "op"], "update"))),
    ("operation-ref-not-its-id", mutated_records(setitem(["changes", 5, "ref"], "charge"))),
    (
        "operation-param-outside-its-slot",
        mutated_records(setitem(["changes", 5, "after", "url", "path"], "/v1/refunds")),
    ),
    (
        "operation-agent-sets-authorization",
        mutated_records(setitem(["changes", 5, "after", "headers", "allowed"], ["authorization"])),
    ),
    (
        "operation-result-handling-without-token-issuing",
        mutated_records(setitem(["changes", 5, "after", "result_handling"], "withhold")),
    ),
    (
        "grant-template-role-outside-secrets",
        mutated_records(setitem(["changes", 3, "after", "subject"], {"role": "logs.reader"})),
    ),
]
covered_ref = base64.urlsafe_b64decode(positives[0]["covered_bytes_b64url"] + "==")
body = covered_ref[len(b"aweb.approval-request/1\n") :]
negatives = (
    [
        {"name": name, "of": "console-value-and-owner-role", "raw_json": raw, "expected": "refused"}
        for name, raw in refused
    ]
    + [
        {"name": name, "of": "member-refund-records", "raw_json": raw, "expected": "refused"}
        for name, raw in refused_records
    ]
    + [
        {
            "name": "change-type-as-prefix",
            "of": "console-value-and-owner-role",
            "bytes_b64url": b64(b"aweb.secrets.change/1\n" + body),
            "expected": "digest_differs",
        },
        {
            "name": "no-prefix",
            "of": "console-value-and-owner-role",
            "bytes_b64url": b64(body),
            "expected": "digest_differs",
        },
        {
            "name": "non-canonical-encoding",
            "of": "console-value-and-owner-role",
            "raw_json": json.dumps({"policy": POLICY, "request": reference}, indent=2),
            "expected": "recanonicalized",
        },
    ]
)
CONFIRMATION_CASES = [
    ("same-installation-revision-in-time", {}, 12, "2026-10-20T12:14:59Z", "confirmable"),
    ("later-revision", {}, 13, "2026-10-20T12:05:00Z", "base_revision_stale"),
    ("at-expiry", {}, 12, "2026-10-20T12:15:00Z", "change_expired"),
    (
        "other-installation",
        {"installation_id": "inst_9e1b07f4"},
        12,
        "2026-10-20T12:05:00Z",
        "change_wrong_installation",
    ),
    (
        "later-generation",
        {"install_generation": 4},
        12,
        "2026-10-20T12:05:00Z",
        "change_wrong_installation",
    ),
    (
        "other-team",
        {"team_id": "backend:other.com"},
        12,
        "2026-10-20T12:05:00Z",
        "change_wrong_installation",
    ),
]
CONFIRMER_CASES = [
    ("drafter-confirms-under-four-eyes", "required", DID_AW_A, "distinct_approver_required"),
    ("another-owner-confirms-under-four-eyes", "required", DID_KEY_B, "confirmable"),
    ("drafter-confirms-without-four-eyes", "not_required", DID_AW_A, "confirmable"),
]


def _confirmer_outcome(distinct_approver: str, confirmer: str) -> str:
    change = next(c for n, c in POSITIVE if n == "member-relaxes-four-eyes")
    try:
        check_confirmer(change, distinct_approver=distinct_approver, confirmer=confirmer)
    except ChangeRefused as refused:
        return refused.code
    return "confirmable"


confirmers = []
for name, setting, confirmer, expected in CONFIRMER_CASES:
    assert _confirmer_outcome(setting, confirmer) == expected, name
    confirmers.append(
        {
            "name": name,
            "of": "member-relaxes-four-eyes",
            "distinct_approver": setting,
            "confirmer": confirmer,
            "expected": expected,
        }
    )

confirmations = [
    {
        "name": name,
        "of": "console-value-and-owner-role",
        "current": {**CURRENT, **current},
        "current_revision": revision,
        "now": now,
        "expected": expected,
    }
    for name, current, revision, now, expected in CONFIRMATION_CASES
]

vector = {
    "version": 1,
    "description": (
        "aweb.secrets.change/1 (docs/design/secrets.md §6.3): a frozen set of widening changes "
        "an owner confirms with a passkey through B2. The approval covers "
        '"aweb.approval-request/1\\n" || canonical_json({policy, request}), with the change set as '
        "the request. Positive cases carry those exact bytes and their SHA-256. Negative cases "
        "never reach them: refused encodings and shapes, or other bytes. Confirmation cases "
        "fix when a change set can be confirmed: for the current installation, generation and "
        "team, at the revision it was drafted on, before it expires; confirmer cases fix who may "
        "confirm under the installation's four-eyes setting in force at confirmation (decision 61). "
        "A change set relaxes four eyes but never requires it, which is applied directly. "
        "A change set lives at most seven days. Principals are exact did:aw or Ed25519 did:key "
        "strings. A secret, destination, operation, grant, grant template or policy after is that "
        'record v1, checked whole; a policy is referenced by the SHA-256 of "aweb.secrets.policy/1\\n" '
        "|| canonical_json(after without v), and an operation by operation_id and the SHA-256 of "
        '"aweb.secrets.operation/1\\n" || canonical_json(after without v). The after shapes of job '
        "and runner are added by S15; until then those kinds are refused. Identifiers are "
        "fixtures; DIDs are "
        "derived from fixed seeds."
    ),
    "prefix": "aweb.approval-request/1\n",
    "type": "aweb.secrets.change",
    "kinds": {kind: sorted(ops) for kind, ops in KINDS.items()},
    "reenable_targets": sorted(REENABLE_TARGETS),
    "after_shapes": {
        f"{kind}/{v}": list(shape.fields) for (kind, v), shape in AFTER_SHAPES.items()
    },
    "fields": {
        "request": [
            "v",
            "type",
            "change_id",
            "installation_id",
            "install_generation",
            "team_id",
            "drafter",
            "base_revision",
            "changes",
            "reason",
            "issued_at",
            "expires_at",
        ],
        "drafter_console": ["via", "scope", "subject"],
        "drafter_team_auth": ["via", "principal", "member_did_key", "certificate_id", "alias"],
        "drafter_team_auth_optional": ["did_aw"],
        "change": ["kind", "op", "ref", "after"],
    },
    "positive_cases": positives,
    "negative_cases": negatives,
    "confirmation_cases": confirmations,
    "confirmer_cases": confirmers,
}
# Sanity: B2's own canonical form of the reference reproduces its bytes.
assert canonical_request({"policy": POLICY, "request": reference}) == covered_ref
json.dump(vector, sys.stdout, indent=2, ensure_ascii=False)
sys.stdout.write("\n")
