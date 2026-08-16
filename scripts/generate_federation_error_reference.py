#!/usr/bin/env python3
"""Generate the public federation error reference from canonical code."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AWID_SOURCE = ROOT / "awid/src"
if str(AWID_SOURCE) not in sys.path:
    sys.path.insert(0, str(AWID_SOURCE))

from awid.federation_errors import FederationErrorSpec, federation_error_specs

DEFAULT_VECTOR = ROOT / "docs/vectors/federation-authority-state-v1.json"
DEFAULT_OUTPUT = ROOT / "docs/federation-error-reference.md"

SUPPORT_MEANINGS = {
    "federation_envelope_invalid": "Envelope shape, version, content mode, UUID, or required behavior field is invalid.",
    "federation_signature_invalid": "Signature encoding or plaintext/encrypted protected-envelope verification failed.",
    "federation_timestamp_invalid": "Signed timestamp is malformed, imprecise, expired, or too far in the future.",
    "sender_address_required": "A global first-contact envelope has no client-signed sender address.",
    "sender_registry_unresolvable": "Historical continuation has no valid stored sender-address locator.",
    "sender_address_wrapper_mismatch": "Wrapper sender address differs from the signed/protected address.",
    "sender_registry_discovery_failed": "DNS authority discovery failed or returned malformed/ambiguous authority data.",
    "sender_registry_origin_forbidden": "Selected registry origin or any resolved endpoint violates origin/SSRF policy.",
    "sender_registry_unavailable": "A validly selected registry is temporarily unreachable or returns a retryable failure.",
    "sender_registry_tls_invalid": "Registry TLS hostname, SNI, or certificate verification failed.",
    "sender_registry_protocol_invalid": "Registry redirect, encoding, framing, JSON/schema, or pinned-dial contract is invalid.",
    "sender_identity_not_found": "Selected authority reports the namespace, address, or DID as absent/deleted.",
    "sender_address_did_mismatch": "Authoritative namespace/address identity differs from the signed or stored sender DID.",
    "sender_current_key_mismatch": "Authoritative key/log differs from the sender key presented in the envelope.",
    "sender_identity_unverifiable": "Required key/log evidence is temporarily unavailable or incomplete.",
    "sender_did_log_invalid": "Genesis, chain, hash, signature, sequence, or checkpoint containment evidence is invalid.",
    "sender_did_log_rollback": "Served identity history is behind the receiver's durable checkpoint.",
    "sender_did_log_split_view": "Served identity history forks from or conflicts with the durable checkpoint.",
    "sender_identity_evidence_too_large": "Registry evidence exceeds response, entry, sequence, or signature-work bounds.",
    "sender_route_missing": "Authoritative global sender or stored continuation has no delivery origin.",
    "sender_route_mismatch": "Presented sender origin differs from the authoritative address route.",
    "local_sender_route_mismatch": "Local sender address/origin differs from or attempts to create its learned route.",
    "target_route_mismatch": "Envelope target origin is not the receiving service's configured public origin.",
    "recipient_identity_not_found": "Target address/DID or active local recipient projection does not exist.",
    "recipient_address_did_mismatch": "Target address resolves to a different stable recipient DID.",
    "recipient_current_key_mismatch": "Target current key differs from authoritative or stored recipient state.",
    "recipient_route_missing": "Target global address or stored participant has no delivery origin.",
    "recipient_route_mismatch": "Target authoritative delivery origin differs from the envelope route.",
    "local_recipient_route_missing": "Local recipient lacks the exact learned conversation/session route.",
    "federation_conversation_invalid": "Continuation state is missing, closed, wrong-kind, or participant-mismatched.",
    "recipient_policy_rejected": "Current recipient inbound policy denies delivery after authority verification.",
    "contact_identity_binding_required": "A legacy address-only contact requires explicit owner DID binding.",
    "federation_message_replay_conflict": "Message UUID was reused with changed metadata/envelope or is legacy-unreplayable.",
    "federation_authority_cas_conflict": "Authority generation, fence, token, or checkpoint changed after one bounded retry.",
    "federation_authority_coordination_unavailable": "Required PostgreSQL/lease publication or target-registry coordination is unavailable.",
    "federation_resolver_busy": "A shared resolver/read concurrency permit is temporarily unavailable.",
    "federation_rate_limited": "A source, sender-domain, or registry-origin authority budget is exhausted.",
    "recipient_encryption_assertion_missing": "Recipient has no identity-authorized X25519 assertion after sender authority passes.",
    "recipient_encryption_assertion_invalid_or_stale": "Recipient X25519 assertion is invalid, stale, or bound to the wrong identity/key.",
    "federation_route_unavailable": "The verified recipient delivery origin cannot be connected.",
    "federation_route_timeout": "Delivery to the verified recipient origin exceeded its deadline.",
    "federation_route_rejected": "The remote peer returned a valid bounded non-retryable rejection.",
}


class ReferenceContractError(RuntimeError):
    """The canonical vector cannot produce a complete stable reference."""


def canonical_error_specs() -> tuple[FederationErrorSpec, ...]:
    """Return the shipped reason/status/retry contract from its code authority."""

    return federation_error_specs()


def _validate_contract(
    contract: Mapping[str, Any],
    error_specs: Sequence[FederationErrorSpec],
) -> list[Mapping[str, Any]]:
    if contract.get("schema") != "aweb.federation-authority-state.v1":
        raise ReferenceContractError("unsupported federation authority vector schema")
    if contract.get("contract") != "aweb-aazd.2.1":
        raise ReferenceContractError("unexpected federation authority contract identity")

    response = contract.get("error_response_contract")
    if not isinstance(response, Mapping):
        raise ReferenceContractError("missing error response contract")
    if response.get("required_body_fields") != ["detail", "reason", "retryable", "correlation_id"]:
        raise ReferenceContractError("stable error body fields changed")
    retry_after_reasons = response.get("retry_after_required_only_for")
    if retry_after_reasons != ["federation_rate_limited"]:
        raise ReferenceContractError("Retry-After reason contract changed")

    errors = contract.get("stable_errors")
    if not isinstance(errors, list) or not errors:
        raise ReferenceContractError("stable error vocabulary is empty")
    reasons: set[str] = set()
    required_fields = {"reason", "detail", "http_status", "retryable", "retry_after_required"}
    for error in errors:
        if not isinstance(error, Mapping) or set(error) != required_fields:
            raise ReferenceContractError("stable error has unsupported fields")
        reason = error.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ReferenceContractError("stable error reason is empty")
        if reason in reasons:
            raise ReferenceContractError(f"duplicate stable error: {reason}")
        reasons.add(reason)
        if error.get("detail") != reason:
            raise ReferenceContractError(f"detail differs from reason: {reason}")
        if not isinstance(error.get("http_status"), int):
            raise ReferenceContractError(f"HTTP status is not an integer: {reason}")
        if not isinstance(error.get("retryable"), bool) or not isinstance(
            error.get("retry_after_required"), bool
        ):
            raise ReferenceContractError(f"retry flags are not boolean: {reason}")
        expected_retry_after = reason in retry_after_reasons
        if error.get("retry_after_required") is not expected_retry_after:
            raise ReferenceContractError(f"Retry-After contract mismatch: {reason}")
    canonical_errors = [
        {
            "reason": spec.reason,
            "detail": spec.reason,
            "http_status": spec.http_status,
            "retryable": spec.retryable,
            "retry_after_required": spec.retry_after_required,
        }
        for spec in error_specs
    ]
    canonical_by_reason = {error["reason"]: error for error in canonical_errors}
    if len(canonical_by_reason) != len(canonical_errors):
        raise ReferenceContractError("duplicate stable error in canonical federation error source")
    vector_by_reason = {error["reason"]: dict(error) for error in errors}
    if vector_by_reason != canonical_by_reason:
        raise ReferenceContractError(
            "authority vector does not match canonical federation error source"
        )

    canonical_reasons = set(canonical_by_reason)
    unclassified = sorted(canonical_reasons - set(SUPPORT_MEANINGS))
    if unclassified:
        raise ReferenceContractError(f"unclassified stable error: {unclassified[0]}")
    stale_meanings = sorted(set(SUPPORT_MEANINGS) - canonical_reasons)
    if stale_meanings:
        raise ReferenceContractError(f"support meaning retains absent stable error: {stale_meanings[0]}")
    return canonical_errors


def render_reference(
    contract: Mapping[str, Any],
    *,
    error_specs: Sequence[FederationErrorSpec] | None = None,
) -> str:
    errors = _validate_contract(
        contract,
        canonical_error_specs() if error_specs is None else error_specs,
    )
    response = contract["error_response_contract"]
    allowed = ", ".join(f"`{field}`" for field in response["diagnostic_fields_allowed"])
    forbidden = ", ".join(f"`{field}`" for field in response["diagnostic_fields_forbidden"])

    lines = [
        "---",
        'title: "Federation error reference"',
        'kicker: "Generated compatibility reference"',
        'description: "Stable cross-registry mail and chat errors generated from the canonical federation error source."',
        "weight: 96",
        "---",
        "",
        "# Federation error reference",
        "",
        "<!-- Generated by scripts/generate_federation_error_reference.py; do not edit by hand. -->",
        "",
        "This compatibility reference generates reason, HTTP status, and retryability from",
        "[`awid/src/awid/federation_errors.py`](../awid/src/awid/federation_errors.py),",
        "the shipped machine-readable authority. The response shape and safe diagnostic fields are",
        "cross-checked against the selected-policy conformance vector in",
        "[`docs/vectors/federation-authority-state-v1.json`](vectors/federation-authority-state-v1.json).",
        "",
        "Federation failures return a JSON object with `detail`, `reason`, `retryable`, and `correlation_id`.",
        "`detail` equals the stable `reason` string. Clients may branch on `reason` and",
        "may retry only when `retryable` is true. `Retry-After` is required only for",
        "`federation_rate_limited`, which emits `Retry-After: 1`; other retryable failures require",
        "caller-chosen bounded backoff.",
        "",
        f"Security diagnostics may additionally include {allowed}. They must not expose {forbidden}.",
        "",
        "| Stable reason | HTTP | Retryable | `Retry-After` required | Support meaning |",
        "| --- | ---: | :---: | :---: | --- |",
    ]
    for error in errors:
        lines.append(
            f"| `{error['reason']}` | {error['http_status']} | "
            f"{'yes' if error['retryable'] else 'no'} | "
            f"{'yes' if error['retry_after_required'] else 'no'} | "
            f"{SUPPORT_MEANINGS[error['reason']]} |"
        )
    lines.extend(
        [
            "",
            "## Support interpretation",
            "",
            "A non-retryable result means the exact request must change or an explicit identity,",
            "route, contact, policy, or migration action must occur. Retrying unchanged input is",
            "not recovery. A retryable result means the service could not establish authority or",
            "complete routing at that attempt; it does not weaken validation or authorize plaintext",
            "fallback. The `correlation_id` is the safe support handle. Do not request registry",
            "responses, DID logs, keys, DNS answers, peer bodies, or internal URLs from users.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    try:
        contract = json.loads(args.vector.read_text(encoding="utf-8"))
        rendered = render_reference(contract)
    except (OSError, json.JSONDecodeError, ReferenceContractError) as exc:
        print(f"cannot generate federation error reference: {exc}", file=sys.stderr)
        return 1

    rendered_bytes = rendered.encode("utf-8")
    if args.check:
        try:
            current = args.output.read_bytes()
        except OSError:
            current = b""
        if current != rendered_bytes:
            print("federation error reference is stale", file=sys.stderr)
            return 1
        print("federation error reference matches canonical error source and authority vectors")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(rendered_bytes)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
