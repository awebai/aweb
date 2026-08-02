#!/usr/bin/env python3
"""Validate the pre-activation 51-row harness and killing mutations."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections.abc import Callable, Mapping
from pathlib import Path

_MANIFEST = Path("test-vectors/federation/preactivation-harness-v1.json")
_TEST = Path("server/tests/test_federation_preactivation_harness.py")
_STACK = Path("scripts/e2e-federation-authority.sh")
_WORKER = Path("scripts/federation-authority-worker.py")
_DIRECT = {*range(10, 17), *range(23, 40), *range(47, 50)}
_ACTIVATION = set(range(1, 52)) - _DIRECT
_CANONICAL_INPUT_NAMES = {
    "e2ee-v2-cross-language.json",
    "federation-authority-state-v1.json",
    "federation-discovery-v1.json",
    "federation-origin-ip-v1.json",
    "identity-log-v1.json",
    "message-signing-v1.json",
}
_SERVICES = {
    "awid-a",
    "awid-b",
    "aweb-a-1",
    "aweb-a-2",
    "aweb-b-1",
    "aweb-b-2",
    "postgres-a",
    "postgres-b",
}


def _read(
    root: Path, path: Path, overrides: Mapping[Path, bytes] | None = None
) -> bytes:
    if overrides and path in overrides:
        return overrides[path]
    return (root / path).read_bytes()


def check(root: Path, overrides: Mapping[Path, bytes] | None = None) -> list[str]:
    failures: list[str] = []
    try:
        manifest = json.loads(_read(root, _MANIFEST, overrides))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as exc:
        return [f"invalid federation harness manifest: {exc}"]
    if manifest.get("schema") != "aweb.federation-preactivation-harness.v1":
        failures.append("unexpected federation harness schema")
    if manifest.get("contract") != "aweb-aazd.2.1":
        failures.append("unexpected federation harness contract")
    activation_inputs = manifest.get("activation_inputs", {})
    if set(activation_inputs) != {"plaintext", "encrypted_v2", "replay_globality"}:
        failures.append("activation input fixture inventory is incomplete")
    elif (
        activation_inputs["replay_globality"].get("sole_key") != "message_id"
        or activation_inputs["encrypted_v2"].get("plaintext_fallback") is not False
        or activation_inputs["encrypted_v2"].get("canonical_case")
        != "python_mail_envelope"
        or activation_inputs["plaintext"].get("signed_address_source")
        != "signed_payload.from"
        or activation_inputs["plaintext"].get("canonical_case")
        != "mail_with_stable_ids_unicode"
        or activation_inputs["plaintext"].get("sender_delivery_origin")
        != "https://sender.fixture.test"
        or activation_inputs["encrypted_v2"].get("target_delivery_origin")
        != "https://receiver.fixture.test"
    ):
        failures.append("activation input fixture contract differs")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or [row.get("id") for row in cases] != list(
        range(1, 52)
    ):
        failures.append("federation harness must inventory exact ordered cases 1..51")
        cases = cases if isinstance(cases, list) else []
    if {row.get("id") for row in cases if row.get("mode") == "direct_core"} != _DIRECT:
        failures.append(
            "direct-core case classification differs from reviewed boundary"
        )
    if {
        row.get("id") for row in cases if row.get("mode") == "activation_fixture"
    } != _ACTIVATION:
        failures.append(
            "activation-fixture classification differs from reviewed boundary"
        )
    for row in cases:
        expected_owner = (
            "aweb-aazd.4" if row.get("mode") == "direct_core" else "aweb-aazd.6"
        )
        if row.get("owner") != expected_owner:
            failures.append(f"case {row.get('id')} has wrong production owner")
        evidence = row.get("evidence")
        if not evidence:
            failures.append(f"case {row.get('id')} has no exact evidence")
        if row.get("mode") == "direct_core" and isinstance(evidence, list):
            for reference in evidence:
                separator = "::" if "::" in reference else "#"
                if separator not in reference:
                    failures.append(
                        f"case {row.get('id')} has non-exact direct evidence"
                    )
                    continue
                source_path, marker = reference.split(separator, 1)
                try:
                    source_text = _read(root, Path(source_path), overrides).decode()
                except (OSError, UnicodeError) as exc:
                    failures.append(
                        f"case {row.get('id')} cannot read evidence {source_path}: {exc}"
                    )
                    continue
                if separator == "::":
                    found = (
                        f"def {marker}(" in source_text
                        or f"async def {marker}(" in source_text
                    )
                else:
                    found = marker in source_text
                if not found:
                    failures.append(
                        f"case {row.get('id')} evidence marker is absent: {reference}"
                    )
        if row.get("mode") == "activation_fixture":
            if row.get("mutation_disposition") == "executed_core_mutation":
                failures.append(f"case {row.get('id')} overclaims activation behavior")
            fixture_refs = row.get("fixture_refs")
            if (
                not isinstance(fixture_refs, list)
                or not fixture_refs
                or not set(fixture_refs) <= set(activation_inputs)
                or row.get("evidence")
                != [f"activation_inputs:{fixture}" for fixture in fixture_refs]
            ):
                failures.append(f"case {row.get('id')} has invalid fixture provenance")
            if (
                row.get("expected_contract") != row.get("name")
                or row.get("deferred_task") != "aweb-aazd.6"
            ):
                failures.append(f"case {row.get('id')} has invalid deferred contract")

    topology = manifest.get("topology", {})
    if set(topology.get("awid_registries", ())) != {"awid-a", "awid-b"}:
        failures.append("topology does not contain two AWID registries")
    if set(topology.get("receiver_processes", ())) != {
        "aweb-a-1",
        "aweb-a-2",
        "aweb-b-1",
        "aweb-b-2",
    }:
        failures.append("topology does not contain two processes per receiver")
    if topology.get("strict_ingress_calls") is not False:
        failures.append("pre-activation topology must not call strict ingress")
    if topology.get("runtime_generated_tls") is not True:
        failures.append("topology TLS must be runtime generated")

    canonical_inputs = manifest.get("canonical_inputs", ())
    if {Path(item.get("path", "")).name for item in canonical_inputs} != (
        _CANONICAL_INPUT_NAMES
    ):
        failures.append("canonical harness input inventory differs")
    for item in canonical_inputs:
        path = Path(item.get("path", ""))
        try:
            body = _read(root, path, overrides)
        except OSError as exc:
            failures.append(f"missing canonical harness input {path}: {exc}")
            continue
        if item.get("embedded") is not False:
            failures.append(f"canonical harness input {path} was embedded")
        if len(body) != item.get("bytes") or hashlib.sha256(
            body
        ).hexdigest() != item.get("sha256"):
            failures.append(f"canonical harness input {path} digest differs")

    try:
        stack = _read(root, _STACK, overrides).decode()
        worker = _read(root, _WORKER, overrides).decode()
        tests = _read(root, _TEST, overrides).decode()
    except (OSError, UnicodeError) as exc:
        failures.append(f"cannot read federation harness sources: {exc}")
        return failures
    for service in _SERVICES:
        if service not in stack:
            failures.append(f"disposable topology omits {service}")
    for marker in (
        "down -v --remove-orphans",
        'com.docker.compose.project="$PROJECT"',
        "openssl req",
        "HARNESS_CA_FILE",
        "federation-authority-worker.py",
        '[[ "$ALPHA_DID_AW" != "$BETA_DID_AW" ]]',
        "singleflight --barrier evidence-race",
        "run_permit_race global global receiver-exact-32 32 31",
        "lock-timeout --scope harness-blocked-lock",
    ):
        if marker not in stack:
            failures.append(f"disposable topology omits guard: {marker}")
    for source_name, source in (("stack", stack), ("worker", worker)):
        if "/v1/federation/messages" in source or "/v1/federation/chat" in source:
            failures.append(f"{source_name} activates federation ingress")
    if "BEGIN PRIVATE KEY" in worker or "BEGIN RSA PRIVATE KEY" in worker:
        failures.append("worker contains committed private key material")
    for marker in (
        "StrictExternalRegistry",
        "FederationAuthorityCore",
        "AuthorityWorkRepository",
        "generate_identity()",
    ):
        if marker not in worker:
            failures.append(f"worker omits production API marker: {marker}")
    for marker in (
        "test_two_workers_share_checkpoint_and_invalidation",
        "test_two_workers_singleflight_one_real_chain_and_non_poisoning",
        "test_two_workers_race_exact_shared_limits_and_token_bucket",
        "test_real_postgresql_lock_timeout_fails_closed_without_publication",
        "test_two_registries_record_exact_dns_http_tls_and_share_side_cohorts",
        "FederatedDeliveryRequest.model_validate",
        "evidence = await resolver.fetch_evidence",
        'await race_at_limit("global", "receiver-exact-32", 32)',
        'await race_at_limit("domain", "alpha-exact-2.test", 2)',
        'await race_at_limit("origin", "https://registry-exact-4.test", 4)',
        '"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"',
        'by_label["wrong"][1] == "sender_address_did_mismatch"',
        "assert registry.sni == [hostname] * len(expected_paths)",
    ):
        if marker not in tests:
            failures.append(f"direct harness omits proof marker: {marker}")
    return failures


def _manifest_mutation(root: Path, mutate: Callable[[dict], None]) -> dict[Path, bytes]:
    value = json.loads((root / _MANIFEST).read_text())
    mutate(value)
    return {_MANIFEST: json.dumps(value).encode()}


def self_test(root: Path) -> list[str]:
    stack = (root / _STACK).read_bytes()
    worker = (root / _WORKER).read_bytes()
    tests = (root / _TEST).read_bytes()
    controls = (
        (
            "case deletion",
            _manifest_mutation(root, lambda value: value["cases"].pop(30)),
        ),
        (
            "activation overclaim",
            _manifest_mutation(
                root, lambda value: value["cases"][0].__setitem__("mode", "direct_core")
            ),
        ),
        (
            "wrong production owner",
            _manifest_mutation(
                root,
                lambda value: value["cases"][0].__setitem__("owner", "aweb-aazd.4"),
            ),
        ),
        (
            "fixture expected-contract deletion",
            _manifest_mutation(
                root,
                lambda value: value["cases"][0].pop("expected_contract"),
            ),
        ),
        (
            "activation schema case deletion",
            _manifest_mutation(
                root,
                lambda value: value["activation_inputs"]["plaintext"].pop(
                    "canonical_case"
                ),
            ),
        ),
        (
            "embedded canonical input",
            _manifest_mutation(
                root,
                lambda value: value["canonical_inputs"][0].__setitem__(
                    "embedded", True
                ),
            ),
        ),
        (
            "canonical digest drift",
            _manifest_mutation(
                root,
                lambda value: value["canonical_inputs"][0].__setitem__(
                    "sha256", "0" * 64
                ),
            ),
        ),
        (
            "worker omitted",
            {_STACK: stack.replace(b"aweb-b-2", b"aweb-b-retired")},
        ),
        (
            "ingress activation",
            {_WORKER: worker + b'\nINGRESS = "/v1/federation/messages"\n'},
        ),
        (
            "duplicate identity topology",
            {
                _STACK: stack.replace(
                    b'[[ "$ALPHA_DID_AW" != "$BETA_DID_AW" ]]',
                    b'[[ "$ALPHA_DID_AW" == "$BETA_DID_AW" ]]',
                )
            },
        ),
        (
            "unguarded teardown",
            {_STACK: stack.replace(b"down -v --remove-orphans", b"down")},
        ),
        (
            "activation production schema validation removed",
            {
                _TEST: tests.replace(
                    b"FederatedDeliveryRequest.model_validate",
                    b"dict",
                )
            },
        ),
        (
            "real singleflight chain removed",
            {
                _TEST: tests.replace(
                    b"evidence = await resolver.fetch_evidence",
                    b"evidence = None  # removed resolver.fetch_evidence",
                )
            },
        ),
        (
            "global exact ceiling weakened",
            {
                _TEST: tests.replace(
                    b'await race_at_limit("global", "receiver-exact-32", 32)',
                    b'await race_at_limit("global", "receiver-exact-32", 31)',
                )
            },
        ),
        (
            "lock timeout blocker removed",
            {
                _TEST: tests.replace(
                    b'"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"',
                    b'"SELECT 1"',
                )
            },
        ),
        (
            "TLS observation removed",
            {
                _TEST: tests.replace(
                    b"assert registry.sni == [hostname] * len(expected_paths)",
                    b"assert registry.sni",
                )
            },
        ),
        (
            "non-poisoning comparison removed",
            {
                _TEST: tests.replace(
                    b'by_label["wrong"][1] == "sender_address_did_mismatch"',
                    b'by_label["wrong"][1]',
                )
            },
        ),
    )
    failures: list[str] = []
    for label, overrides in controls:
        observed = check(root, overrides)
        if not observed:
            failures.append(f"{label} mutation unexpectedly passed")
        else:
            print(f"ok: {label}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    failures = self_test(root) if args.self_test else check(root)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    print(
        "federation harness mutation self-test passed"
        if args.self_test
        else "federation harness check passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
