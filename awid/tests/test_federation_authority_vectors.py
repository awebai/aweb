from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = _ROOT / "docs" / "vectors"
_VECTOR_NAMES = (
    "federation-origin-ip-v1.json",
    "federation-discovery-v1.json",
    "federation-authority-state-v1.json",
)
_VECTOR_PINS = {
    "federation-origin-ip-v1.json": (
        12746,
        "6d6ec789c4d994913ae84a26021a8e8fe0c7eb3aaf008ee10ce623db7a87cb18",
        "7d0bc9ce293d551fdf60cc1b744dce919d36fba17b3733475ec6926ebfd5b79c",
    ),
    "federation-discovery-v1.json": (
        18774,
        "42fc649d28f097d22073d10e01c800ca653e177ec055a9cd2f40b047eb6a22da",
        "47b0c4f01973bec0935628d2b992bdf4cafa9c034935da6c9cc978a4c8333860",
    ),
    "federation-authority-state-v1.json": (
        24926,
        "dbfae045d87a947ba5e9add41b03832159eb584c1ab1d8644ec5a34f27f8d616",
        "653515763d49617951204f8eefcf72fcb375dbab9ef081519bad6a1af37dccbf",
    ),
}
_STABLE_ERRORS = {
    "contact_identity_binding_required": (409, False),
    "federation_authority_cas_conflict": (503, True),
    "federation_authority_coordination_unavailable": (503, True),
    "federation_conversation_invalid": (409, False),
    "federation_envelope_invalid": (422, False),
    "federation_message_replay_conflict": (409, False),
    "federation_rate_limited": (429, True),
    "federation_resolver_busy": (503, True),
    "federation_route_rejected": (502, False),
    "federation_route_timeout": (504, True),
    "federation_route_unavailable": (503, True),
    "federation_signature_invalid": (422, False),
    "federation_timestamp_invalid": (422, False),
    "local_recipient_route_missing": (404, False),
    "local_sender_route_mismatch": (422, False),
    "recipient_address_did_mismatch": (422, False),
    "recipient_current_key_mismatch": (422, False),
    "recipient_encryption_assertion_invalid_or_stale": (422, False),
    "recipient_encryption_assertion_missing": (424, False),
    "recipient_identity_not_found": (404, False),
    "recipient_policy_rejected": (403, False),
    "recipient_route_mismatch": (422, False),
    "recipient_route_missing": (424, False),
    "sender_address_did_mismatch": (422, False),
    "sender_address_required": (422, False),
    "sender_address_wrapper_mismatch": (422, False),
    "sender_current_key_mismatch": (422, False),
    "sender_did_log_invalid": (422, False),
    "sender_did_log_rollback": (409, False),
    "sender_did_log_split_view": (409, False),
    "sender_identity_evidence_too_large": (502, False),
    "sender_identity_not_found": (404, False),
    "sender_identity_unverifiable": (503, True),
    "sender_registry_discovery_failed": (503, True),
    "sender_registry_origin_forbidden": (422, False),
    "sender_registry_protocol_invalid": (502, False),
    "sender_registry_tls_invalid": (502, False),
    "sender_registry_unavailable": (503, True),
    "sender_registry_unresolvable": (422, False),
    "sender_route_mismatch": (422, False),
    "sender_route_missing": (424, False),
    "target_route_mismatch": (421, False),
}
_COHORT_FIELDS = {
    "address_id",
    "authoritative_delivery_origin",
    "authoritative_read_completed_at",
    "authority_name",
    "authority_selection",
    "authority_statement_digest",
    "authority_statement_version",
    "bound_current_did_key",
    "bound_did_aw",
    "canonical_address",
    "checkpoint_entry_hash",
    "checkpoint_revision",
    "checkpoint_seq",
    "controller_did",
    "expires_at",
    "generation",
    "inherited",
    "publishing_fence",
    "registry_explicit",
    "registry_origin",
    "revision",
}
_REQUIRED_MUTATIONS = {
    "accept_degraded_evidence",
    "cache_mismatch_by_address",
    "checkpoint_keyed_by_registry",
    "cohort_keyed_by_did",
    "emit_event_before_commit",
    "fence_counter_deleted_or_reset",
    "global_receipt_omitted_from_local_chat",
    "global_receipt_omitted_from_local_mail",
    "leftmost_xff_trusted",
    "legacy_unreplayable_retry_accepted",
    "live_fence_predicate_removed",
    "mismatch_poisoning_correct_claim",
    "phase_b_commits_split",
    "pre_activation_sot_slice_omitted",
    "production_coordination_fallback",
    "redirect_proxy_or_credentials_allowed",
    "replay_keyed_by_composite",
    "resolved_ip_pinning_removed",
    "same_sequence_fork_allowed",
    "stale_checkpoint_overwrite_allowed",
    "state_accepted_before_checkpoint_winner",
    "checkpoint_containment_omitted",
    "checkpoint_upsert_without_cas",
    "cohort_tuple_field_omitted",
    "cross_worker_invalidation_removed",
    "e2e_downgraded_to_plaintext",
    "error_vector_branch_omitted",
    "established_result_equality_removed",
    "local_route_injection_allowed",
    "process_local_work_limits",
    "receiver_reuse_over_60_seconds",
    "signed_address_replaced_by_wrapper",
    "ssrf_all_answer_validation_removed",
    "contact_transferred_by_address",
}


def _load_vectors() -> dict[str, dict]:
    vectors = {}
    for name in _VECTOR_NAMES:
        body = (_VECTORS / name).read_bytes()
        expected_bytes, expected_sha256, _ = _VECTOR_PINS[name]
        assert len(body) == expected_bytes, f"{name} byte count is not immutable"
        assert hashlib.sha256(body).hexdigest() == expected_sha256, (
            f"{name} bytes are not immutable"
        )
        vectors[name] = json.loads(body)
    return vectors


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _assert_names(cases: list[Mapping[str, object]]) -> None:
    names = [case["name"] for case in cases]
    assert all(isinstance(name, str) and name for name in names)
    assert len(names) == len(set(names))


def _named_case(
    vectors: Mapping[str, dict], vector_name: str, group: str, case_name: str
) -> dict:
    return next(
        case for case in vectors[vector_name][group] if case["name"] == case_name
    )


def _remove_named_case(
    vectors: Mapping[str, dict], vector_name: str, group: str, case_name: str
) -> None:
    cases = vectors[vector_name][group]
    cases.remove(next(case for case in cases if case["name"] == case_name))


def _validate_origin_ip(vector: Mapping[str, object]) -> None:
    assert set(vector) == {
        "schema",
        "contract",
        "origin_cases",
        "ip_cases",
        "answer_set_cases",
        "source_ip_cases",
        "transport_cases",
    }
    assert vector["schema"] == "aweb.federation-origin-ip.v1"
    assert vector["contract"] == "aweb-aazd.2.1"

    for group in (
        "origin_cases",
        "ip_cases",
        "answer_set_cases",
        "source_ip_cases",
        "transport_cases",
    ):
        cases = vector[group]
        assert isinstance(cases, list) and cases
        _assert_names(cases)

    for case in vector["origin_cases"]:
        expected = case["expected"]
        assert set(case) == {"name", "input", "context", "expected"}
        assert set(case["context"]) == {
            "app_env",
            "federation_test_enabled",
            "listener_origin",
        }
        assert set(expected) == {"ok", "canonical_origin", "reason"}
        if expected["ok"]:
            assert expected["canonical_origin"]
            assert expected["reason"] is None
        else:
            assert expected == {
                "ok": False,
                "canonical_origin": None,
                "reason": "sender_registry_origin_forbidden",
            }

    ip_allowed = {}
    for case in vector["ip_cases"]:
        ipaddress.ip_address(case["input"])
        expected = case["expected"]
        assert set(expected) == {"allowed", "reason"}
        assert (
            expected["reason"] is None
            if expected["allowed"]
            else (expected["reason"] == "sender_registry_origin_forbidden")
        )
        ip_allowed[case["input"]] = expected["allowed"]

    for case in vector["answer_set_cases"]:
        for address in case["answers"]:
            ipaddress.ip_address(address)
            assert address in ip_allowed
        expected = case["expected"]
        assert expected["allowed"] is all(
            ip_allowed[address] for address in case["answers"]
        )
        assert set(expected) == {"allowed", "approved_ips", "reason"}
        if expected["allowed"]:
            assert expected["approved_ips"] == case["answers"]
            assert expected["reason"] is None
        else:
            assert expected["approved_ips"] == []
            assert expected["reason"] == "sender_registry_origin_forbidden"

    for case in vector["source_ip_cases"]:
        expected = case["expected"]
        direct_peer = ipaddress.ip_address(case["direct_peer"])
        trusted_cidrs = [
            ipaddress.ip_network(value) for value in case["trusted_proxy_cidrs"]
        ]
        direct_is_trusted = any(direct_peer in network for network in trusted_cidrs)
        if not direct_is_trusted:
            calculated = {
                "source_ip": str(direct_peer),
                "forwarded_header_used": False,
                "unknown_bucket": False,
            }
        else:
            try:
                hops = [
                    ipaddress.ip_address(value.strip())
                    for value in case["forwarded_for"].split(",")
                ]
            except ValueError:
                calculated = {
                    "source_ip": None,
                    "forwarded_header_used": False,
                    "unknown_bucket": True,
                }
            else:
                source = next(
                    (
                        hop
                        for hop in reversed(hops)
                        if not any(hop in network for network in trusted_cidrs)
                    ),
                    None,
                )
                calculated = {
                    "source_ip": str(source) if source is not None else None,
                    "forwarded_header_used": True,
                    "unknown_bucket": source is None,
                }
        assert expected == calculated

    for case in vector["transport_cases"]:
        expected = case["expected"]
        assert case["selected_ip"] in case["resolved_answers"]
        assert expected["connect_ip"] == case["selected_ip"]
        assert expected["accept_encoding"] == "identity"
        for field in (
            "ambient_proxy",
            "auth",
            "cookies",
            "redirect_follow",
            "second_resolution",
        ):
            assert expected[field] is False
        assert expected["host_header"].split(":", 1)[0] == expected["tls_server_name"]


def _validate_discovery(vector: Mapping[str, object]) -> None:
    assert set(vector) == {
        "schema",
        "contract",
        "constants",
        "canonical_address_cases",
        "dns_cases",
        "authority_statement_cases",
        "authority_lookup_cases",
    }
    assert vector["schema"] == "aweb.federation-discovery.v1"
    assert vector["contract"] == "aweb-aazd.2.1"
    assert vector["constants"] == {
        "authority_statement_version": "aweb.federation-authority.dns.v1",
        "public_registry_origin": "https://api.awid.ai",
    }

    for group in (
        "canonical_address_cases",
        "dns_cases",
        "authority_statement_cases",
        "authority_lookup_cases",
    ):
        cases = vector[group]
        assert isinstance(cases, list) and cases
        _assert_names(cases)

    for case in vector["canonical_address_cases"]:
        expected = case["expected"]
        assert set(expected) == {"valid", "canonical"}
        assert bool(expected["canonical"]) is expected["valid"]

    permitted_outcomes = {
        "record",
        "nxdomain",
        "nodata",
        "no_awid_record",
        "timeout",
        "servfail",
        "malformed",
        "duplicate_field",
        "unsupported_version",
        "invalid_controller",
        "multiple_awid_records",
    }
    for case in vector["dns_cases"]:
        assert case["queries"]
        assert all(query["outcome"] in permitted_outcomes for query in case["queries"])
        expected = case["expected"]
        assert set(expected) == {
            "selection",
            "authority_name",
            "inherited",
            "registry_explicit",
            "registry_origin",
            "reason",
        }
        if expected["reason"] is None:
            assert expected["selection"] in {"dns", "public_default"}
            assert expected["registry_origin"]
        else:
            assert expected["reason"] == "sender_registry_discovery_failed"
            assert expected["selection"] is None
            assert expected["registry_origin"] is None

    payload_keys = {
        "authority_name",
        "controller_did",
        "inherited",
        "registry_explicit",
        "registry_origin",
        "selection",
        "version",
    }
    for case in vector["authority_statement_cases"]:
        assert set(case["payload"]) == payload_keys
        canonical = _canonical_json(case["payload"])
        assert case["canonical_payload"] == canonical
        assert (
            case["authority_statement_version"]
            == vector["constants"]["authority_statement_version"]
        )
        assert case["authority_statement_digest"] == (
            "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
        )


def _validate_authority_state(vector: Mapping[str, object]) -> None:
    assert set(vector) == {
        "schema",
        "contract",
        "selected_policies",
        "bounds",
        "identity_log_references",
        "checkpoint_cases",
        "cohort_required_fields",
        "cohort_cases",
        "work_fence_cases",
        "evidence_reuse_cases",
        "error_response_contract",
        "stable_errors",
        "mandatory_mutations",
    }
    assert vector["schema"] == "aweb.federation-authority-state.v1"
    assert vector["contract"] == "aweb-aazd.2.1"
    assert vector["selected_policies"] == {
        "contact_authority": "identity_bound_address_and_did_aw",
        "contact_replacement": "controller_proof_and_authenticated_recipient_acceptance",
        "contact_transfer": "never_automatic",
        "receiver_reuse_default_seconds": 60,
        "receiver_reuse_max_seconds": 60,
        "receiver_reuse_configurable_only_downward": True,
        "receiver_reuse_is_freshness_sla": False,
    }
    assert vector["bounds"] == {
        "resolver_chain_deadline_seconds": 5,
        "max_response_bytes": 10 * 1024 * 1024,
        "max_log_entries": 4096,
        "max_signature_verifications": 4096,
        "max_safe_sequence": 2**53 - 1,
        "max_no_cache_bypass_per_message": 1,
        "max_active_discovery_per_domain": 2,
        "max_active_reads_per_origin": 4,
        "max_active_external_reads": 32,
        "token_bucket_burst": 5,
        "token_bucket_refill_per_minute": 30,
        "success_reuse_max_seconds": 60,
        "authoritative_not_found_reuse_max_seconds": 15,
        "dns_transport_failure_reuse_max_seconds": 5,
        "coordination_store": "postgresql",
        "mismatch_memoization": "none",
    }

    reference_paths = {
        "docs/vectors/identity-log-v1.json",
        "docs/vectors/identity-log-negative-v1.json",
        "docs/vectors/identity-log-raw-wire-v1.json",
    }
    references = vector["identity_log_references"]
    assert len(references) == len(reference_paths)
    assert {reference["path"] for reference in references} == reference_paths
    for reference in references:
        assert reference["embedded"] is False
        body = (_ROOT / reference["path"]).read_bytes()
        assert reference["bytes"] == len(body)
        assert reference["sha256"] == hashlib.sha256(body).hexdigest()

    _assert_names(vector["checkpoint_cases"])
    assert {case["expected"]["action"] for case in vector["checkpoint_cases"]} >= {
        "advance",
        "idempotent",
        "insert",
        "reject",
        "retry_once",
    }
    assert set(vector["cohort_required_fields"]) == _COHORT_FIELDS
    _assert_names(vector["cohort_cases"])
    _assert_names(vector["work_fence_cases"])
    _assert_names(vector["evidence_reuse_cases"])

    assert vector["error_response_contract"] == {
        "required_body_fields": ["detail", "reason", "retryable", "correlation_id"],
        "diagnostic_fields_allowed": ["did_aw", "observed_sequence"],
        "diagnostic_fields_forbidden": [
            "log_contents",
            "keys",
            "dns_answers",
            "peer_body",
            "internal_url",
        ],
        "retry_after_required_only_for": ["federation_rate_limited"],
    }
    for item in vector["stable_errors"]:
        assert set(item) == {
            "reason",
            "detail",
            "http_status",
            "retryable",
            "retry_after_required",
        }
        assert item["detail"] == item["reason"]
        assert item["retry_after_required"] is (
            item["reason"] == "federation_rate_limited"
        )
    errors = {
        item["reason"]: (item["http_status"], item["retryable"])
        for item in vector["stable_errors"]
    }
    assert errors == _STABLE_ERRORS
    assert len(errors) == len(vector["stable_errors"])

    mutations = vector["mandatory_mutations"]
    assert {item["id"] for item in mutations} == _REQUIRED_MUTATIONS
    assert len(mutations) == len(_REQUIRED_MUTATIONS)
    assert all(item["must_fail"] is True for item in mutations)
    assert all(
        item["proof"] in {"schema", "future_behavior", "pre_activation_sot"}
        for item in mutations
    )


def _validate_all(vectors: Mapping[str, Mapping[str, object]]) -> None:
    assert set(vectors) == set(_VECTOR_NAMES)
    for name, vector in vectors.items():
        _, _, expected_content_sha256 = _VECTOR_PINS[name]
        content = _canonical_json(vector).encode()
        assert hashlib.sha256(content).hexdigest() == expected_content_sha256, (
            f"{name} content is not immutable"
        )
    _validate_origin_ip(vectors["federation-origin-ip-v1.json"])
    _validate_discovery(vectors["federation-discovery-v1.json"])
    _validate_authority_state(vectors["federation-authority-state-v1.json"])


def test_federation_authority_vectors_match_acked_contract() -> None:
    _validate_all(_load_vectors())


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        (
            "authority statement digest",
            lambda vectors: vectors["federation-discovery-v1.json"][
                "authority_statement_cases"
            ][0].__setitem__("authority_statement_digest", "sha256:" + "0" * 64),
        ),
        (
            "identity log body copy",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "identity_log_references"
            ][0].__setitem__("embedded", True),
        ),
        (
            "receiver reuse ceiling",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "selected_policies"
            ].__setitem__("receiver_reuse_max_seconds", 61),
        ),
        (
            "cohort tuple completeness",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "cohort_required_fields"
            ].remove("controller_did"),
        ),
        (
            "stable error completeness",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "stable_errors"
            ].pop(),
        ),
        (
            "mandatory mutation completeness",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "mandatory_mutations"
            ].pop(),
        ),
        (
            "mixed answer rejection",
            lambda vectors: vectors["federation-origin-ip-v1.json"]["answer_set_cases"][
                1
            ]["expected"].update(
                {
                    "allowed": True,
                    "approved_ips": ["93.184.216.34", "10.0.0.1"],
                    "reason": None,
                }
            ),
        ),
        (
            "claim-independent mismatch evidence",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "bounds"
            ].__setitem__("mismatch_memoization", "address"),
        ),
        (
            "mixed answer case deletion",
            lambda vectors: _remove_named_case(
                vectors,
                "federation-origin-ip-v1.json",
                "answer_set_cases",
                "mixed_public_private_answers_fail_closed",
            ),
        ),
        (
            "split-view case deletion",
            lambda vectors: _remove_named_case(
                vectors,
                "federation-authority-state-v1.json",
                "checkpoint_cases",
                "same_sequence_different_hash_is_split_view",
            ),
        ),
        (
            "production HTTP semantic reversal",
            lambda vectors: _named_case(
                vectors,
                "federation-origin-ip-v1.json",
                "origin_cases",
                "http_is_forbidden_in_production",
            )["expected"].update(
                {
                    "ok": True,
                    "canonical_origin": "http://registry.example",
                    "reason": None,
                }
            ),
        ),
        (
            "degraded authority semantic reversal",
            lambda vectors: _named_case(
                vectors,
                "federation-discovery-v1.json",
                "authority_lookup_cases",
                "degraded_key_never_authorizes",
            )["expected"].__setitem__("accepted", True),
        ),
        (
            "duplicate identity-log reference",
            lambda vectors: vectors["federation-authority-state-v1.json"][
                "identity_log_references"
            ].append(
                copy.deepcopy(
                    vectors["federation-authority-state-v1.json"][
                        "identity_log_references"
                    ][0]
                )
            ),
        ),
        (
            "unknown case field",
            lambda vectors: _named_case(
                vectors,
                "federation-origin-ip-v1.json",
                "ip_cases",
                "public_ipv4",
            ).__setitem__("unknown_behavior", "allow_private"),
        ),
    ],
)
def test_federation_authority_vector_mutations_fail(label, mutate) -> None:
    vectors = copy.deepcopy(_load_vectors())
    mutate(vectors)
    with pytest.raises(AssertionError, match="content is not immutable"):
        _validate_all(vectors)
