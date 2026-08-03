#!/usr/bin/env python3
"""Prove strict authority and production activation tests kill security weakenings."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def copy_checkout(destination: Path) -> None:
    shutil.copytree(
        ROOT / "cli" / "go",
        destination / "cli" / "go",
        ignore=shutil.ignore_patterns(".cache", "aw"),
    )
    shutil.copytree(
        ROOT / "awid",
        destination / "awid",
        ignore=shutil.ignore_patterns(".venv", ".pytest_cache", "__pycache__"),
    )
    shutil.copytree(ROOT / "docs", destination / "docs")
    shutil.copytree(
        ROOT / "server",
        destination / "server",
        ignore=shutil.ignore_patterns(".venv", ".pytest_cache", "__pycache__"),
    )
    (destination / "scripts").mkdir()
    shutil.copy2(
        ROOT / "scripts" / "pytest_tracked_collection.py",
        destination / "scripts" / "pytest_tracked_collection.py",
    )
    subprocess.run(["git", "init", "-q"], cwd=destination, check=True)
    subprocess.run(
        [
            "git",
            "add",
            "-f",
            "awid/tests/test_external_authority.py",
            "server/tests/test_contacts_http.py",
            "server/tests/test_federation_activation_contacts.py",
            "server/tests/test_federation_activation_delivery.py",
            "server/tests/test_federation_envelope.py",
            "server/tests/test_messages_http.py",
            "server/tests/test_chat_http.py",
            "server/tests/test_federation_preactivation_harness.py",
            "server/tests/test_mcp_contacts_consumer.py",
            "server/tests/test_awid_registry_client.py",
        ],
        cwd=destination,
        check=True,
    )


def run_test(root: Path, pattern: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "GOCACHE": os.environ.get("GOCACHE", "/tmp/go-build"),
    }
    return subprocess.run(
        ["go", "test", "./awid", "-run", pattern, "-count=1"],
        cwd=root / "cli" / "go",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def run_python_test(root: Path, pattern: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", "/tmp/uv-cache"),
        "PYTHONPYCACHEPREFIX": os.environ.get("PYTHONPYCACHEPREFIX", "/tmp/pycache"),
    }
    return subprocess.run(
        ["uv", "run", "--frozen", "pytest", "-q", "tests/test_external_authority.py", "-k", pattern],
        cwd=root / "awid",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def run_server_tests(root: Path, *nodes: str) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR", "/tmp/uv-cache"),
        "PYTHONPYCACHEPREFIX": os.environ.get("PYTHONPYCACHEPREFIX", "/tmp/pycache"),
    }
    return subprocess.run(
        ["uv", "run", "--frozen", "pytest", "-q", *nodes],
        cwd=root / "server",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def replace_exact(path: Path, old: str, new: str) -> None:
    source = path.read_text(encoding="utf-8")
    if source.count(old) != 1:
        raise SystemExit(f"expected one mutation target in {path}, found {source.count(old)}")
    path.write_text(source.replace(old, new), encoding="utf-8")


def replace_unique_json(root: Path, old: str, new: str) -> tuple[Path, str]:
    matches = []
    for path in root.glob("*.json"):
        source = path.read_text(encoding="utf-8")
        if old in source:
            matches.append((path, source))
    if len(matches) != 1:
        raise SystemExit(f"expected one JSON mutation target, found {len(matches)}")
    path, source = matches[0]
    replace_exact(path, old, new)
    return path, source


def require_killed(result: subprocess.CompletedProcess[str], marker: str) -> None:
    if result.returncode == 0:
        raise SystemExit(f"mutation survived; expected failing case {marker}")
    if marker not in result.stdout:
        raise SystemExit(
            f"mutation failed for the wrong reason; missing {marker!r}:\n{result.stdout}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aweb-authority-mutations-") as temporary:
        checkout = Path(temporary)
        copy_checkout(checkout)
        baseline = run_test(
            checkout,
            "TestStrictFederationOriginAndIPVectors|TestStrictGoAuthorityLookupVectors",
        )
        if baseline.returncode != 0:
            raise SystemExit(f"authority mutation baseline failed:\n{baseline.stdout}")
        python_baseline = run_python_test(
            checkout, "pinned_transport_vectors or authority_lookup_vectors"
        )
        if python_baseline.returncode != 0:
            raise SystemExit(
                f"Python authority mutation baseline failed:\n{python_baseline.stdout}"
            )
        activation_nodes = (
            "tests/test_federation_activation_delivery.py::test_phase_b_rejects_missing_authority_token_without_effects",
            "tests/test_federation_activation_delivery.py::test_phase_b_forced_failure_rolls_back_every_effect",
            "tests/test_federation_activation_contacts.py::test_contact_authority_requires_exact_address_and_stable_identity",
            "tests/test_federation_envelope.py::test_verify_federation_envelope_uses_signed_address_when_wrapper_is_absent",
            "tests/test_messages_http.py::test_receive_federated_encrypted_mail_routes_ciphertext_only",
            "tests/test_contacts_http.py::test_contact_reassignment_requires_signed_explicit_acceptance",
            "tests/test_federation_preactivation_harness.py::test_http_ingress_uses_production_dns_authority_not_receiver_home_registry",
            "tests/test_federation_preactivation_harness.py::test_mcp_cross_registry_uses_production_strict_authority_not_home_registry",
            "tests/test_mcp_contacts_consumer.py::test_consumer_mcp_identity_contact_rejects_reassigned_existing_mail_conversation",
            "tests/test_mcp_contacts_consumer.py::test_consumer_mcp_identity_contact_rejects_reassigned_existing_chat_session",
            "tests/test_federation_activation_delivery.py::test_phase_b_rejects_missing_global_stored_route_key",
            "tests/test_federation_activation_delivery.py::test_phase_b_rejects_preexisting_noncanonical_stored_route",
            "tests/test_awid_registry_client.py::test_local_address_authority_ignores_cached_old_binding",
            "tests/test_federation_activation_delivery.py::test_phase_b_rejects_preexisting_external_chat_target_origin",
            "tests/test_messages_http.py::test_send_message_to_external_address_posts_federated_mail_and_projects_locally",
            "tests/test_chat_http.py::test_chat_to_external_address_posts_federated_chat_and_projects_locally",
            "tests/test_chat_http.py::test_remote_chat_route_refresh_preserves_stable_authority_error",
            "tests/test_chat_http.py::test_chat_continuation_refreshes_stale_delivery_origin_once",
        )
        activation_baseline = run_server_tests(checkout, *activation_nodes)
        if activation_baseline.returncode != 0:
            raise SystemExit(
                f"Federation activation mutation baseline failed:\n{activation_baseline.stdout}"
            )

        authority = checkout / "cli" / "go" / "awid" / "federation_authority.go"
        replace_exact(
            authority,
            '\tnetip.MustParsePrefix("100.64.0.0/10"),\n',
            "",
        )
        require_killed(
            run_test(checkout, "TestStrictFederationOriginAndIPVectors"),
            "ipv4_shared",
        )
        shutil.copy2(ROOT / "cli" / "go" / "awid" / "federation_authority.go", authority)

        registry = (
            checkout
            / "cli"
            / "go"
            / "awid"
            / "federation_external_registry.go"
        )
        replace_exact(
            registry,
            'if domainErr != nil || namespaceDomain != domain || namespace.ControllerDID == "" ||\n\t\t(authority.Selection == "dns" && namespace.ControllerDID != authority.ControllerDID) {',
            'if domainErr != nil || namespaceDomain != domain || namespace.ControllerDID == "" {',
        )
        require_killed(
            run_test(checkout, "TestStrictGoAuthorityLookupVectors/dns_controller_mismatch"),
            "dns_controller_mismatch",
        )
        shutil.copy2(
            ROOT / "cli" / "go" / "awid" / "federation_external_registry.go",
            registry,
        )

        vector, original_vector = replace_unique_json(
            checkout / "docs" / "vectors",
            '      "subsequent_answers": ["10.0.0.1"],',
            '      "subsequent_answers": ["93.184.216.34"],',
        )
        require_killed(
            run_python_test(
                checkout,
                "pinned_transport_vectors and pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
            ),
            "pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
        )
        require_killed(
            run_test(
                checkout,
                "TestStrictFederationOriginAndIPVectors/pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
            ),
            "pinned_ip_preserves_hostname_tls_and_disables_ambient_state",
        )
        vector.write_text(original_vector, encoding="utf-8")

        vector, _ = replace_unique_json(
            checkout / "docs" / "vectors",
            '"fallback_contacted": false, "full_log_required": true}',
            '"fallback_contacted": false, "full_log_required": false}',
        )
        require_killed(
            run_python_test(
                checkout,
                "authority_lookup_vectors and degraded_key_never_authorizes",
            ),
            "degraded_key_never_authorizes",
        )
        require_killed(
            run_test(
                checkout,
                "TestStrictGoAuthorityLookupVectors/degraded_key_never_authorizes",
            ),
            "degraded_key_never_authorizes",
        )

        delivery = checkout / "server" / "src" / "aweb" / "federation" / "delivery.py"
        original_delivery = delivery.read_text(encoding="utf-8")
        replace_exact(
            delivery,
            "        controller_did = await _require_phase_a(tx, envelope, authority_token)\n",
            "        controller_did = None\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[0]),
            "test_phase_b_rejects_missing_authority_token_without_effects",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        contacts = checkout / "server" / "src" / "aweb" / "messaging" / "contacts.py"
        original_contacts = contacts.read_text(encoding="utf-8")
        replace_exact(
            contacts,
            "          AND contact_did_aw = $3\n",
            "          AND $3::text IS NOT NULL\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[2]),
            "test_contact_authority_requires_exact_address_and_stable_identity",
        )
        contacts.write_text(original_contacts, encoding="utf-8")

        replace_exact(
            delivery,
            "        if before_commit is not None:\n            await before_commit()\n",
            "        if before_commit is not None:\n            return result\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[1]),
            "test_phase_b_forced_failure_rolls_back_every_effect",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        replace_exact(
            delivery,
            """        if (
            envelope.sender_did_aw.startswith("did:aw:")
            and not sender_key
        ) or (sender_key and sender_key != envelope.sender_current_did_key):
            raise FederationAuthorityError("federation_conversation_invalid")
        if (
            envelope.target_did_aw.startswith("did:aw:")
            and not target_key
        ) or (target_key and target_key != envelope.target_current_did_key):
            raise FederationAuthorityError("federation_conversation_invalid")
""",
            """        if sender_key and sender_key != envelope.sender_current_did_key:
            raise FederationAuthorityError("federation_conversation_invalid")
        if target_key and target_key != envelope.target_current_did_key:
            raise FederationAuthorityError("federation_conversation_invalid")
""",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[10]),
            "test_phase_b_rejects_missing_global_stored_route_key",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        replace_exact(
            delivery,
            """        if _route_value(target.get("delivery_origin")):
            raise FederationAuthorityError("federation_conversation_invalid")
""",
            "",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[13]),
            "test_phase_b_rejects_preexisting_external_chat_target_origin",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        replace_exact(
            delivery,
            """        if include_transport_hint and (
            _route_value(sender.get("transport_hint"))
            != "federation:" + _route_value(envelope.sender_delivery_origin)
            or _route_value(target.get("transport_hint")) != "local"
        ):
            raise FederationAuthorityError("federation_conversation_invalid")
""",
            "",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[11]),
            "test_phase_b_rejects_preexisting_noncanonical_stored_route",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        replace_exact(
            delivery,
            '    if envelope.content_mode != "encrypted_v2":\n        return\n',
            "    return\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[4]),
            "test_receive_federated_encrypted_mail_routes_ciphertext_only",
        )
        delivery.write_text(original_delivery, encoding="utf-8")

        federation_route = checkout / "server" / "src" / "aweb" / "routes" / "federation.py"
        original_federation_route = federation_route.read_text(encoding="utf-8")
        replace_exact(
            federation_route,
            """            authorized = await authority.authorize(
                AuthorityClaim(
                    canonical_address=sender_address,
                    did_aw=envelope.sender_did_aw,
                    current_did_key=envelope.sender_current_did_key,
                    delivery_origin=sender_origin or "",
                ),
                source_ip=str(request.client.host if request.client else "unknown"),
            )
""",
            """            authorized = await registry_client.resolve_key(
                envelope.sender_did_aw
            )
""",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[6]),
            "test_http_ingress_uses_production_dns_authority_not_receiver_home_registry",
        )
        federation_route.write_text(original_federation_route, encoding="utf-8")

        mcp_mail = checkout / "server" / "src" / "aweb" / "mcp" / "tools" / "mail.py"
        original_mcp_mail = mcp_mail.read_text(encoding="utf-8")
        replace_exact(
            mcp_mail,
            """                    resolved = await federation_authority.resolve_contact(
                        recipient_ref,
                        source_ip="mcp:" + str(auth.did_key or auth.did_aw or "unknown"),
                    )
""",
            """                    resolved = await registry_client.resolve_address(
                        domain, name, did_key=auth.did_key
                    )
""",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[7]),
            "test_mcp_cross_registry_uses_production_strict_authority_not_home_registry",
        )
        mcp_mail.write_text(original_mcp_mail, encoding="utf-8")

        mcp_chat = checkout / "server" / "src" / "aweb" / "mcp" / "tools" / "chat.py"
        original_mcp_chat = mcp_chat.read_text(encoding="utf-8")
        replace_exact(
            mcp_chat,
            """                        resolved = await federation_authority.resolve_contact(
                            to_address,
                            source_ip="mcp:"
                            + str(auth.did_key or auth.did_aw or "unknown"),
                        )
""",
            """                        resolved = await registry_client.resolve_address(
                            domain, name, did_key=auth.did_key
                        )
""",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[7]),
            "test_mcp_cross_registry_uses_production_strict_authority_not_home_registry",
        )
        mcp_chat.write_text(original_mcp_chat, encoding="utf-8")

        mcp_contacts = (
            checkout
            / "server"
            / "src"
            / "aweb"
            / "mcp"
            / "tools"
            / "contacts.py"
        )
        replace_exact(
            mcp_contacts,
            """        target = await _resolve_contact_target(
            db_infra,
            registry_client=registry_client,
            federation_authority=federation_authority,
            contact=contact,
        )
""",
            """        target = await _target_from_contact_reference(
            db_infra, contact=contact
        )
""",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[8], activation_nodes[9]),
            "test_consumer_mcp_identity_contact_rejects_reassigned_existing_mail_conversation",
        )

        local_contacts = (
            checkout / "server" / "src" / "aweb" / "messaging" / "contacts.py"
        )
        original_local_contacts = local_contacts.read_text(encoding="utf-8")
        replace_exact(
            local_contacts,
            "        resolved = await registry_client.resolve_address_fresh(domain, name)\n        namespace = await registry_client.get_namespace_fresh(domain)\n",
            "        resolved = await registry_client.resolve_address(domain, name)\n        namespace = await registry_client.get_namespace(domain)\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[12]),
            "test_local_address_authority_ignores_cached_old_binding",
        )
        local_contacts.write_text(original_local_contacts, encoding="utf-8")

        envelope = checkout / "server" / "src" / "aweb" / "federation" / "envelope.py"
        replace_exact(
            envelope,
            "    except Exception as exc:\n        raise FederationEnvelopeError(\"Invalid federation message signature\") from exc\n    return model.model_copy(update={\"sender_address\": signed_sender_address})\n",
            "    except Exception as exc:\n        raise FederationEnvelopeError(\"Invalid federation message signature\") from exc\n    return model\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[3]),
            "test_verify_federation_envelope_uses_signed_address_when_wrapper_is_absent",
        )

        contacts_route = checkout / "server" / "src" / "aweb" / "routes" / "contacts.py"
        replace_exact(
            contacts_route,
            "            or not payload.accept_reassignment\n",
            "",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[5]),
            "test_contact_reassignment_requires_signed_explicit_acceptance",
        )

        messages_route = checkout / "server" / "src" / "aweb" / "routes" / "messages.py"
        replace_exact(
            messages_route,
            '                    "current_did_key": sender_current_did,\n',
            "",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[14]),
            "test_send_message_to_external_address_posts_federated_mail_and_projects_locally",
        )

        chat_service = checkout / "server" / "src" / "aweb" / "messaging" / "chat.py"
        replace_exact(
            chat_service,
            '                "transport_hint": transport_hint or (\n                    "federation:" + delivery_origin if delivery_origin else "local"\n                ),\n',
            '                "transport_hint": "chat",\n',
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[15]),
            "test_chat_to_external_address_posts_federated_chat_and_projects_locally",
        )

        chat_route = checkout / "server" / "src" / "aweb" / "routes" / "chat.py"
        original_chat_route = chat_route.read_text(encoding="utf-8")
        replace_exact(
            chat_route,
            '                    "_strict_authority_route_current": strict_authority is not None,\n',
            "",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[15]),
            "test_chat_to_external_address_posts_federated_chat_and_projects_locally",
        )
        chat_route.write_text(original_chat_route, encoding="utf-8")

        replace_exact(
            chat_route,
            "    except (HTTPException, FederationAuthorityError):\n        raise\n",
            "    except HTTPException:\n        raise\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[16]),
            "test_remote_chat_route_refresh_preserves_stable_authority_error",
        )
        chat_route.write_text(original_chat_route, encoding="utf-8")

        replace_exact(
            chat_route,
            "                current_did_key = $4,\n                transport_hint = 'federation:' || $3\n",
            "                current_did_key = $4\n",
        )
        require_killed(
            run_server_tests(checkout, activation_nodes[17]),
            "test_chat_continuation_refreshes_stale_delivery_origin_once",
        )

    print(
        "authority and activation mutation controls passed: network authority, "
        "Phase-A gating, identity-bound contacts, Phase-B atomicity, signed-address "
        "extraction, E2E no-downgrade, HTTP/MCP strict composition, contact-conversation "
        "binding, route integrity, outbound continuation projection, refreshed chat "
        "routes, stable authority errors, fresh local authority, and reassignment "
        "acceptance weakenings were killed"
    )


if __name__ == "__main__":
    main()
