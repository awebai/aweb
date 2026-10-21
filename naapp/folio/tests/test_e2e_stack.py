from __future__ import annotations

from test_e2e_smoke import e2e_stack


def test_stack_defaults_to_the_local_make_e2e_stack() -> None:
    stack = e2e_stack({})

    assert stack.awid_url == "http://127.0.0.1:18010"
    assert stack.postgres_url == "postgresql://folio:folio@127.0.0.1:55432/folio"
    assert stack.compose == ["docker", "compose", "-p", "folio-e2e", "-f", "docker-compose.e2e.yml"]


def test_stack_follows_the_allocation_a_gate_passes_in() -> None:
    stack = e2e_stack(
        {
            "NAAPP_E2E_PROJECT": "gate-run-folio",
            "NAAPP_E2E_HOST": "aweb-docker.test",
            "NAAPP_E2E_AWID_PORT": "41001",
            "NAAPP_E2E_POSTGRES_PORT": "41002",
        }
    )

    assert stack.awid_url == "http://aweb-docker.test:41001"
    assert stack.postgres_url == "postgresql://folio:folio@aweb-docker.test:41002/folio"
    assert stack.compose == ["docker", "compose", "-p", "gate-run-folio", "-f", "docker-compose.e2e.yml"]
