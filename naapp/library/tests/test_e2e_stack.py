from __future__ import annotations

from test_e2e_smoke import e2e_stack


def test_stack_defaults_to_the_local_make_e2e_stack() -> None:
    stack = e2e_stack({})

    assert stack.awid_url == "http://127.0.0.1:18010"
    assert stack.postgres_url == "postgresql://library:library@127.0.0.1:55432/library"
    assert stack.compose == ["docker", "compose", "-p", "library-e2e", "-f", "docker-compose.e2e.yml"]


def test_stack_follows_the_allocation_a_gate_passes_in() -> None:
    stack = e2e_stack(
        {
            "NAAPP_E2E_PROJECT": "gate-run-library",
            "NAAPP_E2E_HOST": "aweb-docker.test",
            "NAAPP_E2E_AWID_PORT": "41001",
            "NAAPP_E2E_POSTGRES_PORT": "41002",
        }
    )

    assert stack.awid_url == "http://aweb-docker.test:41001"
    assert stack.postgres_url == "postgresql://library:library@aweb-docker.test:41002/library"
    assert stack.compose == ["docker", "compose", "-p", "gate-run-library", "-f", "docker-compose.e2e.yml"]
