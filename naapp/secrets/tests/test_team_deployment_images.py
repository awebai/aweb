"""The team deployment journey's images: everything the journey requires is
something scripts/e2e/team-deployment-images.sh builds."""

import importlib.util
import re
import sys
from pathlib import Path

import team_journey_support

REPO = Path(__file__).resolve().parents[3]
BUILDER = REPO / "scripts" / "e2e" / "team-deployment-images.sh"


def journey():
    sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))
    spec = importlib.util.spec_from_file_location(
        "team_deployment_journey", REPO / "scripts" / "e2e" / "team_deployment_journey.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_builder_builds_every_image_the_journey_requires():
    built = set(re.findall(r"^\s*build\s+([a-z-]+)\s", BUILDER.read_text(), re.M))
    assert journey().REQUIRED_IMAGES <= built, journey().REQUIRED_IMAGES - built


def test_the_loader_keeps_only_image_references(tmp_path):
    images = tmp_path / "images.txt"
    lines = [
        f"{name} localhost:5000/{name}@sha256:{'a' * 64}"
        for name in sorted(journey().REQUIRED_IMAGES)
    ]
    images.write_text("\n".join(lines + ["source " + "b" * 40]) + "\n")
    loaded = journey().load_images(images)
    assert set(loaded) == journey().REQUIRED_IMAGES


def test_a_complete_current_manifest_needs_no_historical_control_image(tmp_path):
    names = {"aweb", "secrets", "logs", "awid", "cli", "chromium"}
    images = tmp_path / "images.txt"
    images.write_text(
        "".join(f"{name} localhost:5000/{name}@sha256:{'a' * 64}\n" for name in names)
    )
    assert set(journey().load_images(images)) == names == journey().REQUIRED_IMAGES


def test_every_genuinely_required_image_is_required_by_the_loader(tmp_path):
    import pytest

    names = journey().REQUIRED_IMAGES
    for missing in names:
        images = tmp_path / "images.txt"
        images.write_text(
            "".join(
                f"{name} localhost:5000/{name}@sha256:{'a' * 64}\n" for name in names - {missing}
            )
        )
        with pytest.raises(SystemExit, match=missing):
            journey().load_images(images)


def test_the_owner_names_the_approvers_lab_mailbox_as_the_holdings_notice_contact():
    # secrets.owner declares a notice contact, so aw refuses a designate
    # without one; the approver's mailbox at the lab's SMTP receives the
    # holding's later notices.
    command = team_journey_support.designate_command(
        "lfteam-secrets",
        "secrets.owner",
        "did:aw:approver",
        "/world/holder-app.json",
        "approver@lf.test",
    )
    assert command == [
        "aw",
        "app",
        "role",
        "designate",
        "lfteam-secrets",
        "--role",
        "secrets.owner",
        "--principal",
        "did:aw:approver",
        "--credential",
        "/world/holder-app.json",
        "--notice-contact",
        "approver@lf.test",
        "--yes",
    ]


def binding(app, kind, hook, binding_id, state="pending", active_from=None, generation=1):
    return {
        "app_id": f"lfteam-{app}",
        "kind": kind,
        "hook": hook,
        "binding_id": binding_id,
        "state": state,
        "active_from": active_from,
        "installation_id": f"{app}-installation",
        "generation": generation,
        "digest": f"sha256:{app}-manifest",
    }


LOGS = [
    binding("logs", "registration", hook, f"logs-{hook}")
    for hook in (
        "post-command-hook",
        "post-governance-hook",
        "post-manifest-command-hook",
        "post-mutation-hook",
        "post-secret-use-hook",
    )
] + [binding("logs", "production", "post-governance-hook", "logs-production")]
SECRETS = [
    binding("secrets", "production", "post-governance-hook", "secrets-governance"),
    binding("secrets", "production", "post-secret-use-hook", "secrets-secret-use"),
]


def test_the_deployment_activates_the_audit_critical_hook_pairs_and_logs_own_production():
    assert set(team_journey_support.REQUIRED_HOOK_BINDINGS) == {
        ("secrets", "production", "post-governance-hook"),
        ("secrets", "production", "post-secret-use-hook"),
        ("logs", "registration", "post-governance-hook"),
        ("logs", "registration", "post-secret-use-hook"),
        ("logs", "production", "post-governance-hook"),
    }


def test_each_required_binding_is_named_by_its_app_kind_and_hook():
    selected = team_journey_support.select_hook_bindings({"logs": LOGS, "secrets": SECRETS})
    assert {key: row["binding_id"] for key, row in selected.items()} == {
        ("secrets", "production", "post-governance-hook"): "secrets-governance",
        ("secrets", "production", "post-secret-use-hook"): "secrets-secret-use",
        ("logs", "registration", "post-governance-hook"): "logs-post-governance-hook",
        ("logs", "registration", "post-secret-use-hook"): "logs-post-secret-use-hook",
        ("logs", "production", "post-governance-hook"): "logs-production",
    }


def test_an_apps_bindings_from_more_than_one_installation_generation_or_manifest_are_refused():
    import pytest

    mixed = SECRETS[:1] + [
        binding("secrets", "production", "post-secret-use-hook", "secrets-secret-use", generation=2)
    ]
    with pytest.raises(SystemExit, match="secrets"):
        team_journey_support.select_hook_bindings({"logs": LOGS, "secrets": mixed})


def test_a_required_binding_missing_or_listed_twice_is_refused():
    import pytest

    with pytest.raises(SystemExit, match="post-secret-use-hook"):
        team_journey_support.select_hook_bindings({"logs": LOGS, "secrets": SECRETS[:1]})
    with pytest.raises(SystemExit, match="post-governance-hook"):
        team_journey_support.select_hook_bindings({"logs": LOGS, "secrets": SECRETS + SECRETS[:1]})


def test_the_bindings_are_ready_once_the_latest_active_from_has_passed_with_a_margin():
    import datetime

    selected = [
        binding("logs", "registration", "post-governance-hook", "a"),
        binding("secrets", "production", "post-governance-hook", "b"),
    ]
    listed = [
        binding(
            "logs", "registration", "post-governance-hook", "a", "active", "2026-11-13T10:00:00.5Z"
        ),
        binding(
            "secrets", "production", "post-governance-hook", "b", "active", "2026-11-13T10:00:03Z"
        ),
        binding("logs", "registration", "post-command-hook", "c", "pending"),
    ]
    ready = team_journey_support.hooks_ready_at(
        listed, selected, margin=datetime.timedelta(seconds=10)
    )
    assert ready == datetime.datetime(2026, 11, 13, 10, 0, 13, tzinfo=datetime.UTC)


def test_an_active_binding_is_ready_only_as_the_installation_generation_and_manifest_selected():
    import pytest

    selected = [binding("secrets", "production", "post-governance-hook", "b")]
    moved = [
        binding(
            "secrets",
            "production",
            "post-governance-hook",
            "b",
            "active",
            "2026-11-13T10:00:03Z",
            generation=2,
        )
    ]
    with pytest.raises(SystemExit, match="b"):
        team_journey_support.hooks_ready_at(moved, selected)


def test_a_selected_binding_not_active_or_without_active_from_is_not_ready():
    import datetime

    import pytest

    margin = datetime.timedelta(seconds=10)
    selected = [binding("secrets", "production", "post-governance-hook", "b")]
    with pytest.raises(SystemExit, match="b"):
        team_journey_support.hooks_ready_at(
            [binding("secrets", "production", "post-governance-hook", "b", "pending")],
            selected,
            margin=margin,
        )
    with pytest.raises(SystemExit, match="b"):
        team_journey_support.hooks_ready_at(
            [binding("secrets", "production", "post-governance-hook", "b", "active")],
            selected,
            margin=margin,
        )


def test_logs_purge_ledger_is_a_database_and_role_of_its_own_with_its_dsn_in_logs_secrets():
    import re

    databases = journey().DATABASES
    assert databases["logs"] == "logs/database-url"
    assert databases["logsledger"] == "logs/purge-ledger-database-url"
    # postgres-roles.sh creates one role and database per name it accepts.
    roles = (REPO / "deploy" / "team" / "postgres-roles.sh").read_text()
    assert "*[!a-z]*)" in roles
    assert all(re.fullmatch(r"[a-z]+", role) and role != "postgres" for role in databases)
    assert len(set(databases.values())) == len(databases)
