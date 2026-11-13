"""The team deployment journey's images: everything the journey requires is
something scripts/e2e/team-deployment-images.sh builds."""

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
BUILDER = REPO / "scripts" / "e2e" / "team-deployment-images.sh"


def journey():
    sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))
    spec = importlib.util.spec_from_file_location("team_deployment_journey", REPO / "scripts" / "e2e" / "team_deployment_journey.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_builder_builds_every_image_the_journey_requires():
    built = set(re.findall(r"^\s*build\s+([a-z-]+)\s", BUILDER.read_text(), re.M))
    assert journey().REQUIRED_IMAGES <= built, journey().REQUIRED_IMAGES - built


def test_the_control_cli_is_built_from_a_pinned_commit_and_recorded_with_it():
    text = BUILDER.read_text()
    pinned = re.search(r'^control="\$\{TEAM_DEPLOYMENT_CONTROL_CLI_COMMIT:-([0-9a-f]{40})\}"$', text, re.M)
    assert pinned, "the control CLI's source must be a full, fixed commit"
    assert "cli-control-source" in text


def test_the_loader_keeps_only_image_references(tmp_path):
    images = tmp_path / "images.txt"
    lines = [f"{name} localhost:5000/{name}@sha256:{'a' * 64}" for name in sorted(journey().REQUIRED_IMAGES)]
    images.write_text("\n".join(lines + ["cli-control-source " + "b" * 40]) + "\n")
    loaded = journey().load_images(images)
    assert set(loaded) == journey().REQUIRED_IMAGES


def test_a_manifest_without_the_control_cli_is_refused(tmp_path):
    import pytest

    images = tmp_path / "images.txt"
    names = sorted(journey().REQUIRED_IMAGES - {"cli-control"})
    images.write_text("".join(f"{name} localhost:5000/{name}@sha256:{'a' * 64}\n" for name in names))
    with pytest.raises(SystemExit, match="cli-control"):
        journey().load_images(images)


def builder(tmp_path, control: str | None):
    """The builder up to its first Docker call, with a docker that refuses to run."""
    import os
    import subprocess

    stub = tmp_path / "bin"
    stub.mkdir(exist_ok=True)
    (stub / "docker").write_text("#!/bin/sh\necho DOCKER-CALLED >&2\nexit 97\n")
    (stub / "docker").chmod(0o755)
    env = {**os.environ, "PATH": f"{stub}:{os.environ['PATH']}"}
    env.pop("TEAM_DEPLOYMENT_CONTROL_CLI_COMMIT", None)
    if control is not None:
        env["TEAM_DEPLOYMENT_CONTROL_CLI_COMMIT"] = control
    return subprocess.run([str(BUILDER), "localhost:5000", str(tmp_path / "images.txt")], env=env,
                          capture_output=True, text=True, timeout=60)


def test_the_control_commit_must_be_a_full_commit_id(tmp_path):
    import pytest

    for given in ("HEAD", "main", "74e70251c", "74E70251CAD33177BD964E432AD939585B8EA79C"):
        result = builder(tmp_path, given)
        assert result.returncode != 0 and "full commit id" in result.stderr, (given, result.stderr)
        assert "DOCKER-CALLED" not in result.stderr
    unknown = builder(tmp_path, "0" * 40)
    assert unknown.returncode != 0 and "not a commit in this checkout" in unknown.stderr, unknown.stderr
    if not (REPO / ".git").exists():
        pytest.skip("no git metadata")


def test_a_full_commit_id_is_accepted_and_reaches_the_builds(tmp_path):
    import subprocess

    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    result = builder(tmp_path, head)
    # Past the control check: the next refusal is the clean-checkout check or Docker itself.
    assert "full commit id" not in result.stderr and "not a commit in this checkout" not in result.stderr, result.stderr


def test_the_owner_names_the_approvers_lab_mailbox_as_the_holdings_notice_contact():
    # secrets.owner declares a notice contact, so aw refuses a designate
    # without one; the approver's mailbox at the lab's SMTP receives the
    # holding's later notices.
    command = journey().designate_command("lfteam-secrets", "secrets.owner", "did:aw:approver",
                                          "/world/holder-app.json", "approver@lf.test")
    assert command == ["aw", "app", "role", "designate", "lfteam-secrets", "--role", "secrets.owner",
                       "--principal", "did:aw:approver", "--credential", "/world/holder-app.json",
                       "--notice-contact", "approver@lf.test", "--yes"]


def binding(app, kind, hook, binding_id, state="pending", active_from=None, generation=1):
    return {"app_id": f"lfteam-{app}", "kind": kind, "hook": hook, "binding_id": binding_id, "state": state,
            "active_from": active_from, "installation_id": f"{app}-installation", "generation": generation,
            "digest": f"sha256:{app}-manifest"}


LOGS = [binding("logs", "registration", hook, f"logs-{hook}") for hook in (
    "post-command-hook", "post-governance-hook", "post-manifest-command-hook", "post-mutation-hook",
    "post-secret-use-hook")] + [binding("logs", "production", "post-governance-hook", "logs-production")]
SECRETS = [binding("secrets", "production", "post-governance-hook", "secrets-governance"),
           binding("secrets", "production", "post-secret-use-hook", "secrets-secret-use")]


def test_the_deployment_activates_the_audit_critical_hook_pairs_and_logs_own_production():
    assert set(journey().REQUIRED_HOOK_BINDINGS) == {
        ("secrets", "production", "post-governance-hook"),
        ("secrets", "production", "post-secret-use-hook"),
        ("logs", "registration", "post-governance-hook"),
        ("logs", "registration", "post-secret-use-hook"),
        ("logs", "production", "post-governance-hook"),
    }


def test_each_required_binding_is_named_by_its_app_kind_and_hook():
    selected = journey().select_hook_bindings({"logs": LOGS, "secrets": SECRETS})
    assert {key: row["binding_id"] for key, row in selected.items()} == {
        ("secrets", "production", "post-governance-hook"): "secrets-governance",
        ("secrets", "production", "post-secret-use-hook"): "secrets-secret-use",
        ("logs", "registration", "post-governance-hook"): "logs-post-governance-hook",
        ("logs", "registration", "post-secret-use-hook"): "logs-post-secret-use-hook",
        ("logs", "production", "post-governance-hook"): "logs-production",
    }


def test_an_apps_bindings_from_more_than_one_installation_generation_or_manifest_are_refused():
    import pytest

    mixed = SECRETS[:1] + [binding("secrets", "production", "post-secret-use-hook", "secrets-secret-use",
                                   generation=2)]
    with pytest.raises(SystemExit, match="secrets"):
        journey().select_hook_bindings({"logs": LOGS, "secrets": mixed})


def test_a_required_binding_missing_or_listed_twice_is_refused():
    import pytest

    with pytest.raises(SystemExit, match="post-secret-use-hook"):
        journey().select_hook_bindings({"logs": LOGS, "secrets": SECRETS[:1]})
    with pytest.raises(SystemExit, match="post-governance-hook"):
        journey().select_hook_bindings({"logs": LOGS, "secrets": SECRETS + SECRETS[:1]})


def test_the_bindings_are_ready_once_the_latest_active_from_has_passed_with_a_margin():
    import datetime

    selected = [binding("logs", "registration", "post-governance-hook", "a"),
                binding("secrets", "production", "post-governance-hook", "b")]
    listed = [binding("logs", "registration", "post-governance-hook", "a", "active", "2026-11-13T10:00:00.5Z"),
              binding("secrets", "production", "post-governance-hook", "b", "active", "2026-11-13T10:00:03Z"),
              binding("logs", "registration", "post-command-hook", "c", "pending")]
    ready = journey().hooks_ready_at(listed, selected, margin=datetime.timedelta(seconds=10))
    assert ready == datetime.datetime(2026, 11, 13, 10, 0, 13, tzinfo=datetime.UTC)


def test_an_active_binding_is_ready_only_as_the_installation_generation_and_manifest_selected():
    import pytest

    selected = [binding("secrets", "production", "post-governance-hook", "b")]
    moved = [binding("secrets", "production", "post-governance-hook", "b", "active", "2026-11-13T10:00:03Z",
                     generation=2)]
    with pytest.raises(SystemExit, match="b"):
        journey().hooks_ready_at(moved, selected)


def test_a_selected_binding_not_active_or_without_active_from_is_not_ready():
    import datetime

    import pytest

    margin = datetime.timedelta(seconds=10)
    selected = [binding("secrets", "production", "post-governance-hook", "b")]
    with pytest.raises(SystemExit, match="b"):
        journey().hooks_ready_at([binding("secrets", "production", "post-governance-hook", "b", "pending")],
                                 selected, margin=margin)
    with pytest.raises(SystemExit, match="b"):
        journey().hooks_ready_at([binding("secrets", "production", "post-governance-hook", "b", "active")],
                                 selected, margin=margin)


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


FIVE_SITES = "".join(f"{host}:443 {{\n  reverse_proxy {host}:80\n}}\n" for host in (
    "aweb.lf.test", "api.secrets.lf.test", "console.secrets.lf.test", "api.logs.lf.test", "console.logs.lf.test"))
WITH_SIGNER = FIVE_SITES + "signer.lf.test:443 {\n  reverse_proxy signer:8080\n}\n"


def prepare_drop(tmp_path, text):
    rendered = tmp_path / "Caddyfile"
    rendered.write_text(text)
    reloads = []
    drop = journey().PrepareDrop(rendered, "signer.lf.test", "signer:8080", lambda: reloads.append(rendered.read_text()))
    return rendered, reloads, drop


def test_the_prepare_drop_uses_the_front_as_rendered_when_enabled_not_when_built(tmp_path):
    # Built while the front had no signer site; the signer's start renders it later.
    rendered, reloads, drop = prepare_drop(tmp_path, FIVE_SITES)
    rendered.write_text(WITH_SIGNER)
    drop.enable()
    enabled = rendered.read_text()
    # One matcher, defined in the signer's site and used by its one abort.
    assert enabled.count("@prepare {") == 1 and "signer.lf.test:443 {\n  @prepare {" in enabled
    assert enabled.count("abort") == 1 and "reverse_proxy signer:8080" in enabled
    assert all(f"{host}:443 {{" in enabled for host in ("aweb.lf.test", "api.logs.lf.test"))
    assert reloads == [enabled]
    drop.disable()
    assert rendered.read_text() == WITH_SIGNER
    assert reloads == [enabled, WITH_SIGNER]


def test_the_prepare_drop_restores_the_front_it_replaced_when_the_step_fails(tmp_path):
    import pytest

    rendered, reloads, drop = prepare_drop(tmp_path, WITH_SIGNER)
    with pytest.raises(RuntimeError):
        drop.enable()
        try:
            raise RuntimeError("the step under the drop failed")
        finally:
            drop.disable()
    assert rendered.read_text() == WITH_SIGNER and reloads[-1] == WITH_SIGNER


@pytest.mark.parametrize("text", [FIVE_SITES, WITH_SIGNER + "signer.lf.test:443 {\n  respond 200\n}\n"])
def test_the_prepare_drop_refuses_a_front_without_exactly_one_signer_site_and_changes_nothing(tmp_path, text):
    import pytest

    rendered, reloads, drop = prepare_drop(tmp_path, text)
    with pytest.raises(SystemExit, match="signer.lf.test"):
        drop.enable()
    assert rendered.read_text() == text and reloads == []
    drop.disable()
    assert rendered.read_text() == text and reloads == []
