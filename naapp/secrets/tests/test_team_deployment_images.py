"""The team deployment journey's images: everything the journey requires is
something scripts/e2e/team-deployment-images.sh builds."""

import importlib.util
import re
import sys
from pathlib import Path

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
