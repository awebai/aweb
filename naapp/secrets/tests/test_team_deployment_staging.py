"""The team deployment journey's staging into an operator-provided secrets
directory (the real-agent run, aweb-acwd.24): a root-owned parent whose
component directories root pre-created for the staging user, and an agents/
login directory the OATS credential receiver owns. The default journey keeps
its own secrets directory under the run directory."""

import importlib.util
import os
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]


def journey():
    sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))
    spec = importlib.util.spec_from_file_location("team_deployment_journey", REPO / "scripts" / "e2e" / "team_deployment_journey.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


J = journey()
ME = os.getuid()
MY_GROUP = os.getgid()
IMAGES = {"awid": "a", "cli": "c"}


def operator_secrets(tmp_path: Path) -> Path:
    """The layout root prepares, with this test's uid standing in for root and
    for the staging user, and its gid for the agents' group."""
    secrets = tmp_path / "srv" / "secrets"
    secrets.mkdir(parents=True)
    secrets.chmod(0o755)
    for component in J.OPERATOR_COMPONENTS:
        (secrets / component).mkdir(mode=0o700)
    (secrets / "agents").mkdir()
    # A new directory may take its parent's group (BSD), not the process's.
    os.chown(secrets / "agents", ME, MY_GROUP)
    (secrets / "agents").chmod(0o750)
    return secrets


def check(secrets: Path, **owners):
    return J.check_operator_secrets(secrets, **{"root_uid": ME, "staging_uid": ME, "agents_gid": MY_GROUP, **owners})


def world(tmp_path: Path, secrets: Path | None = None):
    (tmp_path / "run").mkdir(exist_ok=True)
    return J.World(tmp_path / "run", "teamrun", IMAGES, "172.31.0.0/24", secrets_dir=secrets)


def test_the_default_journey_keeps_its_secrets_under_the_run_directory(tmp_path):
    w = world(tmp_path)
    assert w.secrets == tmp_path / "run" / "secrets"
    w.write_database_files()
    w.write_redis_files()
    assert (w.secrets / "redis" / "users.acl").exists()
    # A second staging into the same directory is refused, as before.
    with pytest.raises(FileExistsError):
        w.write_redis_files()


def test_an_operator_secrets_directory_is_staged_into_the_children_root_created(tmp_path):
    secrets = operator_secrets(tmp_path)
    check(secrets)
    w = world(tmp_path, secrets)
    assert w.secrets == secrets
    w.write_database_files()
    w.write_redis_files()
    assert (secrets / "redis" / "users.acl").exists() and (secrets / "postgres" / "roles").is_dir()
    assert (secrets / "aweb" / "redis-url").exists()


def test_the_front_files_go_into_the_pre_created_front_directory(tmp_path):
    secrets = operator_secrets(tmp_path)
    w = world(tmp_path, secrets)
    (w.world / "tls").mkdir(parents=True)
    for name in ("server.pem", "server.key"):
        (w.world / "tls" / name).write_text(name)
    w.write_front_files()
    assert (secrets / "front" / "certificate.pem").read_text() == "server.pem"


def test_the_receivers_login_directory_is_never_created_or_chowned(tmp_path, monkeypatch):
    secrets = operator_secrets(tmp_path)
    before = os.lstat(secrets / "agents")
    w = world(tmp_path, secrets)
    w.world.mkdir(parents=True)
    (w.world / "tls").mkdir()
    (w.world / "tls" / "ca.pem").write_text("ca")
    made = []
    monkeypatch.setattr(J, "run", lambda *args, **kwargs: made.append(args) or "")
    monkeypatch.setattr(J.World, "deployment", lambda self: None)
    w.configure_agents()
    assert len(made) == 1 and not any("/login" in arg for arg in made[0]), made
    assert "/state" in " ".join(made[0])
    after = os.lstat(secrets / "agents")
    assert (after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns) == (
        before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns)


def test_the_default_journey_still_creates_its_own_empty_login_directory(tmp_path, monkeypatch):
    w = world(tmp_path)
    w.world.mkdir(parents=True)
    (w.world / "tls").mkdir()
    (w.world / "tls" / "ca.pem").write_text("ca")
    w.secrets.mkdir()
    made = []
    monkeypatch.setattr(J, "run", lambda *args, **kwargs: made.append(args) or "")
    monkeypatch.setattr(J.World, "deployment", lambda self: None)
    w.configure_agents()
    assert (w.secrets / "agents").is_dir()
    assert any(f"{w.secrets / 'agents'}:/login" in arg for arg in made[0]), made


def refusal(secrets: Path, **owners) -> str:
    with pytest.raises(SystemExit) as refused:
        check(secrets, **owners)
    return str(refused.value)


def test_a_secrets_directory_not_owned_by_root_is_refused_before_any_child_is_examined(tmp_path):
    # A run's own secrets (the kept run47's, say) belong to the staging user:
    # refused on the parent, so its children, custody included, are never read.
    secrets = operator_secrets(tmp_path)
    (secrets / "signer" / "private-controller").mkdir()
    message = refusal(secrets, root_uid=ME + 1)
    assert "secrets directory" in message and "not root-owned" in message and "signer" not in message


@pytest.mark.parametrize("mode", [0o775, 0o757])
def test_a_writable_secrets_directory_is_refused(tmp_path, mode):
    secrets = operator_secrets(tmp_path)
    secrets.chmod(mode)
    assert "group- or other-writable" in refusal(secrets)


def test_a_symlinked_or_missing_secrets_directory_is_refused(tmp_path):
    secrets = operator_secrets(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(secrets)
    assert "symlink" in refusal(link)
    assert "does not exist" in refusal(tmp_path / "absent")
    assert "absolute" in refusal(Path("relative/secrets"))


@pytest.mark.parametrize("component", ["redis", "front", "signer"])
def test_a_missing_component_directory_is_refused_since_the_staging_user_cannot_create_it(tmp_path, component):
    secrets = operator_secrets(tmp_path)
    (secrets / component).rmdir()
    assert f"{component}: not pre-created" in refusal(secrets)


def test_a_component_directory_with_content_or_another_owner_is_refused(tmp_path):
    secrets = operator_secrets(tmp_path)
    (secrets / "aweb" / "stale").write_text("x")
    assert "aweb: not empty" in refusal(secrets)
    (secrets / "aweb" / "stale").unlink()
    assert "not owned by the staging user" in refusal(secrets, staging_uid=ME + 1)


def test_the_login_directory_must_be_the_receivers(tmp_path):
    secrets = operator_secrets(tmp_path)
    (secrets / "agents").chmod(0o755)
    assert "agents: must be root-owned, group" in refusal(secrets)
    (secrets / "agents").chmod(0o750)
    assert "agents: must be root-owned, group" in refusal(secrets, agents_gid=MY_GROUP + 1)
    (secrets / "agents").rmdir()
    assert "agents: must be root-owned, group" in refusal(secrets)


def test_the_login_directorys_contents_are_not_examined(tmp_path):
    # The receiver's token may already be there; staging never reads it.
    secrets = operator_secrets(tmp_path)
    (secrets / "agents" / "claude-token").write_text("not read")
    (secrets / "agents" / "claude-token").chmod(0o000)
    check(secrets)


def test_the_journey_refuses_an_operator_secrets_directory_before_it_makes_the_run(tmp_path, monkeypatch):
    # The check uses root's uid 0, which this test's directory does not have.
    secrets = operator_secrets(tmp_path)
    images = tmp_path / "images.txt"
    images.write_text("")
    monkeypatch.setattr(sys, "argv", ["journey", "--run-dir", str(tmp_path / "run47"), "--project", "p",
                                      "--images", str(images), "--secrets-dir", str(secrets)])
    with pytest.raises(SystemExit, match="not root-owned"):
        J.main()
    assert not (tmp_path / "run47").exists()


@pytest.mark.parametrize("mode", [0o755, 0o750, 0o705, 0o770, 0o701])
def test_a_component_directory_others_can_reach_is_refused_before_any_write(tmp_path, monkeypatch, mode):
    # Credentials are written with the caller's umask before each component's
    # files are chowned and chmodded; only a private directory keeps them
    # unreachable meanwhile.
    secrets = operator_secrets(tmp_path)
    (secrets / "postgres").chmod(mode)
    assert "postgres: must be private to the staging user (0700)" in refusal(secrets)
    images = tmp_path / "images.txt"
    images.write_text("")
    # The CLI's own check, with this test's uid standing in for root.
    original = J.check_operator_secrets
    monkeypatch.setattr(J, "check_operator_secrets",
                        lambda path: original(path, root_uid=ME, staging_uid=ME, agents_gid=MY_GROUP))
    monkeypatch.setattr(sys, "argv", ["journey", "--run-dir", str(tmp_path / "run"), "--project", "p",
                                      "--images", str(images), "--secrets-dir", str(secrets)])
    with pytest.raises(SystemExit, match="must be private"):
        J.main()
    assert not (tmp_path / "run").exists() and list((secrets / "postgres").iterdir()) == []
