from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import library_prod_gate as gate

EXPECTED_VERSION = "0.1.8"
EXPECTED_DIGEST = f"sha256:{'a' * 64}"


def payload(runtime: str, *, managed: list[str] | None = None) -> dict:
    paths = [".aw/profile/ref.json", "AGENTS.md", "CLAUDE.md"]
    ref = {
        "profile_ref": "developer",
        "profile_version": EXPECTED_VERSION,
        "profile_digest": EXPECTED_DIGEST,
        "runtime_kind": runtime,
        "managed_set": paths if managed is None else managed,
        "source_blueprint_ref": "aweb.team",
        "source_blueprint_version": "0.1.12",
    }
    return {
        "home_files": [
            {"path": paths[0], "content_utf8": json.dumps(ref)},
            {"path": paths[1], "content_utf8": "# Developer\n"},
            {"path": paths[2], "kind": "symlink", "target": "AGENTS.md"},
        ]
    }


def test_candidate_requires_positional_managed_set() -> None:
    summary = gate.validate_candidate_payload(
        payload("claude-code"),
        "claude-code",
        expected_version=EXPECTED_VERSION,
        expected_digest=EXPECTED_DIGEST,
    )
    assert summary["managed_set_count"] == 3
    same_set_wrong_order = ["AGENTS.md", "CLAUDE.md", ".aw/profile/ref.json"]
    with pytest.raises(gate.GateError, match="index 0"):
        gate.validate_candidate_payload(
            payload("claude-code", managed=same_set_wrong_order),
            "claude-code",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


@pytest.mark.parametrize(
    "unsafe",
    [
        ".",
        "foo//bar",
        "foo/",
        "foo/./bar",
        "scheme://host",
        "../escape",
        "nul\x00path",
        "line\npath",
    ],
)
def test_managed_paths_must_be_canonical_and_safe(unsafe: str) -> None:
    with pytest.raises(gate.GateError, match="noncanonical or unsafe"):
        gate.validate_relative_paths([unsafe])


def test_candidate_rejects_unapproved_profile_pin() -> None:
    with pytest.raises(gate.GateError, match="profile_digest"):
        gate.validate_candidate_payload(
            payload("pi"),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=f"sha256:{'b' * 64}",
        )


def test_candidate_rejects_duplicates() -> None:
    with pytest.raises(gate.GateError, match="duplicate"):
        gate.validate_candidate_payload(
            payload("pi", managed=[".aw/profile/ref.json", "AGENTS.md", "AGENTS.md"]),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_recovery_requires_known_old_fingerprint() -> None:
    old = payload("pi")
    ref_entry = old["home_files"][0]
    ref = json.loads(ref_entry["content_utf8"])
    ref.pop("runtime_kind")
    ref.pop("managed_set")
    ref_entry["content_utf8"] = json.dumps(ref)
    summary = gate.validate_recovery_payload(
        old,
        "pi",
        expected_version=EXPECTED_VERSION,
        expected_digest=EXPECTED_DIGEST,
    )
    assert summary["gate"] == "raw-recovery"
    with pytest.raises(gate.GateError, match="not the known"):
        gate.validate_recovery_payload(
            payload("pi"),
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )
    present_but_empty = payload("pi")
    empty_ref_entry = present_but_empty["home_files"][0]
    empty_ref = json.loads(empty_ref_entry["content_utf8"])
    empty_ref["runtime_kind"] = ""
    empty_ref["managed_set"] = []
    empty_ref_entry["content_utf8"] = json.dumps(empty_ref)
    with pytest.raises(gate.GateError, match="not the known"):
        gate.validate_recovery_payload(
            present_but_empty,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_recovery_rejects_unrelated_nonzero_exit(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises(gate.GateError, match="expected schema rejection"):
        gate.require_recovery_rejection(Path("/usr/bin/false"), home, "pi", tmp_path)


def test_recovery_accepts_only_exact_schema_rejection(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class Completed:
        returncode = 1

    def expected_failure(command, cwd, stdout, stderr, check):
        stderr.write(
            b'Error: library materialize response runtime_kind "pi" does not match ref.json ""\n'
        )
        return Completed()

    monkeypatch.setattr(gate.subprocess, "run", expected_failure)
    home = tmp_path / "home"
    home.mkdir()
    result = gate.require_recovery_rejection(Path("/released/aw"), home, "pi", tmp_path)
    assert result["exit"] == 1


def test_materialized_ref_is_strict(tmp_path: Path) -> None:
    path = tmp_path / ".aw" / "profile" / "ref.json"
    path.parent.mkdir(parents=True)
    (tmp_path / "AGENTS.md").write_text("# Developer\n")
    path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": ["AGENTS.md", ".aw/profile/ref.json"],
            }
        )
    )
    assert (
        gate.validate_materialized_ref(
            path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )["runtime_kind"]
        == "pi"
    )
    with pytest.raises(gate.GateError, match="mismatch"):
        gate.validate_materialized_ref(
            path,
            "claude-code",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_materialized_ref_rejects_broken_or_escaping_symlinks(tmp_path: Path) -> None:
    home = tmp_path / "home"
    ref_path = home / ".aw" / "profile" / "ref.json"
    ref_path.parent.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("outside")
    link = home / "managed-link"
    link.symlink_to(outside)
    ref_path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": ["managed-link", ".aw/profile/ref.json"],
            }
        )
    )
    with pytest.raises(gate.GateError, match="resolves outside") as escaped:
        gate.validate_materialized_ref(
            ref_path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )
    assert str(link) in str(escaped.value)
    assert str(outside) in str(escaped.value)
    link.unlink()
    link.symlink_to(home / "missing")
    with pytest.raises(gate.GateError, match="broken"):
        gate.validate_materialized_ref(
            ref_path,
            "pi",
            expected_version=EXPECTED_VERSION,
            expected_digest=EXPECTED_DIGEST,
        )


def test_released_aw_version_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    class Completed:
        stdout = "aw 1.34.1\n"

    monkeypatch.setattr(gate.subprocess, "run", lambda *args, **kwargs: Completed())
    with pytest.raises(gate.GateError, match="metadata"):
        gate.verify_released_aw(Path("/opt/homebrew/bin/aw"))


def test_spoofed_same_version_aw_fails_artifact_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = tmp_path / "aw"
    fake.write_text(f"#!/bin/sh\nprintf '{gate.REQUIRED_AW_VERSION_OUTPUT}'\n")
    fake.chmod(0o755)
    monkeypatch.setattr(gate, "REQUIRED_AW_PATH", fake)
    with pytest.raises(gate.GateError, match="SHA-256"):
        gate.verify_released_aw(fake)


def test_wrong_interpreter_or_entrypoint_artifact_is_refused(tmp_path: Path) -> None:
    fake = tmp_path / "fake"
    fake.write_text("#!/bin/sh\necho fake\n")
    fake.chmod(0o755)
    for expected_path, expected_digest, label in (
        (gate.REQUIRED_NODE_PATH, gate.REQUIRED_NODE_SHA256, "Node interpreter"),
        (gate.REQUIRED_PI_PATH, gate.REQUIRED_PI_SHA256, "Pi entry script"),
    ):
        with pytest.raises(gate.GateError, match="path must be exactly"):
            gate.verify_file_artifact(
                fake,
                expected_path=expected_path,
                expected_sha256=expected_digest,
                label=label,
            )
        with pytest.raises(gate.GateError, match="SHA-256"):
            gate.verify_file_artifact(
                fake,
                expected_path=fake,
                expected_sha256=expected_digest,
                label=label,
            )


def test_harness_artifact_overrides_are_not_exposed() -> None:
    with pytest.raises(SystemExit):
        gate.parser().parse_args(["candidate", "--pi-bin", "/tmp/fake-pi"])


def test_fake_pi_printing_expected_lines_is_refused(tmp_path: Path) -> None:
    fake_pi = tmp_path / "pi"
    fake_pi.write_text(
        "#!/bin/sh\n"
        "echo '# Developer'\n"
        "echo '> Profile developer v0.1.8 · blueprint aweb.team v0.1.12'\n"
    )
    fake_pi.chmod(0o755)
    with pytest.raises(gate.GateError, match="path must be exactly"):
        gate.verify_file_artifact(
            fake_pi,
            expected_path=gate.REQUIRED_PI_PATH,
            expected_sha256=gate.REQUIRED_PI_SHA256,
            label="Pi entry script",
        )


def test_claude_artifact_shape_is_native_macho(tmp_path: Path) -> None:
    gate.verify_native_claude(gate.REQUIRED_CLAUDE_PATH)
    script = tmp_path / "claude"
    script.write_text("#!/bin/sh\n")
    with pytest.raises(gate.GateError, match="native Mach-O"):
        gate.verify_native_claude(script)


def test_pi_harness_bypasses_fake_path_node(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    (fake_bin / "node").write_text("#!/bin/sh\necho FAKE_NODE_INTERCEPTED_PI\n")
    (fake_bin / "node").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_bin}:{gate.HARNESS_PATH}")
    monkeypatch.setenv("UNREVIEWED_INTERCEPT", "must-not-pass")
    home = tmp_path / "home"
    ref_path = home / ".aw" / "profile" / "ref.json"
    ref_path.parent.mkdir(parents=True)
    ref_path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": EXPECTED_VERSION,
                "profile_digest": EXPECTED_DIGEST,
                "runtime_kind": "pi",
                "managed_set": [".aw/profile/ref.json"],
                "source_blueprint_ref": "aweb.team",
                "source_blueprint_version": "0.1.12",
            }
        )
    )
    captured = {}

    def fake_run_checked(command, *, cwd, stdout, stderr, label, env=None):
        captured["command"] = command
        captured["path"] = env["PATH"]
        captured["environment"] = env
        stdout.write_text("# Developer\n> Profile developer v0.1.8 · blueprint aweb.team v0.1.12\n")

    monkeypatch.setattr(gate, "run_checked", fake_run_checked)
    gate.run_harness(
        home,
        "pi",
        tmp_path,
        gate.REQUIRED_CLAUDE_PATH,
        gate.REQUIRED_PI_PATH,
        gate.REQUIRED_NODE_PATH,
    )
    assert captured["command"][:2] == [
        str(gate.REQUIRED_NODE_PATH),
        str(gate.REQUIRED_PI_PATH),
    ]
    assert captured["path"] == gate.HARNESS_PATH
    assert str(fake_bin) not in captured["path"]
    assert "UNREVIEWED_INTERCEPT" not in captured["environment"]
    assert set(captured["environment"]) <= {*gate.HARNESS_ENV_KEYS, "PATH"}


def test_node_options_preload_cannot_intercept_pi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    marker = tmp_path / "node-options-intercepted"
    preload = tmp_path / "intercept.cjs"
    preload.write_text(
        "require('fs').writeFileSync(" + json.dumps(str(marker)) + ", 'intercepted');\n"
    )
    monkeypatch.setenv("NODE_OPTIONS", f"--require={preload}")
    monkeypatch.setenv("NODE_PATH", str(tmp_path / "fake-modules"))
    completed = gate.subprocess.run(
        [str(gate.REQUIRED_NODE_PATH), str(gate.REQUIRED_PI_PATH), "--version"],
        check=True,
        text=True,
        capture_output=True,
        env=gate.controlled_harness_environment(),
    )
    assert completed.stdout.strip() == "0.82.1"
    assert not marker.exists()
    assert "NODE_OPTIONS" not in gate.controlled_harness_environment()
    assert "NODE_PATH" not in gate.controlled_harness_environment()


def test_clone_auth_home_removes_profile_and_delivery_state(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    (source / ".aw" / "profile").mkdir(parents=True)
    (source / ".aw" / "profile" / "ref.json").write_text("{}")
    (source / ".aw" / "signing.key").write_text("secret")
    (source / ".aw" / "interaction-log.jsonl").write_text("private")
    destination.mkdir()
    gate.clone_auth_home(source, destination)
    assert (destination / ".aw" / "signing.key").read_text() == "secret"
    assert not (destination / ".aw" / "profile").exists()
    assert not (destination / ".aw" / "interaction-log.jsonl").exists()
