#!/usr/bin/env python3
"""Seed the aweb.engineering pack into a running Library on the e2e stack.

Provisions a real AWID team against the stack's awid, then publishes the
engineering blueprint into Library over real team-certificate auth - the same
flow Library's own e2e suite exercises (_provision_team + _publish_blueprint),
so the materializer runs against the real folded-block-scalar pack content.

Talks to the stack only over its published host ports and the `aw` binary; it
imports nothing from the library package. Run against a freshly-upped stack.

Environment:
  AW_BIN                       path to the aw binary (default: aw on PATH)
  LIBRARY_E2E_AWID_URL         awid base URL    (default: http://127.0.0.1:18010)
  LIBRARY_E2E_LIBRARY_URL      library base URL (default: http://127.0.0.1:18765)
                               MUST equal Library's LIBRARY_PUBLIC_ORIGIN: it is
                               the team-auth audience the seed signs.
  LIBRARY_E2E_BLUEPRINT_SRC    blueprint source dir
                               (default: ../blueprints/engineering)
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
import uuid
from datetime import UTC, datetime
from pathlib import Path

AW_BIN = os.environ.get("AW_BIN", "aw")
AWID_URL = os.environ.get("LIBRARY_E2E_AWID_URL", "http://127.0.0.1:18010")
LIBRARY_URL = os.environ.get("LIBRARY_E2E_LIBRARY_URL", "http://127.0.0.1:18765")
BLUEPRINT_SRC = Path(
    os.environ.get("LIBRARY_E2E_BLUEPRINT_SRC", "../blueprints/engineering")
).resolve()

BLUEPRINT_ID = "aweb.engineering"
BLUEPRINT_PAYLOAD_SCHEMA = "aweb.blueprint.import-payload.v1"
# Mirror library.digest.EXCLUDED_DIRS: VCS/build/cache dirs never enter the payload.
EXCLUDED_DIRS = frozenset(
    {".git", ".hg", ".svn", "node_modules", ".cache", "dist", "build", "target", "tmp", "vendor", "__pycache__"}
)


def _now_z() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _run_aw(workspace: Path, env: dict[str, str], *args: str) -> dict:
    """Run `aw --json <args>` in the workspace and return the parsed object."""
    result = subprocess.run(
        [AW_BIN, "--json", *args],
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(
            f"aw {' '.join(args)} failed (exit {result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        # Some commands (create/switch) print non-JSON; callers that need a value
        # use the --json ones. Return an empty dict for the rest.
        return {}


def _collect_files(root: Path) -> list[dict[str, str]]:
    """Sorted payload entries with POSIX paths relative to root (excludes build/VCS dirs)."""
    root = root.resolve()
    entries: list[dict[str, str]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in relative.parts[:-1]):
            continue
        raw = path.read_bytes()
        entries.append(
            {
                "content_utf8": raw.decode("utf-8"),
                "path": relative.as_posix(),
                "sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
            }
        )
    entries.sort(key=lambda entry: entry["path"])
    return entries


def _get_blueprints() -> list[dict]:
    with urllib.request.urlopen(f"{LIBRARY_URL}/v1/blueprints", timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _provision_team(workspace: Path, env: dict[str, str]) -> None:
    """Create an identity + team in awid and bind it into the workspace so that
    `aw id request --team-auth` produces a valid team certificate."""
    unique = uuid.uuid4().hex[:12]
    namespace = f"library-seed-{unique}.test"
    team = "default"
    alias = "alice"
    address = f"{namespace}/{alias}"

    _run_aw(workspace, env, "id", "create", "--domain", namespace, "--name", alias,
            "--registry", AWID_URL, "--skip-dns-verify")
    _run_aw(workspace, env, "id", "team", "create", "--namespace", namespace,
            "--name", team, "--registry", AWID_URL)
    add_member = _run_aw(workspace, env, "id", "team", "add-member", "--namespace",
                         namespace, "--team", team, "--member", address)
    certificate_id = str(add_member["certificate_id"])
    fetch_cert = _run_aw(workspace, env, "id", "team", "fetch-cert", "--namespace",
                         namespace, "--team", team, "--cert-id", certificate_id,
                         "--registry", AWID_URL)
    team_id = f"{team}:{namespace}"
    _run_aw(workspace, env, "id", "team", "switch", team_id)

    now = _now_z()
    (workspace / ".aw").mkdir(parents=True, exist_ok=True)
    (workspace / ".aw" / "workspace.yaml").write_text(
        f"""aweb_url: http://127.0.0.1:1
memberships:
    - team_id: {team_id}
      alias: {alias}
      workspace_id: {uuid.uuid4()}
      cert_path: {fetch_cert["cert_path"]}
      joined_at: "{now}"
human_name: e2e-seed
agent_type: agent
workspace_path: {workspace}
updated_at: "{now}"
""",
        encoding="utf-8",
    )


def _publish(workspace: Path, env: dict[str, str], payload_file: Path) -> int:
    result = subprocess.run(
        [AW_BIN, "id", "request", "POST", f"{LIBRARY_URL}/v1/blueprints/import",
         "--team-auth", "--raw", "--body-file", str(payload_file)],
        cwd=workspace,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        print(f"  publish POST failed (exit {result.returncode})", file=sys.stderr)
        print(f"  stdout: {result.stdout}", file=sys.stderr)
        print(f"  stderr: {result.stderr}", file=sys.stderr)
    else:
        print("  published blueprint import payload")
    return result.returncode


def main() -> int:
    if not BLUEPRINT_SRC.is_dir():
        raise SystemExit(
            f"blueprint source not found: {BLUEPRINT_SRC}\n"
            "Expected the ../blueprints checkout as a sibling of this repo, or set "
            "LIBRARY_E2E_BLUEPRINT_SRC to the engineering pack directory."
        )

    print(f"Seeding {BLUEPRINT_ID} from {BLUEPRINT_SRC}")
    print(f"  awid={AWID_URL}  library={LIBRARY_URL}")

    files = _collect_files(BLUEPRINT_SRC)
    payload = {"files": files, "schema": BLUEPRINT_PAYLOAD_SCHEMA}
    print(f"  collected {len(files)} blueprint files")

    with tempfile.TemporaryDirectory(prefix="library-seed-") as tmp:
        tmpdir = Path(tmp)
        workspace = tmpdir / "workspace"
        home = tmpdir / "home"
        workspace.mkdir()
        home.mkdir()
        env = os.environ.copy()
        env.update(
            {
                "HOME": str(home),
                "AWEB_URL": "http://127.0.0.1:1",
                "AWID_REGISTRY_URL": AWID_URL,
                "AWID_SKIP_DNS_VERIFY": "1",
                "NO_COLOR": "1",
            }
        )

        _provision_team(workspace, env)

        payload_file = tmpdir / "payload.json"
        payload_file.write_text(json.dumps(payload), encoding="utf-8")

        rc = _publish(workspace, env, payload_file)
        if rc != 0:
            # Already-seeded stack: tolerate if the catalog already has the pack.
            if any(bp.get("blueprint_ref") == BLUEPRINT_ID for bp in _get_blueprints()):
                print(f"  {BLUEPRINT_ID} already present in catalog; treating as seeded")
            else:
                raise SystemExit("publish failed and blueprint is not in the catalog")

    catalog = _get_blueprints()
    match = next((bp for bp in catalog if bp.get("blueprint_ref") == BLUEPRINT_ID), None)
    if match is None:
        raise SystemExit(
            f"{BLUEPRINT_ID} not found in public catalog after seeding; "
            f"catalog refs: {[bp.get('blueprint_ref') for bp in catalog]}"
        )
    version = match.get("version", "?")
    print(f"OK: {BLUEPRINT_ID} v{version} is live in Library's public catalog")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
