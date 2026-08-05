"""Persisted-database version-skew journey for the aweb server wheel.

This module is a child of the release driver's frozen matrix.  It does not
compute cells: it consumes one exact :class:`release_driver.SkewCell`, obtains
the wheel bytes named by that cell, and proves a real populated PostgreSQL
database survives first -> second -> first server operation.  The final first
server run is the non-atomic rollout check.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
import uuid
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import release_driver as rd

JOURNEY = (
    "persisted-state fixture (aweb-abbe.7.4): migrate a database created by "
    "the published release; published server against upgraded schema where "
    "rollout is non-atomic"
)
ARTIFACTS = {"a": "pypi:aweb", "b": "pypi:aweb"}


@dataclass(frozen=True)
class WheelIdentity:
    filename: str
    version: str
    sha256: str
    bytes: bytes
    source: dict


def _url_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


class WheelResolver:
    """Resolve exact staged and published server wheels from cell identity."""

    def __init__(self, *, staged_store=None, pypi_fetch=None):
        self._staged_store = staged_store
        self._pypi_fetch = pypi_fetch or _url_bytes

    def resolve(self, kind: str, side: dict, locator: str) -> WheelIdentity:
        if locator != "pypi:aweb" or side.get("component") != "server":
            raise rd.ReceiptError(
                "persisted-state skew accepts only the declared pypi:aweb "
                f"server artifact, got {locator!r} / {side.get('component')!r}"
            )
        if kind == "candidate":
            return self._candidate(side)
        if kind not in {"published", "published-latest", "published-floor"}:
            raise rd.ReceiptError(
                f"persisted-state skew does not understand side kind {kind!r}"
            )
        return self._published(side)

    def _candidate(self, side: dict) -> WheelIdentity:
        if self._staged_store is None:
            self._staged_store = rd.GithubArtifactStore(
                repo="awebai/aweb",
                workflow_path=".github/workflows/pypi-release.yml",
            )
        lane_data = side.get("lane_ref")
        if lane_data is None:
            raise rd.ReceiptError(
                "candidate wheel requires the unchanged structured lane reference"
            )
        ref = rd.LaneRef.from_dict(lane_data)
        outer = self._staged_store.get(ref.artifact)
        outer_sha = hashlib.sha256(outer).hexdigest()
        if ref.zip_digest != f"sha256:{outer_sha}":
            raise rd.ReceiptError(
                f"candidate outer ZIP hash sha256:{outer_sha} does not equal "
                f"the bound {ref.zip_digest}"
            )
        manifest = rd.validate_pypi_lane_artifact(
            outer,
            expected_source_sha=ref.aw_source_sha,
            expected_version=side.get("version"),
            package="server",
            pypi_name="aweb",
        )
        files = manifest["files"]
        if side.get("digest_set") != files:
            raise rd.ReceiptError(
                "candidate wheel manifest file set does not equal the frozen "
                "cell digest_set"
            )
        canonical = rd.canonical_digest_of_set(files)
        if side.get("digest") != canonical:
            raise rd.ReceiptError(
                f"candidate canonical digest {canonical} does not equal the "
                f"frozen cell digest {side.get('digest')!r}"
            )
        wheels = [name for name in files if name.endswith(".whl")]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"candidate lane binds {len(wheels)} wheels, expected exactly one"
            )
        filename = wheels[0]
        with zipfile.ZipFile(io.BytesIO(outer)) as archive:
            wheel = archive.read(f"dist/{filename}")
        wheel_sha = hashlib.sha256(wheel).hexdigest()
        if wheel_sha != files[filename]:
            raise rd.ReceiptError(
                f"candidate wheel hash {wheel_sha} does not equal the staged "
                f"manifest digest {files[filename]}"
            )
        return WheelIdentity(
            filename=filename,
            version=side["version"],
            sha256=wheel_sha,
            bytes=wheel,
            source={
                "kind": "candidate",
                "artifact": ref.artifact,
                "source_sha": ref.aw_source_sha,
                "outer_zip_sha256": outer_sha,
                "canonical_set_digest": manifest["canonical_set_digest"],
                "digest_set": dict(files),
            },
        )

    def _published(self, side: dict) -> WheelIdentity:
        version = side.get("version")
        if not isinstance(version, str) or not version:
            raise rd.ReceiptError("published server side has no version")
        metadata_url = f"https://pypi.org/pypi/aweb/{version}/json"
        try:
            metadata = json.loads(self._pypi_fetch(metadata_url))
        except (json.JSONDecodeError, TypeError) as exc:
            raise rd.ReceiptError(
                f"PyPI metadata for aweb {version} is not valid JSON"
            ) from exc
        wheels = [
            item for item in metadata.get("urls", [])
            if item.get("packagetype") == "bdist_wheel"
        ]
        if len(wheels) != 1:
            raise rd.ReceiptError(
                f"PyPI aweb {version} exposes {len(wheels)} wheels, expected one"
            )
        item = wheels[0]
        expected = (item.get("digests") or {}).get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise rd.ReceiptError(
                f"PyPI aweb {version} wheel has no SHA-256 metadata"
            )
        body = self._pypi_fetch(item["url"])
        actual = hashlib.sha256(body).hexdigest()
        if actual != expected:
            raise rd.ReceiptError(
                f"published wheel hash {actual} does not equal PyPI's {expected}"
            )
        return WheelIdentity(
            filename=item["filename"],
            version=version,
            sha256=actual,
            bytes=body,
            source={
                "kind": "published",
                "registry": "pypi:aweb",
                "metadata_url": metadata_url,
                "download_url": item["url"],
            },
        )


class PersistedStateHarness:
    """Orchestrate one frozen persisted-state cell and its negative control."""

    def __init__(self, *, resolver: WheelResolver, journey):
        self._resolver = resolver
        self._journey = journey

    def _validate_cell(self, cell) -> None:
        if (
            cell.journey != JOURNEY
            or cell.edge_a != "server"
            or cell.edge_b != "server"
            or cell.artifacts != ARTIFACTS
            or cell.declared_direction != "persisted-state-both"
            or cell.direction not in {"a-to-b", "b-to-a"}
        ):
            raise rd.ReceiptError(
                "persisted-state harness accepts only the exact persisted-state "
                f"edge contract, got {cell!r}"
            )

    def run(self, cell) -> None:
        self._validate_cell(cell)
        a = self._resolver.resolve(cell.a_kind, cell.a, cell.artifacts["a"])
        b = self._resolver.resolve(cell.b_kind, cell.b, cell.artifacts["b"])
        first, second = (a, b) if cell.direction == "a-to-b" else (b, a)
        first_kind, second_kind = (
            (cell.a_kind, cell.b_kind)
            if cell.direction == "a-to-b"
            else (cell.b_kind, cell.a_kind)
        )
        database = None
        try:
            database = self._journey.new_database(cell)
            with self._journey.serve(first, database) as server:
                self._journey.seed(server, cell)
                seed_phase = (
                    "published-seed"
                    if first_kind.startswith("published") else "candidate-seed"
                )
                self._journey.exercise(server, seed_phase, cell)
            before = self._journey.database_identity(database)

            with self._journey.serve(second, database) as server:
                second_phase = (
                    "candidate-on-populated"
                    if second_kind == "candidate" else "published-on-populated"
                )
                self._journey.exercise(server, second_phase, cell)
            upgraded = self._journey.database_identity(database)

            with self._journey.serve(first, database) as server:
                first_again_phase = (
                    "published-on-upgraded"
                    if first_kind.startswith("published")
                    else "candidate-on-upgraded"
                )
                self._journey.exercise(server, first_again_phase, cell)

            control = self._journey.clone_database(database)
            with self._journey.serve(second, control) as server:
                self._journey.exercise(
                    server, "negative-control-baseline", cell
                )
            self._journey.break_schema(control)
            control_error = None
            with self._journey.serve(second, control) as server:
                try:
                    self._journey.exercise(server, "known-breaking-schema", cell)
                except Exception as exc:  # the control is required to go red
                    control_error = f"{type(exc).__name__}: {exc}"
            if control_error is None:
                raise rd.ReceiptError(
                    "persisted-state negative control stayed green after "
                    "dropping aweb.messages.subject"
                )

            self._journey.write_report({
                "schema": "aweb.persisted-state-skew-measurement.v1",
                "edge_id": cell.edge_id,
                "edge": {"a": cell.edge_a, "b": cell.edge_b},
                "journey": cell.journey,
                "artifacts": dict(cell.artifacts),
                "declared_direction": cell.declared_direction,
                "cell_direction": cell.direction,
                "first": self._wheel_report(first, first_kind),
                "second": self._wheel_report(second, second_kind),
                "database_seeded": before,
                "database_after_transition": upgraded,
                "negative_control": {
                    "baseline": "green",
                    "mutation": "ALTER TABLE aweb.messages DROP COLUMN subject",
                    "result": "red",
                    "error": control_error,
                },
            })
        finally:
            self._journey.close()

    @staticmethod
    def _wheel_report(wheel: WheelIdentity, kind: str) -> dict:
        return {
            "kind": kind,
            "filename": wheel.filename,
            "version": wheel.version,
            "sha256": wheel.sha256,
            "source": dict(wheel.source),
        }


def factory():
    return PersistedStateHarness(
        resolver=WheelResolver(), journey=SubprocessPersistedStateJourney()
    )


def server_command(venv: Path, port: int) -> list[str]:
    return [
        str(venv / "bin" / "aweb"), "serve", "--host", "127.0.0.1",
        "--port", str(port),
    ]


class SubprocessPersistedStateJourney:
    """Run exact wheel processes over one isolated real OSS stack.

    PostgreSQL and Redis are disposable named Docker containers.  AWID and the
    Go CLI are the checked-in journey dependencies; only the aweb server is
    varied, and it always runs from the wheel bytes resolved from the cell.
    """

    def __init__(self, *, evidence_dir: Path | None = None):
        self._repo = Path(__file__).resolve().parents[1]
        self._root = Path(tempfile.mkdtemp(prefix="aweb-persisted-skew-"))
        configured = os.getenv("AWEB_PERSISTED_SKEW_EVIDENCE_DIR")
        self._evidence_dir = Path(evidence_dir or configured or (
            Path(tempfile.gettempdir()) / "aweb-persisted-skew-evidence"
        )).resolve()
        self._evidence_dir.mkdir(parents=True, exist_ok=True)
        suffix = uuid.uuid4().hex[:10]
        self._postgres = f"aweb-skew-pg-{suffix}"
        self._redis = f"aweb-skew-redis-{suffix}"
        self._postgres_port = self._free_port()
        self._redis_port = self._free_port()
        self._awid_port = self._free_port()
        self._aweb_port = self._free_port()
        self._processes: list[subprocess.Popen] = []
        self._log_handles = []
        self._installed: dict[str, Path] = {}
        self._markers: list[str] = []
        self._mail_conversation: str | None = None
        self._counter = 0
        self._started = False
        self._current_database: str | None = None

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    @property
    def _database_url(self) -> str:
        database = self._current_database or "aweb"
        return (
            f"postgresql://aweb:aweb-skew@127.0.0.1:"
            f"{self._postgres_port}/{database}"
        )

    @property
    def _awid_database_url(self) -> str:
        return (
            f"postgresql://aweb:aweb-skew@127.0.0.1:"
            f"{self._postgres_port}/awid"
        )

    @property
    def _redis_url(self) -> str:
        return f"redis://127.0.0.1:{self._redis_port}/0"

    @property
    def _awid_url(self) -> str:
        return f"http://127.0.0.1:{self._awid_port}"

    @property
    def _aweb_url(self) -> str:
        return f"http://127.0.0.1:{self._aweb_port}"

    def _run(self, argv, *, cwd=None, env=None, input_bytes=None):
        result = subprocess.run(
            [str(item) for item in argv], cwd=cwd, env=env,
            input=input_bytes, capture_output=True,
        )
        if result.returncode != 0:
            raise rd.ReceiptError(
                f"persisted-state command failed ({' '.join(map(str, argv))}): "
                + result.stderr.decode(errors="replace")[-2000:]
            )
        return result.stdout

    def _docker(self, *args):
        return self._run(["docker", *args])

    def _wait_postgres(self) -> None:
        for _ in range(60):
            result = subprocess.run(
                ["docker", "exec", self._postgres, "pg_isready", "-U", "aweb"],
                capture_output=True,
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise rd.ReceiptError("throwaway PostgreSQL did not become ready")

    @staticmethod
    def _wait_http(url: str, process=None) -> None:
        last = None
        for _ in range(90):
            if process is not None and process.poll() is not None:
                raise rd.ReceiptError(
                    f"server process exited {process.returncode} before {url}"
                )
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    if response.status == 200:
                        return
            except Exception as exc:  # readiness records the last concrete error
                last = exc
            time.sleep(1)
        raise rd.ReceiptError(f"service at {url} did not become healthy: {last}")

    def _start_infrastructure(self) -> None:
        if self._started:
            return
        self._docker(
            "run", "--rm", "-d", "--name", self._postgres,
            "-e", "POSTGRES_USER=aweb",
            "-e", "POSTGRES_PASSWORD=aweb-skew",
            "-e", "POSTGRES_DB=postgres",
            "-p", f"127.0.0.1:{self._postgres_port}:5432",
            "postgres:17-alpine",
        )
        self._docker(
            "run", "--rm", "-d", "--name", self._redis,
            "-p", f"127.0.0.1:{self._redis_port}:6379",
            "redis:7-alpine",
        )
        self._wait_postgres()
        self._docker("exec", self._postgres, "createdb", "-U", "aweb", "aweb")
        self._docker("exec", self._postgres, "createdb", "-U", "aweb", "awid")
        awid_log = open(self._root / "awid.log", "wb")
        self._log_handles.append(awid_log)
        awid_env = {
            **os.environ,
            "AWID_DATABASE_URL": self._awid_database_url,
            "AWID_REDIS_URL": self._redis_url,
            "AWID_HOST": "127.0.0.1",
            "AWID_PORT": str(self._awid_port),
            "AWID_SKIP_DNS_VERIFY": "1",
            "AWID_ALLOW_INSECURE_DELIVERY_ORIGIN": "1",
            "AWID_RATE_LIMIT_DISABLED": "1",
            "APP_ENV": "development",
        }
        process = subprocess.Popen(
            ["uv", "run", "--frozen", "awid", "--host", "127.0.0.1",
             "--port", str(self._awid_port)],
            cwd=self._repo / "awid", env=awid_env,
            stdout=awid_log, stderr=subprocess.STDOUT,
        )
        self._processes.append(process)
        self._wait_http(f"{self._awid_url}/health", process)
        self._run(["make", "build"], cwd=self._repo / "cli" / "go")
        (self._root / "home" / ".config" / "aw").mkdir(parents=True)
        (self._root / "alice").mkdir()
        (self._root / "bob").mkdir()
        self._started = True

    def new_database(self, cell):
        self._start_infrastructure()
        return "aweb"

    def _install(self, wheel: WheelIdentity) -> Path:
        existing = self._installed.get(wheel.sha256)
        if existing is not None:
            return existing
        wheel_path = self._root / wheel.sha256 / wheel.filename
        wheel_path.parent.mkdir(parents=True)
        wheel_path.write_bytes(wheel.bytes)
        if hashlib.sha256(wheel_path.read_bytes()).hexdigest() != wheel.sha256:
            raise rd.ReceiptError("wheel bytes changed while materializing runtime")
        venv = self._root / "venvs" / wheel.sha256
        self._run(["uv", "venv", "--python", "3.12", str(venv)])
        python = venv / "bin" / "python"
        self._run([
            "uv", "pip", "install", "--python", str(python), str(wheel_path)
        ])
        installed = self._run([
            str(python), "-c",
            "import importlib.metadata; print(importlib.metadata.version('aweb'))",
        ]).decode().strip()
        if installed != wheel.version:
            raise rd.ReceiptError(
                f"installed wheel reports aweb {installed}, expected {wheel.version}"
            )
        self._installed[wheel.sha256] = venv
        return venv

    @contextmanager
    def serve(self, wheel, database):
        self._current_database = database
        venv = self._install(wheel)
        log = open(
            self._root / f"aweb-{wheel.version}-{database}-{uuid.uuid4().hex[:6]}.log",
            "wb",
        )
        self._log_handles.append(log)
        env = {
            **os.environ,
            "AWEB_DATABASE_URL": self._database_url,
            "AWEB_REDIS_URL": self._redis_url,
            "AWID_REGISTRY_URL": self._awid_url,
            "AWEB_HOST": "127.0.0.1",
            "AWEB_PORT": str(self._aweb_port),
            "AWEB_PUBLIC_ORIGIN": self._aweb_url,
            "AWEB_LOG_JSON": "true",
            "APP_ENV": "development",
        }
        process = subprocess.Popen(
            server_command(venv, self._aweb_port),
            cwd=self._root, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            try:
                self._wait_http(f"{self._aweb_url}/health", process)
            except Exception as exc:
                log.flush()
                tail = log.name and Path(log.name).read_text(errors="replace")[-4000:]
                raise rd.ReceiptError(f"{exc}; exact-wheel server log:\n{tail}") from exc
            yield self._aweb_url
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            log.flush()

    def _aw_env(self):
        home = self._root / "home"
        return {
            **os.environ,
            "HOME": str(home),
            "AW_CONFIG_PATH": str(home / ".config" / "aw" / "config.yaml"),
            "AWID_REGISTRY_URL": self._awid_url,
            "AWID_SKIP_DNS_VERIFY": "1",
            "AWEB_URL": self._aweb_url,
        }

    def _aw(self, workspace: str, *args) -> str:
        binary = self._repo / "cli" / "go" / "aw"
        return self._run(
            [binary, *args], cwd=self._root / workspace, env=self._aw_env()
        ).decode(errors="replace")

    @staticmethod
    def _json_output(output: str) -> dict:
        start = output.find("{")
        if start < 0:
            raise rd.ReceiptError(f"aw returned no JSON object: {output[-500:]}")
        try:
            value, _ = json.JSONDecoder().raw_decode(output[start:])
        except json.JSONDecodeError as exc:
            raise rd.ReceiptError(f"aw returned invalid JSON: {output[-500:]}") from exc
        return value

    def seed(self, server, cell):
        self._json_output(self._aw(
            "alice", "id", "create", "--name", "alice", "--domain", "skew.local",
            "--registry", self._awid_url, "--skip-dns-verify", "--json",
        ))
        self._json_output(self._aw(
            "alice", "id", "namespace", "set-delivery-origin",
            "--namespace", "skew.local", "--origin", self._aweb_url, "--json",
        ))
        self._json_output(self._aw(
            "alice", "id", "team", "create", "--name", "devteam",
            "--namespace", "skew.local", "--registry", self._awid_url, "--json",
        ))
        invite = self._json_output(self._aw(
            "alice", "id", "team", "invite", "--team", "devteam",
            "--namespace", "skew.local", "--global", "--json",
        ))["token"]
        self._json_output(self._aw(
            "alice", "id", "team", "accept-invite", invite, "--global",
            "--alias", "alice", "--json",
        ))
        self._aw("alice", "init", "--url", self._aweb_url)

        self._json_output(self._aw(
            "bob", "id", "create", "--name", "bob", "--domain", "skew.local",
            "--registry", self._awid_url, "--skip-dns-verify", "--json",
        ))
        invite = self._json_output(self._aw(
            "alice", "id", "team", "invite", "--team", "devteam",
            "--namespace", "skew.local", "--global", "--json",
        ))["token"]
        self._json_output(self._aw(
            "bob", "id", "team", "accept-invite", invite, "--global",
            "--alias", "bob", "--json",
        ))
        self._aw("bob", "init", "--url", self._aweb_url)

    def exercise(self, server, phase, cell):
        self._counter += 1
        marker = f"skew-{cell.edge_id[:12]}-{self._counter}-{phase}"
        mail_args = [
            "mail", "send", "--plaintext", "--subject", marker,
            "--body", marker, "--json",
        ]
        if self._mail_conversation is None:
            mail_args.extend(["--to", "bob"])
        else:
            mail_args.extend(["--conversation-id", self._mail_conversation])
        sent = self._json_output(self._aw("alice", *mail_args))
        observed_conversation = sent.get("conversation_id")
        if not observed_conversation:
            raise rd.ReceiptError("mail journey returned no conversation identity")
        if self._mail_conversation not in (None, observed_conversation):
            raise rd.ReceiptError(
                "mail continuation changed conversation identity across server restart"
            )
        self._mail_conversation = observed_conversation
        self._markers.append(marker)
        inbox = self._aw("bob", "mail", "inbox", "--show-all", "--json")
        for expected in self._markers:
            if expected not in inbox:
                raise rd.ReceiptError(
                    f"mail journey did not preserve marker {expected!r} during {phase}"
                )

        self._aw(
            "alice", "chat", "send-and-leave", "--plaintext", "bob", marker,
        )
        history = self._aw("alice", "chat", "history", "bob", "--json")
        if marker not in history:
            raise rd.ReceiptError(f"chat journey lost {marker!r} during {phase}")

        self._aw(
            "alice", "task", "create", "--title", marker,
            "--description", "persisted-state skew fixture", "--type", "task",
            "--json",
        )
        tasks = self._aw("alice", "task", "list", "--json")
        if marker not in tasks:
            raise rd.ReceiptError(f"task journey lost {marker!r} during {phase}")

        resource = f"persisted-skew-{self._counter}"
        self._aw(
            "alice", "lock", "acquire", "--resource-key", resource,
            "--ttl-seconds", "3600", "--json",
        )
        locks = self._aw("alice", "lock", "list", "--json")
        if resource not in locks:
            raise rd.ReceiptError(f"lock journey did not observe {resource!r}")
        self._aw("alice", "lock", "release", "--resource-key", resource, "--json")

    def _psql(self, database: str, sql: str) -> bytes:
        return self._docker(
            "exec", "-i", self._postgres, "psql", "-X", "-v", "ON_ERROR_STOP=1",
            "-U", "aweb", "-d", database, "-At", "-F", "\t", "-c", sql,
        )

    def database_identity(self, database):
        migrations = self._psql(
            database,
            "SELECT filename, checksum FROM aweb.schema_migrations ORDER BY filename",
        )
        schema_dump = self._docker(
            "exec", self._postgres, "pg_dump", "-U", "aweb", "-d", database,
            "--schema=aweb", "--schema-only", "--no-owner", "--no-privileges",
        )
        data_dump = self._docker(
            "exec", self._postgres, "pg_dump", "-U", "aweb", "-d", database,
            "--schema=aweb", "--data-only", "--inserts", "--no-owner",
            "--no-privileges",
        )
        return {
            "database": database,
            "migration_rows_sha256": hashlib.sha256(migrations).hexdigest(),
            "schema_dump_sha256": hashlib.sha256(schema_dump).hexdigest(),
            "data_dump_sha256": hashlib.sha256(data_dump).hexdigest(),
            "migration_rows": migrations.decode().splitlines(),
        }

    def clone_database(self, database):
        control = f"control_{uuid.uuid4().hex[:10]}"
        self._docker(
            "exec", self._postgres, "createdb", "-U", "aweb",
            "--template", database, control,
        )
        return control

    def break_schema(self, database):
        self._psql(database, "ALTER TABLE aweb.messages DROP COLUMN subject")

    def write_report(self, report):
        report = {**report, "result": "green"}
        body = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        identity = hashlib.sha256(body).hexdigest()
        path = self._evidence_dir / f"cell-{report['edge_id']}-{identity}.json"
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(body)
        os.replace(temporary, path)
        print(f"persisted-state skew evidence: {path} sha256:{identity}")

    def close(self):
        for process in reversed(self._processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for name in (self._redis, self._postgres):
            subprocess.run(
                ["docker", "rm", "-f", name], capture_output=True
            )
        for handle in self._log_handles:
            try:
                handle.close()
            except Exception:
                pass
        shutil.rmtree(self._root, ignore_errors=True)


def _version_key(version: str):
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise rd.ReceiptError(
            f"measured published version {version!r} is not dotted numeric"
        ) from exc


def aggregate_support(evidence_dir: Path) -> dict:
    """Build the anchor body only from green exact-cell evidence."""
    reports = []
    for path in sorted(Path(evidence_dir).glob("cell-*.json")):
        body = path.read_bytes()
        report = json.loads(body)
        reports.append((path, body, report))
    if not reports:
        raise rd.ReceiptError("no persisted-state cell evidence to aggregate")
    first = reports[0][2]
    bound = {
        key: first[key]
        for key in ("edge_id", "edge", "journey", "artifacts", "declared_direction")
    }
    directions = set()
    published = set()
    candidate_identities: dict[str, dict] = {}
    transition_orders: dict[str, set[str]] = {}
    evidence = []
    for path, body, report in reports:
        current = {
            key: report[key]
            for key in ("edge_id", "edge", "journey", "artifacts", "declared_direction")
        }
        if current != bound:
            raise rd.ReceiptError(f"evidence {path} binds a different edge")
        control = report.get("negative_control", {})
        if (
            report.get("result") != "green"
            or control.get("baseline") != "green"
            or control.get("result") != "red"
        ):
            raise rd.ReceiptError(f"evidence {path} is not green with a red control")
        directions.add(report["cell_direction"])
        sides = (report["first"], report["second"])
        candidates = []
        published_sides = []
        for side in sides:
            kind = str(side.get("kind", ""))
            if kind == "candidate":
                identity = {
                    key: side[key]
                    for key in ("filename", "version", "sha256", "source")
                }
                candidate_identities[
                    json.dumps(identity, sort_keys=True, separators=(",", ":"))
                ] = identity
                candidates.append(side)
            elif kind.startswith("published"):
                published.add(side["version"])
                published_sides.append(side)
        if len(candidates) == 1 and len(published_sides) == 1:
            version = published_sides[0]["version"]
            order = (
                "published-to-candidate"
                if str(report["first"]["kind"]).startswith("published")
                else "candidate-to-published"
            )
            transition_orders.setdefault(version, set()).add(order)
        evidence.append({
            "file": path.name,
            "sha256": hashlib.sha256(body).hexdigest(),
            "cell_direction": report["cell_direction"],
            "first": {k: report["first"][k] for k in ("kind", "version", "sha256")},
            "second": {k: report["second"][k] for k in ("kind", "version", "sha256")},
        })
    if directions != {"a-to-b", "b-to-a"}:
        raise rd.ReceiptError(
            f"persisted-state evidence lacks both directions: {sorted(directions)}"
        )
    if len(candidate_identities) != 1:
        raise rd.ReceiptError(
            "persisted-state evidence must bind one exact candidate identity; "
            f"found {len(candidate_identities)}"
        )
    if not published:
        raise rd.ReceiptError("persisted-state evidence contains no published server")
    incomplete = {
        version: sorted({"published-to-candidate", "candidate-to-published"}
                        - transition_orders.get(version, set()))
        for version in published
        if transition_orders.get(version, set()) != {
            "published-to-candidate", "candidate-to-published"
        }
    }
    if incomplete:
        raise rd.ReceiptError(
            "persisted-state evidence lacks both transition orders for every "
            f"published version: {incomplete}"
        )
    versions = sorted(published, key=_version_key)
    candidate = next(iter(candidate_identities.values()))
    return {
        "schema": "aweb.runtime-support-measurement.v1",
        "edge": bound["edge"],
        "journey": bound["journey"],
        "artifacts": bound["artifacts"],
        "direction": bound["declared_direction"],
        "supported_versions": {"server": versions},
        "candidate": candidate,
        "evidence": evidence,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="verb", required=True)
    aggregate = subparsers.add_parser("aggregate")
    aggregate.add_argument("--evidence-dir", type=Path, required=True)
    aggregate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.verb == "aggregate":
        document = aggregate_support(args.evidence_dir)
        body = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(body)
        print(f"{args.output} sha256:{hashlib.sha256(body).hexdigest()}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
