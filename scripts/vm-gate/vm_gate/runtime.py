"""Wire local admission, canonical ledger transport and one disposable VM."""

from contextlib import contextmanager
from importlib.metadata import version
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

from .backend import Backend
from .config import child_environment
from .config_lease import ConfigLease
from .errors import Infrastructure, Refused
from .executor import Executor
from .expiry import CompletionBudget
from .host_keys import forget, public_key
from .ledger import LedgerLease
from .lifecycle import run_session, write_summary
from .preflight import read_hcloud_token
from .provider import Provider
from .reaping import reap_and_settle
from .source import verify_train_main
from .state import Store


class Runtime:
    def __init__(
        self,
        *,
        config,
        directory,
        source,
        command,
        args,
        run_id,
        provider_factory=None,
        executor_factory=Executor,
    ):
        self.config = dict(config)
        self.directory = Path(directory) if directory else None
        self.source = source
        self.command = command
        self.args = args
        self.run_id = run_id
        self.store = Store(
            Path(config["state_root"]) / "registry.sqlite3",
            config.get("cap_eur", 150),
            seed_eur=config.get("seed_eur", 0),
        )
        self.provider_factory = provider_factory
        if (
            executor_factory is Executor
            and config.get("host_profile") == "native-arm64-oci-v1"
        ):
            from .native_executor import NativeARMExecutor

            executor_factory = NativeARMExecutor
        elif executor_factory is Executor and config.get("archive_out"):
            from .native_executor import ArchiveExecutor

            executor_factory = ArchiveExecutor
        self.executor_factory = executor_factory

    def event(self, name, **fields):
        if self.directory:
            with (self.directory / "provider-events.jsonl").open("a") as f:
                f.write(
                    json.dumps({"time": time.time(), "event": name, **fields}) + "\n"
                )

    def provider(self):
        if self.provider_factory:
            return self.provider_factory(self.config)
        if version("hcloud") != "2.27.0":
            raise Infrastructure("hcloud 2.27.0 is required; refusing provider access")
        from hcloud import Client

        previous = os.environ.get("HCLOUD_TOKEN_FILE")
        try:
            os.environ["HCLOUD_TOKEN_FILE"] = self.config["token_file"]
            token = read_hcloud_token()
        finally:
            if previous is None:
                os.environ.pop("HCLOUD_TOKEN_FILE", None)
            else:
                os.environ["HCLOUD_TOKEN_FILE"] = previous
        client = Client(
            token=token,
            application_name="aweb-vm-gate",
            application_version="1",
            timeout=(10, 60),
        )
        del token
        return Provider(Backend(client, self.config), event=self.event)

    def status(self):
        return {
            "exit": 0,
            "infrastructure": None,
            "spend": self.store.totals(),
            "runs": self.store.runs(),
        }

    def reap(self):
        receipt = reap_and_settle(self.provider(), self.store)
        self._forget_reaped_keys()
        return {
            "exit": 0,
            "infrastructure": None,
            "reap": receipt,
            "spend": self.store.totals(),
        }

    def _key(self):
        for name in ["ssh", "scp", "ssh-keygen", "bash"]:
            if not shutil.which(name):
                raise Refused("local command missing: " + name)
        for name in ["ssh-key", "ssh-host-key"]:
            result = subprocess.run(
                [
                    shutil.which("ssh-keygen"),
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-f",
                    str(self.directory / name),
                ],
                capture_output=True,
                timeout=30,
                env=child_environment(),
            )
            if result.returncode:
                raise Infrastructure("session SSH key generation failed")
        self.config["public_key"] = (self.directory / "ssh-key.pub").read_text()
        self.config["ssh_host_private"] = (self.directory / "ssh-host-key").read_text()
        self.config["ssh_host_public"] = public_key(self.directory / "ssh-host-key.pub")

    def _forget_reaped_keys(self):
        for row in self.store.runs():
            if row.get("reaped") and row.get("settled") is not None:
                root = (Path(self.config["state_root"]) / "runs").resolve()
                directory = (root / row["run_id"]).resolve()
                if not directory.is_relative_to(root):
                    raise Infrastructure("invalid reaped run state path")
                forget(directory)

    def _ledger_logs(self):
        logs = Path(self.config["ledger"]).parent / "gate-logs"
        with tarfile.open(self.directory / "ledger-logs-before.tar.gz", "w:gz") as t:
            if logs.exists():
                t.add(logs, arcname="gate-logs")

    def _import_logs(self, lease):
        logs = self.directory / "evidence/var/log/vm-gate/ledger-gate-logs"
        target = Path(self.config["ledger"]).parent / "gate-logs"
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lease.writer():
            for path in logs.glob("*"):
                if not path.is_file():
                    continue
                dest = target / path.name
                if dest.exists():
                    if dest.read_bytes() != path.read_bytes():
                        raise Infrastructure(
                            "canonical gate log conflicts with retained VM log"
                        )
                else:
                    with dest.open("xb") as f:
                        f.write(path.read_bytes())

    def run(self):
        with ConfigLease(self.config):
            try:
                return self._run()
            finally:
                row = self.store.get(self.run_id)
                if row is None or row.get("settled") is not None:
                    # No reservation means this run never attempted a create;
                    # settlement requires proven resource absence.
                    forget(self.directory)

    def _run(self):
        source = self.source
        with LedgerLease(self.config["ledger"], source["tree"]) as lease:
            before = lease.snapshot(self.directory / "ledger-before.tsv")
            self._ledger_logs()
            self._key()
            remote = self.executor_factory(
                self.config, self.directory, source, self.command, None
            )
            remote.preflight()
            provider = self.provider()
            remote.provider = provider
            # No pricing or image read precedes expiry cleanup.
            reaped = reap_and_settle(provider, self.store)
            self._forget_reaped_keys()
            quote = provider.read("pricing", self.args.type)
            image = provider.read(
                "image_info",
                self.config.get("image_id", self.config.get("snapshot_id")),
            )
            native = self.config.get("host_profile") == "native-arm64-oci-v1"
            if native:
                from .native_oci import validate_image

                if (
                    self.args.type != "cax21"
                    or quote.get("architecture") != "arm"
                    or quote.get("deprecated")
                    or quote.get("cores") != 4
                    or quote.get("memory") != 8
                    or quote.get("disk") != 80
                ):
                    raise Refused("native ARM profile requires CAX21")
                validate_image(image, quote["disk"])
            elif (
                image.get("status") != "available"
                or image.get("architecture") != "x86"
                or image.get("disk_size", 0) > quote["disk"]
            ):
                raise Refused(
                    "configured snapshot unavailable or incompatible with requested server type"
                )
            verify_train_main(self.config["repo"], source)
            durations = {
                key: self.config[key + "_seconds"]
                for key in ["setup", "pull", "cleanup", "margin"]
                if key + "_seconds" in self.config
            }
            budget = CompletionBudget(time.time(), self.args.timeout, **durations)
            result = run_session(
                provider=provider,
                store=self.store,
                remote=remote,
                run_id=self.run_id,
                owner=self.config["owner"],
                sha=source["sha"],
                budget=budget,
                directory=self.directory,
                server_type=self.args.type,
                hourly_eur=quote["server_hourly"],
                ip_hourly_eur=quote["ip_hourly"],
                pre_reaped=reaped,
                max_reserve_eur=self.config.get("run_ceiling_eur"),
            )
            result.update(
                source=source,
                requested_command=self.command,
                requested_stages=self.args.stages,
                scope=source["scope"],
                host_profile=self.config.get("host_profile", "snapshot"),
            )
            try:
                after = self.directory / "evidence/var/log/vm-gate/ledger-after.tsv"
                if after.exists():
                    self._import_logs(lease)
                    result["ledger_rows_imported"] = lease.import_rows(
                        before, after.read_bytes()
                    )
                elif result["infrastructure"] is None:
                    raise Infrastructure(
                        "completed gate lacks authoritative ledger evidence"
                    )
                if result["infrastructure"] is None:
                    verify_train_main(self.config["repo"], source)
            except (Infrastructure, Refused) as exc:
                result.update(
                    exit=int(exc.exit_code),
                    infrastructure=exc.classification,
                    error=str(exc),
                )
            if result.get("cleanup", {}).get("exact_ids_absent"):
                forget(self.directory)
            if self.store.get(self.run_id) is not None:
                self.store.update(
                    self.run_id,
                    {
                        "summary": str(self.directory / "summary.json"),
                        "exit": result["exit"],
                        "infrastructure": result["infrastructure"],
                    },
                )
            write_summary(self.directory, result)
            return result

    def snapshot(self):
        from .snapshot_ops import SnapshotOperations
        from .snapshot import rebuild

        with ConfigLease(self.config, exclusive=True):
            operations = SnapshotOperations(self)
            try:
                try:
                    rebuild(operations)
                except BaseException as exc:
                    return operations.result(exc)
                return operations.result()
            finally:
                row = self.store.get(self.run_id)
                if row is None or row.get("settled") is not None:
                    forget(self.directory)
