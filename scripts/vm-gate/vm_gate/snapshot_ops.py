"""Bounded provider/SSH operations for the restored-snapshot transaction."""

from decimal import Decimal
import json
import math
import os
from pathlib import Path
import shlex
import time

from .errors import Infrastructure, Refused
from .executor import Executor, REMOTE
from .host_contract import verify_receipt
from .host_keys import forget
from .lifecycle import write_summary
from .reaping import reap_and_settle
from .toolplan import resolve

Q = shlex.quote


class SnapshotOperations:
    PHASES = {
        "builder": 900,
        "install": 900,
        "seal": 1800,
        "delete-builder": 180,
        "restore": 900,
        "delete-verify": 180,
        "publish": 60,
        "retire-old": 180,
        "cleanup": 300,
        "margin": 300,
    }

    def __init__(self, runtime):
        self.r = runtime
        self.config = runtime.config
        self.directory = runtime.directory
        self.old_id = self.config["snapshot_id"]
        self.provider = None
        self.remote = None
        self.created = time.time()
        self.expires = math.ceil(self.created + sum(self.PHASES.values()))
        self.resources = []
        self.servers = {}
        self.new_id = None
        self.images = []
        self.attempts = 0
        self.unknown_transients = False
        self.reserved = False
        self.cleanup_receipt = None
        self.published = False
        self.old_deleted = False
        self.image_unknown = False
        self.image_attempted = False
        self.quote = None
        self.storage = Decimal(0)
        self.actual = None
        self.verified = False
        self.labels = {
            "run_id": runtime.run_id,
            "owner": self.config["owner"],
            "sha": runtime.source["sha"],
            "expires": self.expires,
        }

    def phase(self, name):
        names = list(self.PHASES)
        future = sum(self.PHASES[n] for n in names[names.index(name) + 1 :])
        cutoff = self.expires - future
        remaining = min(self.PHASES[name], cutoff - time.time())
        if remaining <= 0:
            raise Infrastructure(f"snapshot {name} cannot finish before expiry")
        self.phase_deadline = time.monotonic() + remaining
        if self.provider:
            self.provider.backend.deadline = self.phase_deadline
        return remaining

    def remaining(self):
        left = self.phase_deadline - time.monotonic()
        if left <= 0:
            raise Infrastructure("snapshot phase completion deadline exhausted")
        return left

    def save(self, **patch):
        if self.reserved:
            self.r.store.update(
                self.r.run_id,
                {
                    "resources": self.resources,
                    "server_attempts": self.attempts,
                    "snapshot_images": self.images,
                    "old_snapshot": self.old_id,
                    **patch,
                },
            )

    def reserve(self):
        self.server_type = self.config.get("snapshot_type", "ccx33")
        if self.server_type not in {"ccx33", "ccx43"}:
            raise Refused("snapshot_type must be ccx33 or ccx43")
        required = self.r.source["requirements"]
        if required["python"] != self.config["manifest"]["observed"]["python"]:
            raise Refused(
                "Python pin needs an OS base migration; snapshot supports Go, uv and Node pin changes"
            )
        plan = resolve(required)
        (self.directory / "tool-download-plan.json").write_text(
            json.dumps(plan, indent=2) + "\n"
        )
        self.r._key()
        self.ledger = self.directory / "snapshot-ledger.tsv"
        self.private_config = dict(self.config, ledger=str(self.ledger))
        (self.directory / "ledger-before.tsv").write_bytes(b"")
        self.ledger.write_bytes(b"")
        import tarfile

        with tarfile.open(self.directory / "ledger-logs-before.tar.gz", "w:gz"):
            pass
        self.remote = Executor(
            self.private_config, self.directory, self.r.source, "true", None
        )
        self.remote.verify_host = False
        self.remote.preflight()
        self.provider = self.r.provider()
        self.remote.provider = self.provider
        self.reaped = reap_and_settle(self.provider, self.r.store)
        self.r._forget_reaped_keys()
        self.quote = self.provider.read("pricing", self.server_type)
        image = self.provider.read("image_info", self.old_id)
        if (
            image.get("status") != "available"
            or image.get("architecture") != "x86"
            or image.get("disk_size", 0) > self.quote["disk"]
        ):
            raise Refused("current base snapshot is unavailable or incompatible")
        pricing = self.provider.read("snapshot_pricing")
        if pricing["currency"] != "EUR":
            raise Refused("snapshot pricing must be EUR")
        self.storage_rate = Decimal(pricing["image"]["price_per_gb_month"]["gross"])
        # Count a conservative first-two-week storage charge in the cap. This
        # is reported separately from compute and observed prorated storage.
        self.storage = (
            self.storage_rate * Decimal(self.quote["disk"]) * Decimal(14) / Decimal(30)
        )
        hours = math.ceil((self.expires - time.time()) / 3600)
        reserve = (
            2 * hours * Decimal(self.quote["server_hourly"])
            + hours * Decimal(self.quote["ip_hourly"])
            + self.storage
        )
        self.r.store.reserve(
            self.r.run_id,
            str(reserve),
            owner=self.config["owner"],
            sha=self.r.source["sha"],
            expires=self.expires,
        )
        self.reserved = True
        self.save(
            purpose="snapshot",
            hourly_eur=self.quote["server_hourly"],
            ip_hourly_eur=self.quote["ip_hourly"],
            storage_reserve_eur=str(self.storage),
        )

    def create(self, method, *, server_start=None, role=None, **kwargs):
        try:
            return self.provider.create(method, self.r.run_id, **kwargs)
        except (Infrastructure, Refused) as exc:
            found = getattr(exc, "resources", None)
            self.unknown_transients = found is None
            known = {(x["kind"], x["id"]) for x in self.resources}
            for item in found or []:
                if (item["kind"], item["id"]) not in known:
                    self.resources.append(item)
                if item["kind"] == "server":
                    self.servers.setdefault(
                        item["id"],
                        {
                            "created": server_start or self.created,
                            "role": role or "unknown",
                        },
                    )
            self.save(unknown_transients=self.unknown_transients)
            raise

    def builder(self):
        self.phase("builder")
        self.key = self.create("create_key", labels=self.labels)
        self.resources.append(self.key)
        self.save(attempted_ip=True)
        self.ip = self.create("create_ip", labels=self.labels)
        self.resources.append(self.ip)
        return self.create_vm("builder")

    def create_vm(self, role):
        self.attempts += 1
        self.save(attempted_server=True)
        started = time.time()
        server = self.create(
            "create_server",
            server_start=started,
            role=role,
            server_type=self.server_type,
            labels=self.labels,
            key=self.key,
            ip=self.ip,
        )
        self.resources.append(server)
        self.servers[server["id"]] = {"created": started, "role": role}
        self.save()
        self.remote.prepare(server, timeout=self.remaining())
        return server

    def install(self, server):
        self.phase("install")
        self.remote.deadline = self.phase_deadline
        # Establish the old base byte identity before allowing tool replacements.
        check = f"""import json
from pathlib import Path
from vm_gate.host_contract import inspect_host
expected=json.loads(Path({REMOTE + "/expected-host.json"!r}).read_text())
receipt=inspect_host({REMOTE + "/source"!r},expected)
assert all(receipt[k]==expected[k] for k in ['commands','dpkg','observed']), 'base snapshot byte identity differs'
print(json.dumps(receipt))
"""
        self.remote.run(
            f"cd {REMOTE}/source && runuser -u gateuser -- "
            + self.remote.env()
            + "python3 -c "
            + Q(check),
            "base-identity",
        )
        self.remote.upload(
            self.directory / "tool-download-plan.json",
            REMOTE + "/tool-download-plan.json",
        )
        self.remote.run(
            self.remote.env(root=True)
            + f"python3 -m vm_gate.install_tools {REMOTE}/tool-download-plan.json",
            "tool-install",
        )
        record = self.remote.run(
            f"cd {REMOTE}/source && runuser -u gateuser -- "
            + self.remote.env()
            + f"python3 -m vm_gate.host_contract record {REMOTE}/source {REMOTE}/source.json {REMOTE}/expected-host.json",
            "new-host-contract",
        )
        self.manifest = json.loads(record.stdout)
        self.manifest["source_sha"] = self.r.source["sha"]
        self.manifest["downloads"] = json.loads(
            (self.directory / "tool-download-plan.json").read_text()
        )
        self.manifest_path = self.directory / "new-host-manifest.json"
        self.manifest_path.write_text(json.dumps(self.manifest, indent=2) + "\n")
        self.remote.upload(self.manifest_path, REMOTE + "/new-host-manifest.json")
        self.remote.run(
            f"install -m 0644 {REMOTE}/new-host-manifest.json /var/lib/aweb-gates/host-toolchain-manifest.json",
            "record-image-manifest",
        )

    def seal(self, server):
        self.phase("seal")
        self.remote.deadline = self.phase_deadline
        self.remote.run(
            f"""set -e
rm -rf {REMOTE} /var/log/vm-gate /root/.cache /home/gateuser/.cache
find /root /home/gateuser -type f -name authorized_keys -exec truncate -s 0 {{}} +
rm -f /etc/ssh/ssh_host_* /root/.bash_history /home/gateuser/.bash_history
cloud-init clean --logs --seed
sync
""",
            "seal-scrub",
        )
        self.image_attempted = True
        try:
            result = self.provider.create(
                "create_image",
                self.r.run_id,
                server=server,
                labels=self.labels,
                reconcile_method="snapshot_candidates",
            )
        except (Infrastructure, Refused) as exc:
            found = getattr(exc, "resources", None)
            self.image_unknown = found is None or isinstance(exc, Infrastructure)
            self.images = [x["id"] for x in (found or [])]
            self.save(snapshot_outcome_unknown=self.image_unknown)
            raise
        self.new_id = result["id"]
        self.images = [self.new_id]
        self.save()
        self.provider.backend.wait(result.get("action"), seconds=self.remaining())
        image = self.provider.read("image_info", self.new_id)
        if image.get("status") != "available":
            raise Infrastructure("candidate snapshot is not available")
        self.storage = (
            self.storage_rate
            * Decimal(str(image.get("image_size", self.quote["disk"])))
            * Decimal(14)
            / Decimal(30)
        )
        self.save(storage_reserve_eur=str(self.storage))
        return self.new_id

    def delete_vm(self, server):
        role = self.servers[server["id"]]["role"]
        self.phase("delete-builder" if role == "builder" else "delete-verify")
        self.provider.backend.delete(server)
        if self.provider.read("get", "server", server["id"]) is not None:
            raise Infrastructure("snapshot VM remains after deletion")
        self.servers[server["id"]]["deleted"] = time.time()
        self.save(server_times=self.servers)

    def restore(self, image):
        self.phase("restore")
        self.provider.backend.config["snapshot_id"] = image
        child = self.directory / "restore"
        child.mkdir(mode=0o700)
        # Each VM has its own SSH alias; only the private key is shared locally.
        for name in [
            "ssh-key",
            "ssh-key.pub",
            "ssh-host-key.pub",
            "source.json",
            "source.bundle",
            "ledger-before.tsv",
            "ledger-logs-before.tar.gz",
        ]:
            import shutil

            shutil.copyfile(self.directory / name, child / name)
            if name == "ssh-key":
                (child / name).chmod(0o600)
        config = dict(self.private_config, manifest=self.manifest)
        source = dict(self.r.source, bundle=str(child / "source.bundle"))
        self.remote = Executor(config, child, source, "true", self.provider)
        self.remote.preflight()
        return self.create_vm("verify")

    def verify(self, server):
        receipt = json.loads(
            (self.remote.directory / "host-contract.stdout").read_text()
        )
        verify_receipt(
            receipt, self.r.source["requirements"], self.manifest, self.r.source["sha"]
        )
        self.verified = True
        return self.manifest

    def publish_config(self, image, manifest):
        self.phase("publish")
        self.provider.backend.promote_image(image, self.r.run_id)
        path = Path(self.config["config_path"])
        current = json.loads(path.read_text())
        if current["snapshot_id"] != self.old_id:
            raise Refused("old base config changed before publish")
        current.update(snapshot_id=image, snapshot_manifest=str(self.manifest_path))
        temporary = path.with_name(path.name + "." + self.r.run_id + ".tmp")
        with temporary.open("x") as f:
            json.dump(current, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self.published = True
        self.save(config_published=True)

    def delete_old(self):
        self.phase("retire-old")
        self.provider.backend.delete_base(self.old_id, self.new_id)
        if self.provider.read("get", "image", self.old_id) is not None:
            raise Infrastructure("old base snapshot remains after verified replacement")
        self.old_deleted = True

    def cleanup(self):
        if self.provider is None:
            return
        self.phase("cleanup")
        self.cleanup_receipt = self.provider.cleanup(self.r.run_id)
        remaining = [
            (x["kind"], x["id"])
            for x in self.resources
            if self.provider.read("get", x["kind"], x["id"]) is not None
        ]
        if remaining:
            raise Infrastructure("recorded snapshot transient resources remain")
        forget(self.directory)
        self.finished = time.time()
        for row in self.servers.values():
            row.setdefault("deleted", self.finished)

    def settle(self):
        if not self.reserved:
            return
        if not self.cleanup_receipt or self.unknown_transients:
            raise Infrastructure(
                "snapshot cleanup or create outcome unproven; reservation held"
            )
        compute = sum(
            Decimal(self.quote["server_hourly"])
            * max(1, math.ceil((r["deleted"] - r["created"]) / 3600))
            for r in self.servers.values()
        )
        ip = (
            Decimal(self.quote["ip_hourly"])
            * max(1, math.ceil((time.time() - self.created) / 3600))
            if any(x["kind"] == "ip" for x in self.resources)
            else Decimal(0)
        )
        storage = self.storage if self.images or self.image_unknown else Decimal(0)
        self.actual = compute + ip + storage
        self.r.store.settle(self.r.run_id, str(self.actual))
        self.cost = {
            "compute_eur": str(compute),
            "ip_eur": str(ip),
            "storage_14day_upper_bound_eur": str(storage),
            "ledger_charge_eur": str(self.actual),
            "basis": "compute billed hours plus conservative fourteen-day snapshot storage",
        }
        self.save(cost=self.cost, new_snapshot_id=self.new_id)

    def result(self, error=None):
        known = isinstance(error, (Infrastructure, Refused))
        result = {
            "run_id": self.r.run_id,
            "sha": self.r.source["sha"],
            "operation": "snapshot",
            "exit": int(error.exit_code) if known else (70 if error else 0),
            "infrastructure": error.classification
            if known
            else ("infrastructure" if error else None),
            "error": str(error) if known else (type(error).__name__ if error else None),
            "old_snapshot_id": self.old_id,
            "new_snapshot_id": self.new_id,
            "verified": self.verified,
            "old_deleted": self.old_deleted,
            "config_published": self.published,
            "orphan_snapshots": self.images if not self.published else [],
            "snapshot_outcome_unknown": self.image_unknown,
            "servers": self.servers,
            "created": self.created,
            "finished": time.time(),
            "cleanup": self.cleanup_receipt,
            "cost": getattr(self, "cost", None),
            "spend": self.r.store.totals(),
        }
        write_summary(self.directory, result)
        return result
