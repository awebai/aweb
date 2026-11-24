"""Acquire one disposable KVM guest through the Merak host's exclusive slot."""

import json
import os
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import time

from .config import child_environment
from .errors import Infrastructure, Refused
from .expiry import CompletionBudget
from .lifecycle import execute_guest, write_summary
from .signals import handling
from .source import verify_train_main
from .transport import Transport

SSH = [
    "ssh",
    "-T",
    "-o",
    "BatchMode=yes",
    "-o",
    "StrictHostKeyChecking=yes",
    "-o",
    "ForwardAgent=no",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "ServerAliveInterval=15",
    "-o",
    "ServerAliveCountMax=3",
]


def host_ssh():
    # The host login can use the Mac's agent. The guest uses its per-run key;
    # neither SSH hop forwards the agent or its environment to the remote host.
    sock = os.environ.get("SSH_AUTH_SOCK")
    return [*SSH, "-o", "IdentityAgent=" + sock] if sock else SSH


def endpoint(config):
    settings = config.get("merak") or {}
    host = settings.get("host", "merak")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", host):
        raise Refused("invalid Merak SSH alias")
    base = settings.get("base_sha256", "")
    launcher = settings.get("launcher_image_id", "")
    if not re.fullmatch(r"[0-9a-f]{64}", base) or not re.fullmatch(
        r"sha256:[0-9a-f]{64}", launcher
    ):
        raise Refused("Merak requires a verified base SHA-256 and launcher image ID")
    return host, base, launcher


def guest_transport(directory, run, host, container):
    if not re.fullmatch(r"[0-9a-f]{64}", container):
        raise Infrastructure("invalid Merak guest container")
    # The pin is private to this run's known_hosts file.
    transport = Transport(directory, "127.0.0.1", int(run[3:], 16) or 1)
    proxy = shlex.join(
        [
            *host_ssh(),
            host,
            "docker",
            "exec",
            "-i",
            container,
            "socat",
            "STDIO",
            "TCP4:127.0.0.1:2222",
        ]
    )
    transport.options.extend(["-o", "ProxyCommand=" + proxy])
    return transport


def validate_cloud_config(host, image, seed, directory):
    """Validate the exact NoCloud input on the launcher host before allocating KVM."""
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", image):
        raise Refused("Merak cloud-init validator requires an immutable image ID")
    user_data = "#cloud-config\n" + json.dumps(seed)
    check = "umask 077; cat > /tmp/user-data; cloud-init --version; cloud-init schema --config-file /tmp/user-data"
    argv = ["docker", "run", "--rm", "-i", "--pull=never", "--read-only",
            "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--tmpfs", "/tmp:mode=0700", "--entrypoint", "/bin/sh", image, "-ec", check]
    result = subprocess.run(
        [*host_ssh(), host, shlex.join(argv)], input=user_data, text=True,
        capture_output=True, env=child_environment(), timeout=60,
    )
    # A schema diagnostic can quote supplied host key material. Only retain the verdict.
    proof = {"validator_image": image, "user_data_sha256": hashlib.sha256(user_data.encode()).hexdigest(),
             "exit": result.returncode, "valid": result.returncode == 0}
    (directory / "cloud-config-schema.json").write_text(json.dumps(proof, indent=2) + "\n")
    if result.returncode:
        raise Refused("Merak cloud-init schema refused the user-data before guest allocation")


def run_guest(runtime, remote):
    cfg, run, directory = runtime.config, runtime.run_id, runtime.directory
    host, base, launcher = endpoint(cfg)
    manifest_bytes = Path(cfg["execution_manifest"]).read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    delta = Path(cfg["merak"]["package_delta"]).read_bytes()
    delta_hash = hashlib.sha256(delta).hexdigest()
    if delta_hash != cfg["manifest"].get("package_delta_sha256"):
        raise Refused("Merak OS package delta differs from the pinned manifest")
    (directory / "merak-package-delta.json").write_bytes(delta)
    (directory / "merak-host-manifest.json").write_bytes(manifest_bytes)
    verify_train_main(cfg["repo"], runtime.source)
    durations = {
        name: cfg[name + "_seconds"]
        for name in ["setup", "pull", "cleanup", "margin"]
        if name + "_seconds" in cfg
    }
    budget = CompletionBudget(time.time(), runtime.args.timeout, **durations)
    public_key = cfg["public_key"].strip()
    spec = {
        "run": run,
        "base": base,
        "launcher": launcher,
        "firewall_sha256": hashlib.sha256(
            Path(__file__).with_name("merak_egress.py").read_bytes()
        ).hexdigest(),
        "duration": int(sum(budget.steps.values()) + 1),
        "seed": {
            # Freeze scheduled package changes before the immutable host is admitted.
            "package_update": False,
            "package_upgrade": False,
            "bootcmd": [
                ["systemctl", "mask", "--runtime", "apt-daily.timer",
                 "apt-daily-upgrade.timer", "apt-daily.service",
                 "apt-daily-upgrade.service", "unattended-upgrades.service"],
                ["systemctl", "stop", "apt-daily.timer", "apt-daily-upgrade.timer"],
            ],
            "disable_root": False,
            "users": [{"name": "root", "ssh_authorized_keys": [public_key]}],
            "ssh_authorized_keys": [public_key],
            "ssh_pwauth": False,
            "ssh_deletekeys": True,
            "ssh_keys": {
                "ed25519_private": cfg["ssh_host_private"],
                "ed25519_public": cfg["ssh_host_public"],
            },
        },
    }
    validator = cfg["merak"].get("cloud_init_validator_image_id")
    if validator:
        validate_cloud_config(host, validator, spec["seed"], directory)
    helper = Path(__file__).with_name("merak_host.py").read_text()
    command = "python3 -u -c " + shlex.quote(helper)
    summary = {
        "run_id": run,
        "target": "merak",
        "host": host,
        "base_sha256": base,
        "launcher_image_id": launcher,
        "sha": runtime.source["sha"],
        "stages": [],
        "merak_manifest_sha256": manifest_hash,
        "package_delta_sha256": delta_hash,
        "package_delta_file": "merak-package-delta.json",
        "python3_sha256": cfg["manifest"]["commands"]["python3"]["sha256"],
        "created": time.time(),
        "exit": 70,
        "infrastructure": "infrastructure",
        "state": "queued",
    }
    write_summary(directory, summary)
    with (directory / "merak-host.stderr").open("w") as errors:
        proc = subprocess.Popen(
            [*host_ssh(), host, command],
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            env=child_environment(),
        )
        try:
            proc.stdin.write(json.dumps(spec) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise Infrastructure("Merak host did not return a guest admission")
            admission = json.loads(line)
            if (
                admission.get("ready") is not True
                or admission.get("run") != run
                or admission.get("base") != base
                or not re.fullmatch(r"[a-f0-9]{64}", admission.get("container", ""))
                or not re.fullmatch(r"[a-f0-9]{64}", admission.get("network_id", ""))
                or admission.get("egress", {}).get("present") is not True
                or admission["egress"].get("run") != run
                or admission["egress"].get("helper_sha256") != spec["firewall_sha256"]
            ):
                raise Infrastructure("Merak guest admission differs from the dispatch")
            budget = CompletionBudget(time.time(), runtime.args.timeout, **durations)
            summary.update(state="running", admission=admission, expires=budget.expires)
            write_summary(directory, summary)
            remote.transport = guest_transport(
                directory, run, host, admission["container"]
            )
            deadline = time.monotonic() + budget.require("setup", now=time.time())
            while time.monotonic() < deadline:
                try:
                    if (
                        remote.transport.run("true", timeout=8, check=False).returncode
                        == 0
                    ):
                        break
                except Infrastructure:
                    pass
                time.sleep(2)
            else:
                raise Infrastructure(
                    "Merak guest did not accept its pinned SSH identity"
                )
            guest_manifest = remote.transport.run(
                "sha256sum /var/lib/aweb-gates/host-toolchain-manifest.json", timeout=15
            )
            if guest_manifest.stdout.split()[0] != manifest_hash:
                raise Infrastructure(
                    "guest image has a different Merak toolchain manifest"
                )
            execute_guest(remote, {"run_id": run}, budget, summary)
        except BaseException as exc:
            summary.update(
                exit=getattr(exc, "exit_code", 70),
                infrastructure=getattr(exc, "classification", "infrastructure"),
                error=str(exc)
                if isinstance(exc, (Infrastructure, Refused))
                else type(exc).__name__,
            )
        finally:
            with handling(cleanup=True):
                proc.stdin.close()
                try:
                    proc.wait(timeout=150)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                proc.stdout.close()
                # Re-read the persisted host receipt over an independent pinned connection.
                try:
                    rc = subprocess.run(
                        [*host_ssh(), host, command + " --reconcile " + shlex.quote(run)],
                        env=child_environment(),
                        text=True,
                        capture_output=True,
                        timeout=140,
                        check=True,
                    )
                    closure = json.loads(rc.stdout)
                    if (
                        closure.get("run_id") != run
                        or closure.get("exact_ids_absent") is not True
                        or closure.get("labels_absent") is not True
                        or closure.get("guest_disk_and_checkout_absent") is not True
                    ):
                        raise Infrastructure("Merak closure lacks resource absence")
                    admitted = summary.get("admission", {}).get("container")
                    if admitted and admitted not in closure["container_ids"]:
                        raise Infrastructure(
                            "Merak closure lacks admitted container ID"
                        )
                    network = summary.get("admission", {}).get("network_id")
                    if network and network not in closure.get("removed_network_ids", []):
                        raise Infrastructure("Merak closure lacks admitted network ID")
                    if closure.get("egress", {}).get("present") is not False:
                        raise Infrastructure("Merak closure lacks firewall removal")
                    summary.update(state="closed", cleanup=closure)
                except (
                    ValueError,
                    OSError,
                    Infrastructure,
                    subprocess.SubprocessError,
                ) as exc:
                    summary.update(
                        state="cleanup_pending",
                        exit=70,
                        infrastructure="infrastructure",
                        cleanup_error=type(exc).__name__,
                    )
                summary["finished"] = time.time()
                summary["total_seconds"] = summary["finished"] - summary["created"]
                write_summary(directory, summary)
    return summary
