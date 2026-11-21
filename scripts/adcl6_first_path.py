#!/usr/bin/env python3
"""Product commands for optional human issuance, enrollment and public proof.

aw performs human keychain preparation, certificate registration, enrollment,
approved add through the generic 428 client, proof export and outside verification.
The operator uses the holder's private commands for namespace configuration and
operator issuance. Python configures the disposable infrastructure and real DNS,
automates Chromium virtual authenticators, and makes read-only assertions. It
never generates a person's key, signs a request/message, or registers its ID.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import tarfile
import time
import tomllib
from urllib.parse import quote

APPROVAL = "426fc6ba11f916cd2c2b4d0246e802486e1ab946"
ORG = "org.adcl6.test"
REGISTRY = "https://awid.adcl6.test"
SITE = "https://approval.adcl6.test"
AUDIENCE = "https://holder.adcl6.test"
RP = "approval.adcl6.test"
DNS = "172.29.190.53"
HOLDER_IP = "172.29.190.13"
NETWORK = "172.29.190.0/24"
STEP_OWNERS = {
    "aw": [
        "human init through real OS keychain and PTY",
        "human register",
        "human enroll start/material/confirm/activate",
        "human add through generic 428 approval",
        "id proof with stored evidence",
        "plain outside aw verify",
    ],
    "holder_private_cli": [
        "controller/namespace setup",
        "operator issue-person",
    ],
    "deployment_operator": [
        "edit deployment.yaml human_approval and run the product policy renderer",
    ],
    "driver": [
        "disposable service and authoritative DNS fixture lifecycle",
        "Chromium virtual-authenticator ceremony automation",
        "read-only public registry and output assertions",
    ],
}


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with open(temporary, "w", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(value, stream, indent=2)
    temporary.chmod(0o600)
    temporary.replace(path)


def public_file(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    path.parent.chmod(0o755)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(text)
    temporary.chmod(0o644)
    temporary.replace(path)


def retain(args) -> None:
    # The driver runs as the disposable Docker operator. Give only the retained
    # diagnostics/exports back to the host operator before removing its image.
    work = Path("/work")
    names = (
        "journey.json",
        "first-activation.json",
        "second-activation.json",
        "first-outside.json",
        "first-no-evidence-outside.json",
        "second-outside.json",
        "third-unconfigured-no-evidence-outside.json",
        "approval-record.json",
        "approval-page.json",
        "controller-public.json",
        "command-failure.stderr",
        "prompt-counts.json",
    )
    paths = [work / name for name in names if (work / name).exists()]
    public = work / "public"
    if public.exists():
        paths.extend(public.rglob("*"))
        paths.append(public)
    metadata = [
        {
            "path": str(p.relative_to(work)),
            "uid": p.stat().st_uid,
            "gid": p.stat().st_gid,
            "mode": oct(p.stat().st_mode & 0o777),
        }
        for p in paths
    ]
    save(work / "retention.json", metadata)
    paths.append(work / "retention.json")
    for path in paths:
        os.chown(path, args.uid, args.gid, follow_symlinks=False)
    # Private identity/browser directories also belong to the root driver.
    # Erase them here, so a nonroot Linux host can remove the remaining work.
    for path in work.iterdir():
        if path.name in (*names, "public", "retention.json"):
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()


def extract(archive: Path, expected: str, destination: Path, prefixes=()) -> None:
    commit = subprocess.check_output(
        ["git", "get-tar-commit-id"], stdin=archive.open("rb"), text=True
    ).strip()
    if commit != expected:
        raise RuntimeError("input archive does not name the pinned commit")
    with tarfile.open(archive) as source:
        members = [
            member
            for member in source
            if not prefixes or any(member.name.startswith(p) for p in prefixes)
        ]
        source.extractall(destination, members=members, filter="data")


def archive_running_tree(root: Path, archive: Path) -> str:
    if subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=root).returncode:
        raise RuntimeError("journey requires a clean checked-out source tree")
    source_sha = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    with archive.open("wb") as stream:
        subprocess.run(
            [
                "git",
                "archive",
                "--format=tar",
                source_sha,
                "cli/go",
                "awid",
                "key-holder",
                "deploy/team",
            ],
            cwd=root,
            stdout=stream,
            check=True,
        )
    return source_sha


def prepare(args) -> None:
    runtime = args.runtime.resolve()
    build = runtime / "build"
    build.mkdir(mode=0o700)
    extract(args.approval_archive, APPROVAL, build / "approval")
    # Build aw and holder from this clean checkout, including the landing merge.
    # Only compiled artifacts/wheels enter the application image.
    root = Path(__file__).resolve().parents[1]
    archive = runtime / "source.tar"
    source_sha = archive_running_tree(root, archive)
    extract(
        archive, source_sha, build / "holder", ("awid/", "key-holder/", "deploy/team/")
    )
    go_tree = subprocess.check_output(
        ["git", "rev-parse", f"{source_sha}:cli/go"], cwd=root, text=True
    ).strip()
    product = build / "aw-source"
    extract(archive, source_sha, product, ("cli/go/",))
    env = dict(
        os.environ,
        GOOS="linux",
        GOARCH=args.architecture,
        CGO_ENABLED="0",
        GOWORK="off",
    )
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-o",
            str(build / "aw"),
            "./cmd/aw",
        ],
        cwd=product / "cli/go",
        env=env,
        check=True,
    )
    shutil.rmtree(product)
    (build / "journey.py").write_bytes(Path(__file__).read_bytes())
    (build / "Dockerfile").write_bytes(
        (root / "scripts/adcl6-first-path.Dockerfile").read_bytes()
    )
    runner = []
    for lock, names in (
        ("naapp-lib/uv.lock", {"playwright", "pyee", "greenlet"}),
        ("naapp/secrets/uv.lock", {"pexpect", "ptyprocess"}),
    ):
        runner_lock = tomllib.loads((root / lock).read_text())
        for package in runner_lock["package"]:
            if package["name"] not in names:
                continue
            artifacts = package.get("wheels", []) + (
                [package["sdist"]] if "sdist" in package else []
            )
            runner.append(
                package["name"]
                + "=="
                + package["version"]
                + " "
                + " ".join("--hash=" + item["hash"] for item in artifacts)
            )
    if len(runner) != 5:
        raise RuntimeError(
            "browser dependency closure missing from the repository lock"
        )
    (build / "runner-requirements.txt").write_text("\n".join(runner) + "\n")
    runtime.joinpath("work/public").mkdir(parents=True, mode=0o700)
    runtime.joinpath("public").mkdir(mode=0o755)
    public_file(
        runtime / "public/Corefile",
        """adcl6.test:53 {
  errors
  file /zones/adcl6.test.zone adcl6.test {
    reload 1s
  }
}
.:53 {
  forward . 127.0.0.11
}
""",
    )
    public_file(runtime / "public/adcl6.test.zone", zone(None))
    public_file(
        runtime / "public/nginx.conf",
        """events {}
http {
  access_log off;
  error_log /dev/stderr warn;
  server {
    listen 443 ssl;
    server_name awid.adcl6.test;
    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    location / { proxy_pass http://awid:8010; proxy_set_header Host $host; }
  }
  server {
    listen 443 ssl;
    server_name approval.adcl6.test;
    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    location / {
      proxy_pass http://approval:8030;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $remote_addr;
    }
  }
  server {
    listen 443 ssl;
    server_name holder.adcl6.test;
    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    location / { proxy_pass http://holder:8081; proxy_set_header Host $host; }
  }
}
""",
    )
    image = args.project + "-runtime:journey"
    common = {
        "image": image,
        "platform": "linux/" + args.architecture,
        "dns": [DNS],
        "environment": {
            "SSL_CERT_FILE": "/public/ca.crt",
            "AWID_REGISTRY_URL": REGISTRY,
            "PYTHONUNBUFFERED": "1",
            "HOME": "/tmp",
        },
        "volumes": [str(runtime / "public") + ":/public:ro"],
    }
    services = {}
    for name, database in (("pg-awid", "awid"), ("pg-approval", "approval")):
        services[name] = {
            "image": "postgres:16-alpine",
            "environment": {
                "POSTGRES_USER": "fixture",
                "POSTGRES_PASSWORD": "disposable",
                "POSTGRES_DB": database,
            },
            "healthcheck": {
                "test": ["CMD-SHELL", "pg_isready -U fixture -d " + database],
                "interval": "2s",
                "timeout": "2s",
                "retries": 60,
            },
        }
    services["redis"] = {
        "image": "redis:7-alpine",
        "healthcheck": {
            "test": ["CMD", "redis-cli", "ping"],
            "interval": "2s",
            "timeout": "2s",
            "retries": 60,
        },
    }
    services["dns"] = {
        "image": "coredns/coredns:1.11.3",
        "command": ["-conf", "/zones/Corefile"],
        "volumes": [str(runtime / "public") + ":/zones:ro"],
        "networks": {"default": {"ipv4_address": DNS}},
    }
    services["awid"] = {
        **common,
        "user": "1001:1001",
        "command": [
            "awid",
            "--host",
            "0.0.0.0",
            "--port",
            "8010",
            "--log-level",
            "warning",
        ],
        "environment": {
            **common["environment"],
            "AWID_DATABASE_URL": "postgresql://fixture:disposable@pg-awid/awid",
            "AWID_REDIS_URL": "redis://redis:6379/0",
            "AWID_PUBLIC_ORIGINS": REGISTRY,
        },
        "depends_on": {
            "pg-awid": {"condition": "service_healthy"},
            "redis": {"condition": "service_healthy"},
        },
        "healthcheck": {
            "test": [
                "CMD",
                "python",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8010/health', timeout=2)",
            ],
            "interval": "2s",
            "timeout": "3s",
            "retries": 60,
        },
    }
    services["approval"] = {
        **common,
        "user": "1002:1002",
        "command": [
            "sh",
            "-ec",
            "awsign migrate; exec awsign serve --bind 0.0.0.0 --port 8030",
        ],
        "environment": {
            **common["environment"],
            "AWSIGN_DATABASE_URL": "postgresql://fixture:disposable@pg-approval/approval",
            "AWSIGN_ORIGIN": SITE,
            "AWSIGN_RP_ID": RP,
            "AWSIGN_GRADING": "passkey_only",
            "AWSIGN_TRUSTED_PROXY_IPS": "172.29.190.10",
        },
        "depends_on": {"pg-approval": {"condition": "service_healthy"}},
        "healthcheck": {
            "test": [
                "CMD",
                "python",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8030/health', timeout=2)",
            ],
            "interval": "2s",
            "timeout": "3s",
            "retries": 60,
        },
    }
    holder_flags = (
        "--state /state/private --registry-origin " + REGISTRY + " --origin " + AUDIENCE
    )
    services["holder"] = {
        **common,
        "user": "1003:1003",
        "container_name": args.project + "-holder",
        "command": [
            "sh",
            "-ec",
            "umask 077; aweb-key-holder --state /state/private init --organisation "
            + ORG
            + " >/state/public-descriptor.json; exec aweb-key-holder "
            + holder_flags
            + " serve --bind 0.0.0.0 --port 8081",
        ],
        "volumes": common["volumes"] + ["holder-state:/state"],
        "networks": {"default": {"ipv4_address": HOLDER_IP}},
    }
    services["https"] = {
        "image": "nginx:1.27-alpine",
        "volumes": [
            str(runtime / "public/nginx.conf") + ":/etc/nginx/nginx.conf:ro",
            str(runtime / "tls") + ":/tls:ro",
        ],
        "networks": {"default": {"ipv4_address": "172.29.190.10"}},
        "depends_on": {
            "awid": {"condition": "service_healthy"},
            "approval": {"condition": "service_healthy"},
            "holder": {"condition": "service_started"},
        },
    }
    services["driver"] = {
        **common,
        "command": ["dbus-run-session", "--", "python", "/journey.py", "driver"],
        "cap_add": [
            "IPC_LOCK"
        ],  # The disposable real Secret Service locks key material.
        "environment": {
            **common["environment"],
            "HOME": "/work/browser-home",
            "PROJECT": args.project,
            "JOURNEY_SOURCE_SHA": source_sha,
            "HOLDER_CONTAINER": args.project + "-holder",
            "IMAGE": image,
            "HOST_WORK": str(runtime / "work"),
            "HOST_PUBLIC": str(runtime / "public"),
        },
        # The fixture operator invokes only the holder's real CLI, and creates
        # the outside verifier. Application containers receive no Docker socket
        # or holder-state mount. No holder seed is exported or archived.
        "volumes": [
            str(runtime / "public") + ":/public",
            str(runtime / "work") + ":/work",
            "/var/run/docker.sock:/var/run/docker.sock",
        ],
        "shm_size": "1gb",
    }
    save(
        runtime / "compose.json",
        {
            "services": services,
            "networks": {"default": {"ipam": {"config": [{"subnet": NETWORK}]}}},
            "volumes": {"holder-state": {}},
        },
    )
    save(
        runtime / "inputs.json",
        {
            "aw": source_sha,
            "architecture": args.architecture,
            "aw_go_tree": go_tree,
            "aw_build_flags": ["-trimpath", "-buildvcs=false"],
            "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
            "holder_and_awid": source_sha,
            "approval": APPROVAL,
            "aw_binary_sha256": hashlib.sha256((build / "aw").read_bytes()).hexdigest(),
            "approval_archive_sha256": hashlib.sha256(
                args.approval_archive.read_bytes()
            ).hexdigest(),
            "source_archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
        },
    )


def zone(controller):
    text = """$ORIGIN adcl6.test.
$TTL 1
@ IN SOA ns.adcl6.test. hostmaster.adcl6.test. (1 1 1 1 1)
@ IN NS ns.adcl6.test.
ns IN A 172.29.190.53
awid IN A 172.29.190.10
approval IN A 172.29.190.10
holder IN A 172.29.190.10
"""
    if controller:
        text += (
            '_awid.org IN TXT "awid=v1; controller='
            + controller
            + "; registry="
            + REGISTRY
            + ';"\n'
        )
    return text.replace("(1 1 1 1 1)", "(2 1 1 1 1)") if controller else text


async def command(*args, data=None, cwd=None, env=None, timeout=120):
    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE
        if data is not None
        else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
    )
    try:
        out, err = await asyncio.wait_for(process.communicate(data), timeout)
    except BaseException:
        process.kill()
        await process.wait()
        raise
    if process.returncode:
        # Stderr retained privately for diagnosis, never expanded into a public
        # assertion or a message. No automatic command or whole-journey retry.
        failure = Path("/work/command-failure.stderr")
        failure.write_bytes(err)
        failure.chmod(0o600)
        raise RuntimeError(f"{Path(args[0]).name} exited {process.returncode}")
    return out


async def human_command(
    home, args, *, actor=None, json_output=True, approval_ready=None
):
    """Run the installed human client at a real PTY, with a real Secret Service.

    The fixture types only its disposable passphrase and browser-completion
    answers. All keys, requests, certificates and evidence are produced by aw.
    """
    import pexpect

    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    env = {**os.environ, "HOME": str(home)}
    env.pop("AWEB_IDENTITY_HOME", None)
    child = pexpect.spawn(
        "aw", args, cwd=str(home), env=env, encoding="utf-8", timeout=180, echo=False
    )
    transcript = []
    unlock_prompts = 0
    registered, confirmed = False, False
    try:
        while True:
            found = await child.expect(
                [
                    r"Choose a passphrase[^\r\n]*: ",
                    r"Type the passphrase again: ",
                    r"Passphrase for that human key: ",
                    r"Register your key in that browser, then type yes to continue \[y/N\]: ",
                    r"Confirm your enrollment in that browser, then type yes to continue \[y/N\]: ",
                    "Waiting for human approval at the person's known approval service.",
                    r"How many keys did you personally register in this enrollment \(1-8\)\? ",
                    r"Do these keys match the keys you registered\? Type yes to let your issuer bind them \[y/N\]: ",
                    pexpect.EOF,
                ],
                async_=True,
            )
            transcript.append(child.before)
            if found == 8:
                break
            if found == 6:
                assert registered, "key_count_before_browser_registration"
                # This actor registered exactly one key. Do not derive the
                # person's answer from the service's registration list.
                child.sendline("1")
                continue
            if found == 7:
                assert registered, "key_review_before_browser_registration"
                child.sendline("yes")
                continue
            if found == 5:
                if approval_ready is not None:
                    approval_ready.set()
                continue
            if found < 3:
                if found == 2:
                    unlock_prompts += 1
                    assert unlock_prompts <= 1, "person_command_prompted_more_than_once"
                child.sendline("disposable adcl6 human passphrase")
            elif found == 3:
                assert actor is not None and not registered, (
                    "unexpected_browser_registration"
                )
                urls = re.findall(
                    r"Open (https://[^\s]+/enroll#[^\s]+)", "".join(transcript)
                )
                assert urls and urls[-1].startswith(SITE + "/enroll#"), (
                    "wrong_enrollment_site"
                )
                await actor.register(urls[-1].partition("/enroll#")[2])
                registered = True
                child.sendline("yes")
            else:
                assert actor is not None, "unexpected_browser_confirmation"
                if not confirmed:
                    await actor.confirm()
                    confirmed = True
                child.sendline("yes")
        child.close()
        text = "".join(transcript)
        if child.exitstatus != 0:
            failure = Path("/work/command-failure.stderr")
            failure.write_text(text)
            failure.chmod(0o600)
            raise RuntimeError(
                f"human aw exited {child.exitstatus}/{child.signalstatus}"
            )
        assert not list(home.rglob("signing.key")), "human_key_written_into_agent_home"
        if "--human" in args:
            assert unlock_prompts == 1, "person_command_did_not_unlock_once"
            counts_file = Path("/work/prompt-counts.json")
            counts = json.loads(counts_file.read_text()) if counts_file.exists() else []
            counts.append(
                {
                    "person": args[args.index("--human") + 1],
                    "command": args[4:7],
                    "unlock_prompts": unlock_prompts,
                }
            )
            save(counts_file, counts)
        if not json_output:
            return text
        start = re.search(r"[\[{]", text)
        assert start is not None, "missing_human_command_json"
        return json.loads(text[start.start() :])
    finally:
        if child.isalive():
            child.close(force=True)


async def holder_cli(operation, person=None, value=None, *extra, approval=False):
    args = [
        "docker",
        "exec",
        "-i",
        os.environ["HOLDER_CONTAINER"],
        "aweb-key-holder",
        "--state",
        "/state/private",
        "--registry-origin",
        REGISTRY,
        "--origin",
        AUDIENCE,
    ]
    if approval:
        args += ["--approval-origin", SITE, "--rp-id", RP, "--grading", "passkey_only"]
    args.append(operation)
    if person:
        args += ["--person", person]
    args += list(extra)
    raw = await command(
        *args, data=None if value is None else json.dumps(value).encode()
    )
    return json.loads(raw)


@dataclass
class Person:
    name: str
    key: str
    identity: str
    home: Path
    activation: dict | None = None

    @property
    def record_dir(self):
        return (
            self.home / ".awid" / "humans" / ORG / self.identity.removeprefix("did:aw:")
        )

    async def aw(self, *args, actor=None, json_output=True, approval_ready=None):
        return await human_command(
            self.home,
            ["--human", self.identity, "--human-domain", ORG, *args],
            actor=actor,
            json_output=json_output,
            approval_ready=approval_ready,
        )


async def deployment_policy(section):
    """Operator edits the one deployment file; the product renders its policy."""
    path = Path("/work/deployment.yaml")
    value = (
        json.loads(path.read_text())
        if path.exists()
        else {
            "team": {"id": "journey:" + ORG},
            "postgres": {},
            "network": {"servicesCidr": NETWORK},
            "aweb": {
                "image": "ghcr.io/awebai/aweb-server@sha256:" + "0" * 64,
                "publicOrigin": "https://aweb." + ORG,
            },
            "compose": {"secretsDir": "/fixture-secrets"},
        }
    )
    if section is None:
        value.pop("human_approval", None)
    else:
        value["human_approval"] = section
    save(path, value)
    rendered = await command(
        "python", "/deployment/render_env.py", "--human-approval", str(path)
    )
    public_file(Path("/public/human-approval.json"), rendered.decode())
    assert json.loads(rendered)["human_approval"] == (section or {})
    public_file(
        Path("/work/public")
        / ("policy-configured.json" if section else "policy-off.json"),
        rendered.decode(),
    )


async def enable_holder_approval():
    """Change only the owned holder; its key volume and audience stay fixed."""
    name, project = os.environ["HOLDER_CONTAINER"], os.environ["PROJECT"]
    (old,) = json.loads(await command("docker", "inspect", name))
    assert old["Config"]["Labels"]["com.docker.compose.project"] == project
    assert "--approval-origin" not in " ".join(old["Config"]["Cmd"])
    assert not any(value.startswith("AWSIGN_") for value in old["Config"]["Env"])
    (state,) = [mount for mount in old["Mounts"] if mount["Destination"] == "/state"]
    (public,) = [mount for mount in old["Mounts"] if mount["Destination"] == "/public"]
    assert state["Type"] == "volume" and state["Name"].startswith(project + "_")
    before = await holder_cli("descriptor")
    await deployment_policy(
        {"service": SITE, "require": {"organisation.human.add": "passkey"}}
    )
    # Keep the old phase's startup/configuration evidence before replacing it.
    public_file(
        Path("/work/public/holder-operator-config.json"),
        json.dumps(
            {
                "cmd": old["Config"]["Cmd"],
                "image": old["Image"],
                "user": old["Config"]["User"],
            }
        ),
    )
    await command("docker", "stop", "--time", "10", name)
    await command("docker", "rm", name)
    args = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        "com.docker.compose.project=" + project,
        "--label",
        "com.docker.compose.service=holder",
        "--user",
        "1003:1003",
        "--network",
        project + "_default",
        "--network-alias",
        "holder",
        "--ip",
        HOLDER_IP,
        "--dns",
        DNS,
        "--mount",
        "type=volume,src=" + state["Name"] + ",dst=/state",
        "--mount",
        "type=bind,src=" + public["Source"] + ",dst=/public,readonly",
    ]
    # Preserve Compose's ownership/configuration metadata when replacing this
    # one service, so compose logs/down include it and release its volume/network.
    for label, value in old["Config"]["Labels"].items():
        if label.startswith("com.docker.compose."):
            args += ["--label", label + "=" + value]
    for value in old["Config"]["Env"]:
        # This owned service has only image defaults and public fixture inputs.
        args += ["--env", value]
    args += ["--env", "HUMAN_APPROVAL_CONFIG_FILE=/public/human-approval.json"]
    args += [
        old["Image"],
        "sh",
        "-ec",
        'umask 077; exec "$@"',
        "holder",
        "aweb-key-holder",
        "--state",
        "/state/private",
        "--registry-origin",
        REGISTRY,
        "--origin",
        AUDIENCE,
        "--approval-origin",
        SITE,
        "--rp-id",
        RP,
        "--grading",
        "passkey_only",
        "serve",
        "--bind",
        "0.0.0.0",
        "--port",
        "8081",
    ]
    await command(*args)
    after = await holder_cli("descriptor", approval=True)
    assert before["did_key"] == after["did_key"], "holder_key_changed_on_configuration"


def assert_outside_verdict(result, identity, profile="creation"):
    assert result["identity_valid"] is True, (
        "outside_identity_invalid:" + result["reason"]
    )
    assert result["human_id"] == identity and result["kind"] == "human", (
        "outside_human_mismatch"
    )
    assert result["id"] == identity and result["outcome"] == "nearest_human", (
        "outside_subject_mismatch"
    )
    assert len(result["evidence"]) == 1, "outside_evidence_missing"
    (evidence,) = result["evidence"]
    if profile == "none":
        assert evidence["presence"] == "absent", "outside_unexpected_evidence"
        assert evidence["issuer_authenticated_grade"] is None, (
            "outside_unexpected_grade"
        )
        assert evidence["proof"]["status"] != "valid", "outside_invented_proof"
        return
    for part in ("statement", "proof"):
        assert isinstance(evidence.get(part), dict), f"outside_{part}_missing"
        checked = evidence[part]
        assert checked["status"] == "valid", (
            f"outside_{part}_{checked['status']}:{checked['reason']}"
        )
    assert (
        evidence["issuer_authenticated_grade"] == "passkey_uv"
        and evidence["proof_binds_grade"] is True
    ), "outside_grade_below_passkey_uv"
    assert evidence["currentness"] == "current", "outside_subject_not_current"
    if profile == "later":
        assert evidence["profile"] == "human_enrolled_later", "outside_creation_claim"
        assert isinstance(evidence["can_approve_since"], int), "outside_missing_since"
        assert evidence["continuity"] == "unknown", "outside_later_creation_continuity"
    else:
        assert evidence["continuity"] == "unbroken", (
            "outside_continuity_" + evidence["continuity"]
        )


def assert_approval_target(request, first, second):
    assert request["approver"] == first, "approval_approver_mismatch"
    assert request["act"]["target"]["person"] == second, "approval_target_mismatch"


def assert_approval_display(actual_digest, text, digest, first, second):
    assert actual_digest == digest, "approval_digest_mismatch"
    for value in (first, second, ORG, AUDIENCE, "human.add"):
        assert value in text, "approval_display_mismatch:" + value


@dataclass
class BrowserActor:
    page: object

    async def register(self, locator):
        from playwright.async_api import expect

        await self.page.goto(SITE + "/enroll#" + quote(locator, safe=""))
        assert await self.page.evaluate("window.isSecureContext")
        await self.page.locator("#register").click()
        await expect(self.page.locator("#status")).to_contain_text("Key registered.")

    async def confirm(self):
        from playwright.async_api import expect

        await self.page.locator("#confirm").click()
        await self.page.get_by_role(
            "button", name="Confirm with your key", exact=True
        ).click()
        await expect(self.page.locator("#status")).to_contain_text(
            "Enrollment confirmed."
        )

    async def login(self, person):
        from playwright.async_api import expect

        await self.page.goto(SITE + "/")
        await self.page.locator("#login").click()
        await expect(self.page.locator("#status")).to_have_text(
            "Signed in as " + person
        )

    async def approve(self, digest, first, second):
        from playwright.async_api import expect

        rows = self.page.locator("#requests article")
        displayed_digest = digest
        row = rows.filter(has=self.page.get_by_text(displayed_digest, exact=True))
        evidence_path = Path("/work/approval-page.json")
        evidence = {
            "url": self.page.url,
            "expected_digest": digest,
            "approver": first,
            "target": second,
            "status": await self.page.locator("#status").inner_text(),
            "rows_before_assertion": await rows.all_inner_texts(),
        }
        save(evidence_path, evidence)
        try:
            await expect(row).to_have_count(1)
        except AssertionError:
            evidence["rows_on_failure"] = await rows.all_inner_texts()
            evidence["status_on_failure"] = await self.page.locator(
                "#status"
            ).inner_text()
            save(evidence_path, evidence)
            raise
        assert_approval_display(
            await row.get_by_text(displayed_digest, exact=True).inner_text(),
            await row.inner_text(),
            digest,
            first,
            second,
        )
        await row.get_by_role("button", name="Approve", exact=True).click()
        await expect(row).to_have_count(0)


@asynccontextmanager
async def browsers():
    from playwright.async_api import async_playwright

    # Chromium uses the fixture CA, without ignore_https_errors or a TLS bypass.
    nss = Path.home() / ".pki/nssdb"
    nss.mkdir(parents=True, mode=0o700)
    await command("certutil", "-N", "--empty-password", "-d", "sql:" + str(nss))
    await command(
        "certutil",
        "-A",
        "-d",
        "sql:" + str(nss),
        "-n",
        "adcl6-fixture",
        "-t",
        "C,,",
        "-i",
        "/public/ca.crt",
    )
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(args=["--no-sandbox"])
        try:
            actors = []
            for _ in range(2):
                context = await browser.new_context()
                page = await context.new_page()
                page.set_default_timeout(60000)
                cdp = await context.new_cdp_session(page)
                await cdp.send("WebAuthn.enable")
                await cdp.send(
                    "WebAuthn.addVirtualAuthenticator",
                    {
                        "options": {
                            "protocol": "ctap2",
                            "transport": "internal",
                            "hasResidentKey": True,
                            "hasUserVerification": True,
                            "isUserVerified": True,
                            "automaticPresenceSimulation": True,
                        }
                    },
                )
                actors.append(BrowserActor(page))
            yield actors
        finally:
            await browser.close()


async def driver():
    import dns.asyncresolver
    import httpx
    from awid.registry import RegistryClient, DIDKeyNotFoundError
    from approval_service.canonical import parse
    from approval_service.encoding import decode
    from approval_service.seams import make_needs_human

    work = Path("/work")
    runtime = work / "browser-home" / "keyring-runtime"
    runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.environ["XDG_RUNTIME_DIR"] = str(runtime)
    await command(
        "gnome-keyring-daemon",
        "--unlock",
        "--components=secrets",
        data=b"disposable adcl6 collection password",
    )
    await command("gnome-keyring-daemon", "--start", "--components=secrets")
    report = {
        "journey_kind": "product",
        "step_owners": STEP_OWNERS,
        "completed": False,
        "phases": [],
        "aw": os.environ["JOURNEY_SOURCE_SHA"],
        "holder_and_awid": os.environ["JOURNEY_SOURCE_SHA"],
        "approval": APPROVAL,
    }
    save(work / "journey.json", report)
    for module in ("awid", "awid_service", "approval_service", "aweb_key_holder"):
        imported = __import__(module)
        assert "site-packages" in str(imported.__file__), module
    report["packages"] = {
        name: importlib.metadata.version(name)
        for name in (
            "awid-service",
            "aweb-approval-service",
            "aweb-key-holder",
            "playwright",
            "pexpect",
        )
    }
    assert not any(
        os.environ.get(name)
        for name in (
            "AWID_SKIP_DNS_VERIFY",
            "AWID_SERVICE_TOKEN",
            "AWID_RATE_LIMIT_DISABLED",
            "AWEB_FEDERATION_TEST",
            "PYTHONPATH",
        )
    )

    @asynccontextmanager
    async def phase(name):
        row = {"name": name, "outcome": "running"}
        report["phases"].append(row)
        try:
            yield
        except BaseException as error:
            row.update(outcome="failed", error=type(error).__name__)
            raise
        else:
            row["outcome"] = "passed"
            print("PASS: " + name, flush=True)
        finally:
            save(work / "journey.json", report)

    async with (
        httpx.AsyncClient(timeout=20) as client,
        aclosing(RegistryClient(REGISTRY)) as registry,
    ):
        async with phase("real HTTPS service readiness"):
            for address, expected in (
                (REGISTRY + "/health", 200),
                (SITE + "/health", 200),
                (AUDIENCE + "/", 404),
            ):
                deadline, last_error = time.monotonic() + 90, "not attempted"
                while True:
                    try:
                        response = await client.get(address)
                        if response.status_code == expected:
                            break
                        last_error = f"HTTP {response.status_code}, expected {expected}"
                    except httpx.TransportError as error:
                        last_error = f"{type(error).__name__}: {error}"
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            f"service readiness deadline for {address}: {last_error}"
                        )
                    await asyncio.sleep(1)
        async with phase(
            "controller custody and authoritative DNS through holder command"
        ):
            descriptor = await holder_cli("descriptor")
            public_file(Path("/public/adcl6.test.zone"), zone(descriptor["did_key"]))
            deadline = time.monotonic() + 30
            while True:
                try:
                    records = await dns.asyncresolver.resolve(
                        "_awid." + ORG + ".", "TXT"
                    )
                    values = [b"".join(record.strings).decode() for record in records]
                    if values == [
                        "awid=v1; controller="
                        + descriptor["did_key"]
                        + "; registry="
                        + REGISTRY
                        + ";"
                    ]:
                        break
                except dns.exception.DNSException:
                    pass
                if time.monotonic() >= deadline:
                    raise RuntimeError("authoritative DNS publication not observed")
                await asyncio.sleep(1)
            await holder_cli(
                "registry",
                value={
                    "operation": "namespace_register",
                    "domain": ORG,
                    "controller_did": descriptor["did_key"],
                },
            )
            save(work / "controller-public.json", descriptor)

        async def person(name):
            home = work / "identities" / name
            created = await human_command(
                home, ["id", "human", "init", "--domain", ORG, "--json"]
            )
            assert created["status"] == "prepared"
            return Person(name, created["did_key"], created["id"], home)

        async def outside(subject, profile):
            text = work / (subject.name + "-message.txt")
            text.write_text("Public human identity proof from aw")
            name = subject.name + "-" + profile + ".json"
            exported = work / "public" / name
            await subject.aw(
                "id",
                "proof",
                "--message-file",
                str(text),
                "--out",
                str(exported),
                json_output=False,
            )
            document = json.loads(exported.read_text())
            signed = json.loads(document["signed_payload"])
            assert (
                signed["from_stable_id"] == subject.identity
                and signed["from_did"] == subject.key
            )
            assert signed["from"] == "", "proof_fabricated_an_address"
            if profile == "none":
                assert "evidence" not in document, "unenrolled_sender_gained_evidence"
            else:
                (entry,) = document["evidence"]["links"]
                body = entry["statement"]["evidence"]
                if profile == "later":
                    assert (
                        body["kind"] == "human_enrolled_later"
                        and "creation" not in body
                    )
                else:
                    assert body["kind"] == "human" and "creation" in body
                confirmation = parse(decode(entry["receipt"]["request_bytes"]))
                assert confirmation["purpose"] == "enrollment_confirmation"
                assert confirmation["approver"] == subject.identity
            # The first invocation is deliberately plain: no --registry, --json,
            # identity, inherited config or credential. JSON is a second projection.
            # This fixture's registry resolves to a private Docker address. Name
            # that operator-selected origin explicitly through the normal private
            # registry setting; DNS still selects/checks its authority. Production
            # public DNS registries need no such transport allowance.
            script = (
                "export HOME=/tmp/outsider SSL_CERT_FILE=/public/ca.crt; "
                "mkdir /tmp/empty; cd /tmp/empty; "
                + "aw verify /exports/"
                + name
                + " >/tmp/plain; "
                + "aw --json verify /exports/"
                + name
                + " >/tmp/result; "
                + 'test ! -e "$HOME"; test ! -e .aw; '
                + 'python -c \'import json,pathlib; print(json.dumps({"plain":pathlib.Path("/tmp/plain").read_text(),"result":json.loads(pathlib.Path("/tmp/result").read_text())}))\''
            )
            raw = await command(
                "docker",
                "run",
                "--rm",
                "--label",
                "com.docker.compose.project=" + os.environ["PROJECT"],
                "--network",
                os.environ["PROJECT"] + "_default",
                "--dns",
                DNS,
                "--read-only",
                "--env",
                "AWID_REGISTRY_URL=" + REGISTRY,
                "--tmpfs",
                "/tmp",
                "--mount",
                "type=bind,src="
                + os.environ["HOST_WORK"]
                + "/public,dst=/exports,readonly",
                "--mount",
                "type=bind,src="
                + os.environ["HOST_PUBLIC"]
                + "/ca.crt,dst=/public/ca.crt,readonly",
                os.environ["IMAGE"],
                "sh",
                "-ec",
                script,
            )
            result = json.loads(raw)
            assert_outside_verdict(result["result"], subject.identity, profile)
            plain = result["plain"]
            if profile == "none":
                assert (
                    "no evidence" in plain
                    and "created with" not in plain
                    and "can approve since" not in plain
                )
                output = subject.name + "-no-evidence-outside.json"
            elif profile == "later":
                assert "can approve since" in plain and "(issuer's statement)" in plain
                assert (
                    "confirmation proof checked" in plain
                    and "created with" not in plain
                    and "creation proof" not in plain
                )
                output = subject.name + "-outside.json"
            else:
                assert (
                    "created with a passkey and user verification; proof checked"
                    in plain
                )
                output = subject.name + "-outside.json"
            save(work / output, result["result"])
            public_file(
                work / "public" / (subject.name + "-" + profile + "-plain.txt"), plain
            )

        async def enroll(subject, actor, intent=None):
            args = ["id", "human", "enroll", "--issuer", AUDIENCE, "--json"]
            if intent is not None:
                path = work / (subject.name + "-intent.json")
                save(path, intent)
                args += ["--intent", str(path)]
                assert intent["intent"]["requester"] == {
                    "kind": "identity",
                    "id": subject.identity,
                    "key": subject.key,
                }
            result = await subject.aw(*args, actor=actor)
            assert (
                result["statement"]["status"] == "valid"
                and result["proof"]["status"] == "valid"
            )
            session = json.loads(
                (subject.record_dir / "enrollment-session.json").read_text()
            )
            assert session["completed"] is True
            subject.activation = session["activation"]
            save(work / (subject.name + "-activation.json"), subject.activation)
            await actor.login(subject.identity)

        async with browsers() as (first_browser, second_browser):
            first, second = await person("first"), await person("second")
            async with phase(
                "operator issues without approval configuration; aw registers own certificate"
            ):
                issued = await holder_cli(
                    "issue-person", first.identity, None, "--identity-key", first.key
                )
                assert (
                    issued["state"] == "issued" and issued["identity_key"] == first.key
                )
                path = work / "first-issued.json"
                save(path, issued)
                result = await first.aw("id", "human", "register", str(path), "--json")
                assert (
                    result["status"] == "registered" and result["id"] == first.identity
                )
            async with phase(
                "plain outsider aw verify reports valid human with no evidence"
            ):
                await outside(first, "none")
            async with phase(
                "same holder enables approval; existing person enrolls later through aw"
            ):
                await enable_holder_approval()
                deadline = time.monotonic() + 60
                while True:
                    try:
                        response = await client.get(AUDIENCE + "/")
                        if response.status_code == 404:
                            break
                    except httpx.TransportError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("configured holder readiness deadline")
                    await asyncio.sleep(1)
                await enroll(first, first_browser)
                assert (
                    first.activation["evidence"]["evidence"]["kind"]
                    == "human_enrolled_later"
                )
            async with phase(
                "plain outsider aw verify reports later approval evidence without creation"
            ):
                await outside(first, "later")
            async with phase(
                "aw human add carries exact second-person approval through Chromium"
            ):
                intent_path = work / "second-pending-intent.json"
                approval_ready = asyncio.Event()
                pending = asyncio.create_task(
                    first.aw(
                        "id",
                        "human",
                        "add",
                        "--person",
                        second.identity,
                        "--identity-key",
                        second.key,
                        "--out",
                        str(intent_path),
                        json_output=False,
                        approval_ready=approval_ready,
                    )
                )
                try:
                    deadline = time.monotonic() + 90
                    while True:
                        records = list(first.record_dir.glob("human-add-*.json"))
                        if records:
                            assert len(records) == 1
                            retained = json.loads(records[0].read_text())
                            if "request_bytes" in retained:
                                break
                        if pending.done():
                            await pending
                            raise RuntimeError(
                                "typed add returned before retaining approval"
                            )
                        if time.monotonic() >= deadline:
                            raise RuntimeError("typed add did not retain needs-human")
                        await asyncio.sleep(0.1)
                    original = retained["request_bytes"]
                    save(work / "approval-record.json", retained)
                    request = parse(decode(original))
                    assert_approval_target(request, first.identity, second.identity)
                    try:
                        current = await registry.resolve_key_fresh(second.identity)
                    except DIDKeyNotFoundError as missing:
                        enrollment = missing.id_tree
                    else:
                        enrollment = current.id_tree
                    assert enrollment is not None and not enrollment.enrolled, (
                        "human_issued_before_approval"
                    )
                    # R is retained before submission. Wait for aw's actual
                    # successful submit/poll before login snapshots the UI list.
                    ready = asyncio.create_task(approval_ready.wait())
                    try:
                        done, _ = await asyncio.wait(
                            (ready, pending),
                            timeout=90,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        if pending in done:
                            await pending
                        assert ready in done, "requester_did_not_reach_approval_wait"
                    finally:
                        if not ready.done():
                            ready.cancel()
                            await asyncio.gather(ready, return_exceptions=True)
                    await first_browser.login(first.identity)
                    _, needs = make_needs_human(request, origin=SITE)
                    await first_browser.approve(
                        needs["digest"], first.identity, second.identity
                    )
                    await pending
                    retained = json.loads(records[0].read_text())
                    assert (
                        retained["request_bytes"]
                        == original
                        == retained["receipt"]["request_bytes"]
                    )
                    save(work / "approval-record.json", retained)
                    intent = json.loads(intent_path.read_text())["intent"]
                    assert intent["intent"]["person"] == second.identity
                finally:
                    if not pending.done():
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
            async with phase(
                "new person enrolls and registers own certificate through aw"
            ):
                await enroll(second, second_browser, intent)
                assert second.activation["evidence"]["evidence"]["kind"] == "human"
                assert "creation" not in first.activation["evidence"]["evidence"]
            async with phase(
                "plain outsider aw verify checks creation statement and proof"
            ):
                await outside(second, "creation")
            async with phase(
                "deployment section removed: human add/register succeed with awsign stopped"
            ):
                await deployment_policy(None)
                names = (
                    (
                        await command(
                            "docker",
                            "ps",
                            "--all",
                            "--quiet",
                            "--filter",
                            "label=com.docker.compose.project=" + os.environ["PROJECT"],
                            "--filter",
                            "label=com.docker.compose.service=approval",
                        )
                    )
                    .decode()
                    .split()
                )
                assert len(names) == 1, "owned_approval_service_not_unique"
                await command("docker", "stop", "--time", "10", names[0])
                try:
                    response = await client.get(SITE + "/health")
                except httpx.TransportError:
                    pass
                else:
                    assert response.status_code != 200, (
                        "approval_service_still_reachable"
                    )
                third = await person("third-unconfigured")
                issued_path = work / "third-issued.json"
                await first.aw(
                    "id",
                    "human",
                    "add",
                    "--issuer",
                    AUDIENCE,
                    "--person",
                    third.identity,
                    "--identity-key",
                    third.key,
                    "--out",
                    str(issued_path),
                    json_output=False,
                )
                issued = json.loads(issued_path.read_text())
                assert issued["state"] == "issued" and "intent" not in issued
                result = await third.aw(
                    "id", "human", "register", str(issued_path), "--json"
                )
                assert (
                    result["status"] == "registered" and result["id"] == third.identity
                )
                assert not (third.record_dir / "approval-binding.json").exists()
                await outside(third, "none")
        report["completed"] = True
        save(work / "journey.json", report)
        print("PASS: adcl6 first self-custody add-human journey completed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    prep = modes.add_parser("prepare")
    prep.add_argument("--runtime", required=True, type=Path)
    prep.add_argument("--project", required=True)
    prep.add_argument("--approval-archive", required=True, type=Path)
    prep.add_argument("--architecture", choices=("amd64", "arm64"), default="amd64")
    modes.add_parser("driver")
    retention = modes.add_parser("retain")
    retention.add_argument("--uid", required=True, type=int)
    retention.add_argument("--gid", required=True, type=int)
    check = modes.add_parser("check-saved-export")
    check.add_argument("--probe", required=True, type=Path)
    check.add_argument("--original-export", required=True, type=Path)
    check.add_argument("--original-verdict", required=True, type=Path)
    check.add_argument("--export", required=True, type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args)
    elif args.mode == "retain":
        retain(args)
    elif args.mode == "check-saved-export":
        raw = subprocess.check_output(
            [
                str(args.probe),
                str(args.original_export),
                str(args.original_verdict),
                str(args.export),
            ]
        )
        print(raw.decode().strip(), flush=True)
        assert_outside_verdict(
            json.loads(raw), json.loads(args.original_verdict.read_text())["id"]
        )
    else:
        try:
            asyncio.run(driver())
        except BaseException as error:
            path = Path("/work/journey.json")
            if path.exists():
                report = json.loads(path.read_text())
                report.update(completed=False, fatal_error=type(error).__name__)
                save(path, report)
            raise


if __name__ == "__main__":
    main()
