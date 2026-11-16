#!/usr/bin/env python3
"""One real self-custody add-human journey. Invoked by e2e-adcl6-first-path.sh.

The prepare command only stages a concrete Compose fixture. The driver uses the
actual installed service/holder/SDK, aw requester, and Chromium ceremonies.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import aclosing, asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import tomllib
from urllib.parse import quote
from uuid import uuid4

AW = "962c94dd747f6adff2ee7f9c7d1f69bea3b6da0f"
HOLDER = "0ba1350347d57bfe3fc93aeba5fa6261f48937e1"
APPROVAL = "2f041129ab21147fd2d452a679bf629279e92642"
ORG = "org.adcl6.test"
REGISTRY = "https://awid.adcl6.test"
SITE = "https://approval.adcl6.test"
AUDIENCE = "https://holder.adcl6.test"
RP = "approval.adcl6.test"
DNS = "172.29.190.53"
NETWORK = "172.29.190.0/24"


def save(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
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


def prepare(args) -> None:
    runtime = args.runtime.resolve()
    build = runtime / "build"
    build.mkdir(mode=0o700)
    extract(args.approval_archive, APPROVAL, build / "approval")
    extract(args.holder_archive, HOLDER, build / "holder", ("awid/", "key-holder/"))
    # The only aw-side additions are the journey files; product Go bytes must
    # remain exactly those ACKed at the composition's requested aw revision.
    root = Path(__file__).resolve().parents[1]
    trees = [
        subprocess.check_output(
            ["git", "rev-parse", f"{revision}:cli/go"], cwd=root, text=True
        ).strip()
        for revision in (AW, "HEAD")
    ]
    if trees[0] != trees[1]:
        raise RuntimeError("aw Go tree differs from the requested 962c94dd74 input")
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD", "--", "cli/go"], cwd=root, check=True
    )
    env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0")
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
        cwd=root / "cli/go",
        env=env,
        check=True,
    )
    (build / "journey.py").write_bytes(Path(__file__).read_bytes())
    (build / "Dockerfile").write_bytes(
        (root / "scripts/adcl6-first-path.Dockerfile").read_bytes()
    )
    runner_lock = tomllib.loads((root / "naapp-lib/uv.lock").read_text())
    runner = []
    for package in runner_lock["package"]:
        if package["name"] in {"playwright", "pyee", "greenlet"}:
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
    if len(runner) != 3:
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
  file /zones/adcl6.test.zone adcl6.test { reload 1s }
}
.:53 { forward . 127.0.0.11 }
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
    }
    holder_flags = (
        "--state /state/private --registry-origin "
        + REGISTRY
        + " --origin "
        + AUDIENCE
        + " --approval-origin "
        + SITE
        + " --rp-id "
        + RP
        + " --grading passkey_only"
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
    }
    services["https"] = {
        "image": "nginx:1.27-alpine",
        "volumes": [
            str(runtime / "public/nginx.conf") + ":/etc/nginx/nginx.conf:ro",
            str(runtime / "tls") + ":/tls:ro",
        ],
        "networks": {"default": {"ipv4_address": "172.29.190.10"}},
        "depends_on": ["awid", "approval", "holder"],
    }
    services["driver"] = {
        **common,
        "command": ["python", "/journey.py", "driver"],
        "environment": {
            **common["environment"],
            "HOME": "/work/browser-home",
            "PROJECT": args.project,
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
            "aw": AW,
            "aw_go_tree": trees[0],
            "aw_build_flags": ["-trimpath", "-buildvcs=false"],
            "go_version": subprocess.check_output(["go", "version"], text=True).strip(),
            "holder_and_awid": HOLDER,
            "approval": APPROVAL,
            "aw_binary_sha256": hashlib.sha256((build / "aw").read_bytes()).hexdigest(),
            "approval_archive_sha256": hashlib.sha256(
                args.approval_archive.read_bytes()
            ).hexdigest(),
            "holder_archive_sha256": hashlib.sha256(
                args.holder_archive.read_bytes()
            ).hexdigest(),
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


async def holder_cli(operation, person=None, value=None, *extra):
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
        "--approval-origin",
        SITE,
        "--rp-id",
        RP,
        "--grading",
        "passkey_only",
        operation,
    ]
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
    seed: bytes
    key: str
    identity: str
    home: Path
    activation: dict | None = None


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

        row = self.page.locator("#requests article").filter(
            has=self.page.get_by_text(digest, exact=True)
        )
        await expect(row).to_have_count(1)
        for text in (first, second, ORG, AUDIENCE, "human.add"):
            await expect(row).to_contain_text(text)
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
    from awid.did import generate_keypair, did_from_public_key, stable_id_from_did_key
    from awid.id_certificates import encode_id_chain_header, id_certificate_id
    from awid.registry import RegistryClient
    from awid.signing import sign_message, canonical_payload
    from approval_service.answers import read_answer, assemble_receipt
    from approval_service.canonical import canonical, parse
    from approval_service.encoding import decode
    from approval_service.seams import http_authorization, make_needs_human, check_http

    work = Path("/work")
    report = {
        "completed": False,
        "phases": [],
        "aw": AW,
        "holder_and_awid": HOLDER,
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
            for url, expected in (
                (REGISTRY + "/health", 200),
                (SITE + "/health", 200),
                (AUDIENCE + "/", 404),
            ):
                deadline = time.monotonic() + 120
                while True:
                    try:
                        response = await client.get(url)
                        if response.status_code == expected:
                            break
                    except httpx.TransportError:
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError("service readiness deadline")
                    await asyncio.sleep(1)
        async with phase("controller custody and authoritative DNS"):
            descriptor = json.loads(
                await command(
                    "docker",
                    "exec",
                    os.environ["HOLDER_CONTAINER"],
                    "aweb-key-holder",
                    "--state",
                    "/state/private",
                    "descriptor",
                )
            )
            root_key = descriptor["did_key"]
            public_file(Path("/public/adcl6.test.zone"), zone(root_key))
            deadline = time.monotonic() + 30
            while True:
                try:
                    records = await dns.asyncresolver.resolve(
                        "_awid." + ORG + ".", "TXT"
                    )
                    values = [b"".join(record.strings).decode() for record in records]
                    if values == [
                        "awid=v1; controller="
                        + root_key
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
                    "controller_did": root_key,
                },
            )
            save(work / "controller-public.json", descriptor)

        async def person(name):
            seed, public = generate_keypair()
            key = did_from_public_key(public)
            identity = stable_id_from_did_key(key)
            await registry.register_did(key, seed)
            home = work / "identities" / name / ".aw"
            home.mkdir(parents=True, mode=0o700)
            (home / "signing.key").write_text(
                "-----BEGIN ED25519 PRIVATE KEY-----\n"
                + base64.b64encode(seed).decode()
                + "\n-----END ED25519 PRIVATE KEY-----\n"
            )
            (home / "signing.key").chmod(0o600)
            save(
                home / "identity.yaml",
                {
                    "schema_version": 2,
                    "did": key,
                    "stable_id": identity,
                    "address": ORG + "/" + name,
                    "custody": "self",
                    "identity_scope": "global",
                    "registry_url": REGISTRY,
                    "registry_status": "registered",
                    "created_at": datetime.now(UTC).isoformat(),
                },
            )
            return Person(name, seed, key, identity, home)

        async def exchange(purpose, body, intent, caller):
            requester = intent["intent"]["requester"]
            raw = canonical(body)
            issued = int(time.time())
            if caller is None:
                auth = (
                    await holder_cli(
                        "authorize",
                        intent["intent"]["person"],
                        body,
                        "--purpose",
                        purpose,
                        "--issued-at",
                        str(issued),
                    )
                )["authorization"]
            else:
                auth = http_authorization(
                    raw,
                    seed=caller.seed,
                    requester=requester,
                    origin=SITE,
                    purpose=purpose,
                    issued_at=issued,
                )
            path = "/v1/enrollments/" + purpose.removeprefix("enrollment_")
            check_http(
                auth,
                raw,
                requester=requester,
                origin=SITE,
                method="POST",
                path=path,
                purpose=purpose,
                now=issued,
            )
            response = await client.post(
                SITE + path,
                content=raw,
                headers={"Authorization": auth, "Content-Type": "application/json"},
            )
            request_bytes = (
                decode(body["request_bytes"])
                if purpose == "enrollment_confirm"
                else None
            )
            return read_answer(
                purpose,
                response.json(),
                status=response.status_code,
                intent=intent,
                request_bytes=request_bytes,
            )

        async def enforcer(caller, path, body, *, approvals=False):
            body_path = work / ("request-" + uuid4().hex + ".json")
            save(body_path, body)
            env = {
                **os.environ,
                "AWEB_IDENTITY_HOME": str(caller.home),
                "HOME": str(caller.home.parent),
            }
            chain = {
                "v": 1,
                "type": "aweb.id-chain",
                "certificates": caller.activation["id_chain"],
            }
            args = [
                "aw",
                "id",
                "request",
                "POST",
                AUDIENCE + path,
                "--body-file",
                str(body_path),
                "--header",
                "X-AWID-ID-Chain: " + encode_id_chain_header(chain),
                "--json",
            ]
            if approvals:
                requester_path, admission_path = (
                    work / "requester.json",
                    work / "admission.json",
                )
                save(
                    requester_path,
                    {"kind": "identity", "id": caller.identity, "key": caller.key},
                )
                save(
                    admission_path,
                    {
                        "team_certificate": None,
                        "id_chain": caller.activation["id_chain"],
                    },
                )
                args += [
                    "--approval-origin",
                    SITE,
                    "--approval-requester",
                    str(requester_path),
                    "--approval-admission",
                    str(admission_path),
                    "--approval-record",
                    str(work / "approval-record.json"),
                ]
            result = json.loads(
                await command(*args, env=env, cwd=caller.home.parent, timeout=180)
            )
            assert result["status"] == 200, result["status"]
            return result["body"]

        async def outside(subject):
            activation = subject.activation
            receipt = activation["creation_receipt"]
            creation_request = parse(decode(receipt["request_bytes"]))
            assert creation_request["purpose"] == "enrollment_confirmation"
            assert creation_request["approver"] == subject.identity
            assert (
                activation["evidence"]["evidence"]["creation"]["credential"]
                == receipt["assertion"]["id"]
            )
            envelope = {
                "from": ORG + "/" + subject.name,
                "from_did": subject.key,
                "from_stable_id": subject.identity,
                "to": "public-proof-reader",
                "to_did": subject.key,
                "type": "mail",
                "subject": "adcl6 public identity proof",
                "body": "Public creation evidence",
                "timestamp": datetime.now(UTC).isoformat(),
                "message_id": str(uuid4()),
            }
            raw = canonical_payload(envelope)
            export = {
                "v": 1,
                "type": "aweb.message-envelope",
                "signed_payload": raw.decode(),
                "signature": sign_message(subject.seed, raw),
                "signing_key_id": subject.key,
                "id_chain": {
                    "v": 1,
                    "type": "aweb.id-chain",
                    "certificates": activation["id_chain"],
                },
                "evidence": {
                    "v": 1,
                    "links": [
                        {
                            "certificate": id_certificate_id(
                                activation["id_chain"][-1]["certificate"]
                            ),
                            "statement": activation["evidence"],
                            "receipt": receipt,
                        }
                    ],
                },
            }
            save(work / "public" / (subject.name + ".json"), export)
            script = (
                "mkdir -p /tmp/fresh-home /tmp/fresh-cwd; cd /tmp/fresh-cwd; env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp/fresh-home TMPDIR=/tmp SSL_CERT_FILE=/public/ca.crt aw verify --registry "
                + REGISTRY
                + " --json /exports/"
                + subject.name
                + '.json; test -z "$(ls -A /tmp/fresh-home)"; test ! -e .aw'
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
            assert (
                result["identity_valid"] is True
                and result["human_id"] == subject.identity
                and result["kind"] == "human"
            )
            (evidence,) = result["evidence"]
            assert (
                evidence["statement"]["status"]
                == evidence["proof"]["status"]
                == "valid"
            )
            assert (
                evidence["issuer_authenticated_grade"] == "passkey_uv"
                and evidence["proof_binds_grade"] is True
            )
            assert (
                evidence["currentness"] == "current"
                and evidence["continuity"] == "unbroken"
            )
            save(work / (subject.name + "-outside.json"), result)

        async def enroll(subject, intent, actor, caller):
            empty = {"team_certificate": None, "id_chain": []}
            admission = (
                empty
                if caller is None
                else {
                    "team_certificate": None,
                    "id_chain": caller.activation["id_chain"],
                }
            )
            base = {"version": 1, "intent": intent, "admission": admission}
            started = await exchange("enrollment_start", base, intent, caller)
            await actor.register(started["locator"])
            material = await exchange("enrollment_material", base, intent, caller)
            assert len(material["registrations"]) == 1
            if caller is None:
                prepared = await holder_cli(
                    "bind", subject.identity, material, "--registration-count", "1"
                )
            else:
                prepared = await enforcer(
                    caller,
                    "/v1/enrollments/" + subject.identity + "/binding",
                    {"material": material, "registration_count": 1},
                )
            confirm = {
                **base,
                "binding": prepared["binding"],
                "request_bytes": prepared["request_bytes"],
            }
            pending = await exchange("enrollment_confirm", confirm, intent, caller)
            assert pending["state"] == "pending"
            await actor.confirm()
            deadline = parse(decode(prepared["request_bytes"]))["deadline"]
            while True:
                answer = await exchange("enrollment_confirm", confirm, intent, caller)
                if answer["state"] != "pending":
                    break
                if time.time() >= deadline:
                    raise RuntimeError("original enrollment deadline reached")
                await asyncio.sleep(1)
            receipt = assemble_receipt(
                decode(prepared["request_bytes"]),
                answer,
                locator=started["locator"],
                intent=intent,
            )
            if caller is None:
                activation = await holder_cli("finish", subject.identity, receipt)
            else:
                activation = await enforcer(
                    caller, "/v1/enrollments/" + subject.identity + "/finish", receipt
                )
            await registry.register_id_certificate(
                {
                    "v": 1,
                    "type": "aweb.id-chain",
                    "certificates": activation["id_chain"],
                },
                signer=lambda payload: (
                    subject.key,
                    base64.b64decode(sign_message(subject.seed, payload) + "=="),
                ),
                expected_head=None,
                invitation_id=None,
            )
            result = await exchange("enrollment_activate", activation, intent, caller)
            assert result["state"] == "active"
            activated = (
                await holder_cli("activate", subject.identity)
                if caller is None
                else await enforcer(
                    caller, "/v1/enrollments/" + subject.identity + "/activate", {}
                )
            )
            assert activated["state"] == "active"
            subject.activation = activation
            save(work / (subject.name + "-activation.json"), activation)
            await actor.login(subject.identity)

        async with browsers() as (first_browser, second_browser):
            first, second = await person("first"), await person("second")
            async with phase(
                "controller bootstraps first person and browser enrollment"
            ):
                intent = (
                    await holder_cli(
                        "bootstrap", first.identity, None, "--identity-key", first.key
                    )
                )["intent"]
                await enroll(first, intent, first_browser, None)
            async with phase("first person outside verification"):
                await outside(first)
            async with phase(
                "first person approves exact second-person request in Chromium"
            ):
                pending = asyncio.create_task(
                    enforcer(
                        first,
                        "/v1/humans",
                        {
                            "person": second.identity,
                            "identity_key": second.key,
                            "approver": first.identity,
                        },
                        approvals=True,
                    )
                )
                try:
                    deadline = time.monotonic() + 60
                    while not (work / "approval-record.json").exists():
                        if pending.done():
                            await pending
                            raise RuntimeError("request returned without retaining R")
                        if time.monotonic() >= deadline:
                            raise RuntimeError("requester did not reach needs-human")
                        await asyncio.sleep(0.1)
                    original = json.loads((work / "approval-record.json").read_text())[
                        "request_bytes"
                    ]
                    request = parse(decode(original))
                    assert (
                        request["approver"] == first.identity
                        and request["act"]["target"]["person"] == second.identity
                    )
                    assert not (
                        await registry.resolve_key_fresh(second.identity)
                    ).id_tree.enrolled
                    # The page fetches pending rows after login; no invented UI poll.
                    await first_browser.login(first.identity)
                    _, needs = make_needs_human(request, origin=SITE)
                    await first_browser.approve(
                        needs["digest"], first.identity, second.identity
                    )
                    intent = (await pending)["intent"]
                    retained = json.loads((work / "approval-record.json").read_text())
                    assert (
                        retained["request_bytes"]
                        == original
                        == retained["receipt"]["request_bytes"]
                    )
                    assert intent["intent"]["person"] == second.identity
                finally:
                    if not pending.done():
                        pending.cancel()
                        await asyncio.gather(pending, return_exceptions=True)
            async with phase(
                "second person browser enrollment and committed activation"
            ):
                await enroll(second, intent, second_browser, first)
                assert (
                    first.activation["creation_receipt"]["assertion"]["id"]
                    != second.activation["creation_receipt"]["assertion"]["id"]
                )
            async with phase("second person outside verification"):
                await outside(second)
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
    prep.add_argument("--holder-archive", required=True, type=Path)
    modes.add_parser("driver")
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args)
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
