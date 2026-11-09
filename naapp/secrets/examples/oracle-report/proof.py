"""Lab-only consumer of the existing HPKE/RunnerConfig/execute_oci interfaces."""

import asyncio
import hashlib
import json
import secrets
import shutil
import sys
import time
from pathlib import Path

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import CredentialInput, RunnerConfig
from aweb_secrets_runner.oci_execution import execute_oci
from aweb_secrets_runner.protocol import encode64
from aweb_secrets_values import encode_value
from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


async def run():
    # Only the trusted lab driver sends this private pipe. No values go to argv,
    # image layers, daemon environment or persistent runner/config state.
    incoming = json.loads(sys.stdin.buffer.read(16384))
    root = Path("/memory/proof")
    root.mkdir(mode=0o700)
    images = root / "images"
    shutil.copytree("/oci-source", images)
    workspace = root / "workspace"
    workspace.mkdir(mode=0o700)
    document = json.loads(Path("/pins/runner-config.json").read_bytes())
    document["agent_uids"] = [incoming["agent_uid"]]
    runtime = {"kind": "runc", "images": str(images), "workspace": str(workspace)}
    for name, executable in (
        ("engine", shutil.which("runc")),
        ("unpacker", shutil.which("umoci")),
        ("supervisor", sys.executable),
    ):
        path = Path(executable)
        runtime[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    document["runtime"] = runtime
    path = root / "runner-config.json"
    path.write_text(json.dumps(document))
    path.chmod(0o600)
    config = RunnerConfig.load(path)
    job = document["jobs"]["oracle-weekly-quality"]
    definition = job["definition"]
    key = X25519PrivateKey.generate()
    dispatch = "dsp_" + secrets.token_urlsafe(16)
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    sealed = suite.encrypt(
        encode_value("basic", {"username": "LAB_REPORT", "password": incoming["password"]}),
        key.public_key(),
        dispatch.encode(),
    )
    credentials = [CredentialInput("oracle-lab-report", encode64(sealed), key, dispatch)]
    report = await execute_oci(
        config.runtime(),
        config,
        job_id="oracle-weekly-quality",
        digest=job["digest"],
        runner_id=definition["runner_ids"][0],
        params=incoming["params"],
        credentials=credentials,
        expires_at=time.time() + 120,
    )
    if incoming["password"] in json.dumps(report):
        raise RuntimeError("private value escaped report")
    if list(workspace.iterdir()):
        raise RuntimeError("OCI workspace was not cleaned")
    print(json.dumps(report))


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except Refused as refused:
        if refused.code == "params_invalid":
            print(json.dumps({"refused": "params_invalid"}))
        else:
            print("oracle OCI proof failed", file=sys.stderr)
            raise SystemExit(1) from None
    except Exception:
        # No input, credential, driver message or transient bundle is evidence.
        print("oracle OCI proof failed", file=sys.stderr)
        raise SystemExit(1) from None
