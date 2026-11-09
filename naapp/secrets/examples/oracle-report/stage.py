"""Stage the one reviewed lab artifact; rebuilding never silently changes its pin."""

import hashlib
import json
import subprocess
import tarfile
from pathlib import Path


def stage():
    root = Path(__file__).resolve().parent
    lock = json.loads((root / "image-lock.json").read_bytes())
    job = json.loads((root / "job.json").read_bytes())
    config = json.loads((root / "runner-config.json").read_bytes())
    if config["jobs"][job["job_id"]]["definition"] != job:
        raise ValueError("service/local job definition mismatch")
    if job["oci"]["image"] != lock["image"]:
        raise ValueError("job/image pin mismatch")
    for name, digest in lock["source_sha256"].items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError("image source changed; rebuild and review its new pin")
    archive = root / ".artifacts/report.oci.tar"
    if hashlib.sha256(archive.read_bytes()).hexdigest() != lock["archive_sha256"]:
        raise ValueError("archive pin mismatch")
    with tarfile.open(archive) as source:
        source.extractall(root / ".artifacts/layout", filter="data")
    index = json.loads((root / ".artifacts/layout/index.json").read_bytes())
    if [entry["digest"] for entry in index["manifests"]] != [lock["image"].split("@", 1)[1]]:
        raise ValueError("OCI manifest pin mismatch")
    subprocess.run(["docker", "load", "--input", str(archive)], check=True)


if __name__ == "__main__":
    stage()
