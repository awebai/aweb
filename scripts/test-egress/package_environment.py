#!/usr/bin/env python3
"""Prepare a source-owned test image and run its packaged callers on a gate VM.

The ordinary isolated runner stays socket-free. This entry serves package callers
that own Compose stacks and need the ephemeral VM's loopback and Docker socket.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import uuid
from pathlib import Path

FORWARDED = (
    "AWEB_TEST_SERVICES",
    "TEST_DB_HOST",
    "TEST_DB_PORT",
    "TEST_DB_USER",
    "TEST_DB_PASSWORD",
    "PGHOST",
    "PGPORT",
    "PGUSER",
    "PGPASSWORD",
    "PGDATABASE",
    "TEST_REDIS_URL",
    "REDIS_URL",
    "AWEB_REDIS_URL",
    "AWID_REDIS_URL",
    "NAAPP_REQUIRE_TEST_DATABASE",
    "NAAPP_E2E_PROJECT",
    "NAAPP_E2E_HOST",
    "NAAPP_E2E_POSTGRES_PORT",
    "NAAPP_E2E_AWID_PORT",
    "NAAPP_E2E_API_PORT",
    "NAAPP_E2E_CONTAINER_NETWORK",
    "NAAPP_E2E_CONTAINER_HOST",
)


def source_binding(root, sha, projects):
    from prepare_projects import selected_projects

    if (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=root, text=True
        ).strip()
        != sha
    ):
        raise RuntimeError("PACKAGE_SOURCE_MISMATCH")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=root, text=True):
        raise RuntimeError("PACKAGE_SOURCE_DIRTY")
    selected = selected_projects(root, projects)
    return {
        "source": sha,
        "locks": {
            str(lock.relative_to(root)): hashlib.sha256(lock.read_bytes()).hexdigest()
            for _, lock in selected
        },
        "projects": list(dict.fromkeys(projects)),
    }


def prepare(root, sha, projects, evidence, binding):
    if evidence.resolve().is_relative_to(root) or binding.resolve().is_relative_to(
        root
    ):
        raise RuntimeError("PACKAGE_OUTPUT_IN_SOURCE")
    if binding.exists():
        raise RuntimeError("PACKAGE_BINDING_ALREADY_EXISTS")
    before = source_binding(root, sha, projects)
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location(
        "source_image_preparation", Path(__file__).with_name("package_image.py")
    )
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    image = "aw-package-" + uuid.uuid4().hex
    prepared = False
    try:
        owner.prepare_image(root, evidence, image, projects)
        image_id = subprocess.check_output(
            ["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True
        ).strip()
        verified = json.loads(
            subprocess.check_output(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--user",
                    "1000:1000",
                    image_id,
                    "cat",
                    "/home/test-runner/package-environment-verified.json",
                ],
                text=True,
            )
        )
        helper_readability = json.loads(
            subprocess.check_output(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--user",
                    "1000:1000",
                    image_id,
                    "cat",
                    "/home/test-runner/package-helper-readable.json",
                ],
                text=True,
            )
        )
        helper_hash = hashlib.sha256(
            Path(__file__).with_name("prepare_projects.py").read_bytes()
        ).hexdigest()
        if (
            helper_readability.get("status") != "PASS"
            or helper_readability.get("uid") != 1000
            or helper_readability.get("gid") != 1000
            or helper_readability.get("mode") != "0644"
            or helper_readability.get("sha256") != helper_hash
            or not helper_readability.get("parents")
            or not all(
                row.get("traversable") for row in helper_readability["parents"].values()
            )
        ):
            raise RuntimeError("PACKAGE_HELPER_READABILITY_INVALID")
        if (
            verified.get("status") != "PASS"
            or verified.get("uid") != 1000
            or verified.get("source") != sha
            or verified.get("locks") != before["locks"]
        ):
            raise RuntimeError("PACKAGE_PREPARATION_RECEIPT_INVALID")
        if source_binding(root, sha, projects) != before:
            raise RuntimeError("PACKAGE_SOURCE_CHANGED")
        binding.write_text(
            json.dumps(
                {
                    **before,
                    "image": image_id,
                    "tag": image,
                    "verified": verified,
                    "helper_readability": helper_readability,
                    "status": "PASS",
                },
                indent=2,
            )
            + "\n"
        )
        prepared = True
    finally:
        if not prepared:
            subprocess.run(["docker", "image", "rm", image], check=False)


# The OCI image is immutable; also retain the mutable test container's source
# read-back before it is removed. The original test exit remains visible.
COMMAND_RECEIPT = r"""
import hashlib,json,subprocess,sys
from pathlib import Path
expected=json.loads(sys.argv[1]); evidence=Path(sys.argv[2]); root=Path.cwd()
result=subprocess.run(sys.argv[3:],check=False)
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
status=subprocess.check_output(['git','status','--porcelain','--untracked-files=no'],text=True)
locks={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in expected['locks']}
unchanged=sha==expected['source'] and not status and locks==expected['locks']
(evidence/'source-after.json').write_text(json.dumps(dict(source=sha,tracked_status=status,locks=locks,source_unchanged=unchanged,test_exit=result.returncode),indent=2)+'\n')
raise SystemExit(result.returncode if unchanged else 78)
"""


def runner_args(receipt, evidence, name, command, junit):
    if receipt.get("status") != "PASS" or not receipt.get("image", "").startswith(
        "sha256:"
    ):
        raise RuntimeError("PACKAGE_ENVIRONMENT_NOT_PREPARED")
    args = [
        "docker",
        "run",
        "--rm",
        "--init",
        "--name",
        name,
        "--user",
        "1000:1000",
        "--group-add",
        str(Path("/var/run/docker.sock").stat().st_gid),
        "--network",
        "host",
        "--cpus",
        "4",
        "--memory",
        "8g",
        "--pids-limit",
        "2048",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        str(evidence) + ":/evidence",
        "-w",
        "/src",
    ]
    for key in FORWARDED:
        if key in os.environ:
            args += ["-e", key]
    label = os.environ.get("AC_CANDIDATE_RESOURCE_LABEL")
    if label:
        args += ["--label", "aweb.ac.candidate-gate=" + label]
    if junit:
        args += ["-e", "PYTEST_ADDOPTS=--junitxml=/evidence/cases.xml"]
    expected = {key: receipt[key] for key in ("source", "locks")}
    return [
        *args,
        receipt["image"],
        "python3",
        "-c",
        COMMAND_RECEIPT,
        json.dumps(expected),
        "/evidence",
        *command,
    ]


def run(binding, evidence, command, junit, expected_sha):
    receipt = json.loads(binding.read_text())
    if receipt.get("source") != expected_sha:
        raise RuntimeError("PACKAGE_BINDING_SOURCE_MISMATCH")
    evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    name = "aw-package-run-" + uuid.uuid4().hex
    args = runner_args(receipt, evidence, name, command, junit)
    try:
        with (evidence / "test.log").open("w") as log:
            result = subprocess.run(
                args, stdout=log, stderr=subprocess.STDOUT, check=False
            )
        (evidence / "result.json").write_text(
            json.dumps(
                {
                    "source": receipt["source"],
                    "image": receipt["image"],
                    "exit": result.returncode,
                    "context": "owned ephemeral VM Docker and loopback; not the isolated runner",
                },
                indent=2,
            )
            + "\n"
        )
        return result.returncode
    finally:
        subprocess.run(
            ["docker", "rm", "-f", "-v", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "run"))
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--project", action="append")
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--junit", action="store_true")
    parser.add_argument("--command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.mode == "prepare":
        if not args.source_root or not args.source_sha or not args.project:
            parser.error("prepare requires exact source root/SHA and selected projects")
        prepare(
            args.source_root.resolve(),
            args.source_sha,
            args.project,
            args.evidence.resolve(),
            args.binding,
        )
    else:
        if not args.command or not args.source_sha:
            parser.error("run requires the package command and exact source SHA")
        raise SystemExit(
            run(
                args.binding,
                args.evidence.resolve(),
                args.command,
                args.junit,
                args.source_sha,
            )
        )
