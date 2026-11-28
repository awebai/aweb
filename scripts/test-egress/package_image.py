"""One source-owned image build for isolated suites and package callers."""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


HELPER_READABILITY_CHECK = """from pathlib import Path
import hashlib,json,os,stat
p=Path('/opt/package-environment.py')
data=p.read_bytes()
parents={str(parent):dict(mode=format(stat.S_IMODE(parent.stat().st_mode),'04o'),traversable=os.access(parent,os.X_OK)) for parent in p.parents}
mode=format(stat.S_IMODE(p.stat().st_mode),'04o')
assert os.getuid()==os.getgid()==1000 and mode=='0644' and all(row['traversable'] for row in parents.values())
receipt=dict(status='PASS',uid=os.getuid(),gid=os.getgid(),path=str(p),mode=mode,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),parents=parents)
Path('/home/test-runner/package-helper-readable.json').write_text(json.dumps(receipt,indent=2)+'\\n')
print(json.dumps(receipt))
"""


# Where the image build leaves its proof that UID 1000 could read the helper
# and then prepared and verified the projects.
RECEIPTS = {
    "helper": "/home/test-runner/package-helper-readable.json",
    "prepared": "/home/test-runner/package-environment-prepared.json",
    "verified": "/home/test-runner/package-environment-verified.json",
}


class PackageReceiptError(RuntimeError):
    """The built image does not prove the package preparation it claims."""


def uv_projects(root):
    return [
        str(Path(p).parent)
        for p in subprocess.check_output(
            ["git", "ls-files", "*uv.lock"], cwd=root, text=True
        ).splitlines()
    ]


def read_package_receipts(root, evidence, image):
    """Read back the build's receipts from the built image, and refuse unless
    each was written as UID and GID 1000 for this source and its own mode,
    and preparation and verification each covered exactly the projects the
    build selected, with their lock bytes.

    A build that prepared no projects wrote none. The copies are kept as
    evidence beside the build's other records.
    """
    projects = uv_projects(root)
    if not projects:
        return
    locks = {
        str(Path(project) / "uv.lock"): hashlib.sha256(
            (root / project / "uv.lock").read_bytes()
        ).hexdigest()
        for project in projects
    }
    digest_file = evidence / "package-preparation-tool.sha256"
    if not digest_file.is_file():
        raise PackageReceiptError(
            "the build prepared projects but recorded no helper digest"
        )
    helper_digest = digest_file.read_text().strip()
    source = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()
    for name, path in RECEIPTS.items():
        read = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "1000:1000",
                "--entrypoint",
                "cat",
                image,
                path,
            ],
            capture_output=True,
            text=True,
        )
        if read.returncode:
            raise PackageReceiptError(
                f"the {name} receipt {path} cannot be read from {image}: {read.stderr.strip()}"
            )
        (evidence / f"receipt-{name}.json").write_text(read.stdout)
        try:
            receipt = json.loads(read.stdout)
        except ValueError as exc:
            raise PackageReceiptError(
                f"the {name} receipt is not JSON: {exc}"
            ) from None
        if not isinstance(receipt, dict):
            raise PackageReceiptError(f"the {name} receipt is not a JSON object")
        expected = {"status": "PASS", "uid": 1000, "gid": 1000}
        if name == "helper":
            expected.update(mode="0644", sha256=helper_digest)
        else:
            expected.update(
                mode={"prepared": "prepare", "verified": "verify"}[name], source=source
            )
        for field, value in expected.items():
            if receipt.get(field) != value:
                raise PackageReceiptError(
                    f"the {name} receipt field {field} is {receipt.get(field)!r}, expected {value!r}"
                )
        if name == "helper":
            parents = receipt.get("parents")
            for parent in ("/opt", "/"):
                row = parents.get(parent) if isinstance(parents, dict) else None
                if not isinstance(row, dict) or row.get("traversable") is not True:
                    raise PackageReceiptError(
                        f"the helper receipt does not show {parent} traversable by UID 1000"
                    )
            continue
        rows = receipt.get("projects")
        if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
            raise PackageReceiptError(
                f"the {name} receipt field projects is {rows!r}, expected a list of project rows"
            )
        covered = [row.get("project") for row in rows]
        if covered != projects:
            raise PackageReceiptError(
                f"the {name} receipt field projects covers {covered!r}, expected {projects!r}"
            )
        if receipt.get("locks") != locks:
            raise PackageReceiptError(
                f"the {name} receipt field locks is {receipt.get('locks')!r}, expected {locks!r}"
            )


def prepare_image(root, evidence, image, base=None):
    """Build the isolated suites' image.

    In a gate run, base is the gate's own image, already in the engine: the
    suites' setup starts from it, and the engine's own builder builds it, so
    the image lands in the engine with no export and load. Standalone, the
    recipe starts from candidate-gate/Dockerfile.
    """
    projects = uv_projects(root)
    # Copy only source files and a self-contained Git bundle. A worktree's
    # .git file points outside it and cannot be copied into the runner.
    with tempfile.TemporaryDirectory(prefix="aw-egress-source-") as tmp:
        bundle = Path(tmp) / "source.bundle"
        subprocess.run(
            ["git", "-C", str(root), "bundle", "create", str(bundle), "HEAD"],
            check=True,
        )
        files = (
            subprocess.check_output(
                [
                    "git",
                    "-C",
                    str(root),
                    "ls-files",
                    "-z",
                    "--cached",
                    "--others",
                    "--exclude-standard",
                ]
            )
            .decode()
            .split("\0")
        )
        hashes = []
        for name in dict.fromkeys(files):
            if name and ((root / name).is_file() or (root / name).is_symlink()):
                destination = Path(tmp) / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / name, destination, follow_symlinks=False)
                data = (
                    destination.readlink().as_posix().encode()
                    if destination.is_symlink()
                    else destination.read_bytes()
                )
                hashes.append(hashlib.sha256(data).hexdigest() + "  " + name)
        (evidence / "source-files.sha256").write_text("\n".join(hashes) + "\n")
        recipe = (
            (
                f"FROM {base}\n"
                if base
                else (root / "candidate-gate/Dockerfile").read_text()
            )
            + "\n"
            + (root / "scripts/test-egress/Dockerfile").read_text()
        )
        if projects:
            helper = Path(__file__).with_name("prepare_projects.py")
            shutil.copy2(helper, Path(tmp) / "package-environment.py")
            sha = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            (evidence / "package-preparation-tool.sha256").write_text(
                hashlib.sha256(helper.read_bytes()).hexdigest() + "\n"
            )
            argv = [
                "python3",
                "/opt/package-environment.py",
                "--source-root",
                "/src",
                "--source-sha",
                sha,
            ]
            for project in projects:
                argv += ["--project", project]
            recipe += (
                "\nCOPY --chmod=0644 package-environment.py /opt/package-environment.py\n"
                + "USER 1000:1000\n"
                + "RUN "
                + shlex.join(
                    [
                        *argv,
                        "--mode",
                        "prepare",
                        "--receipt",
                        "/home/test-runner/package-environment-prepared.json",
                    ]
                )
                + "\nRUN "
                + shlex.join(
                    ["python3", "-c", "exec(" + repr(HELPER_READABILITY_CHECK) + ")"]
                )
                + " && "
                + shlex.join(
                    [
                        *argv,
                        "--mode",
                        "verify",
                        "--receipt",
                        "/home/test-runner/package-environment-verified.json",
                    ]
                )
                + "\nUSER root\n"
            )
        dockerfile = Path(tmp) / "isolated.Dockerfile"
        dockerfile.write_text(recipe)
        (evidence / "Dockerfile.generated").write_text(recipe)
        # Inside a gate runner the docker shim sends plain builds to the run's
        # docker-container builder (BUILDX_BUILDER), whose image must be
        # exported and loaded back; this build uses the engine's own builder.
        env = {k: v for k, v in os.environ.items() if k != "BUILDX_BUILDER"}
        label = os.environ.get("AWEB_CANDIDATE_RESOURCE_LABEL")
        labels = ["--label", f"aweb.candidate-gate={label}"] if label else []
        subprocess.run(
            ["docker", "build", *labels, "-f", str(dockerfile), "-t", image, tmp],
            check=True,
            env=env,
        )
