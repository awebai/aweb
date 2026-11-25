"""One source-owned image build for isolated suites and package callers."""

import hashlib
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


def prepare_image(root, evidence, image, base=None):
    """Build the isolated suites' image.

    In a gate run, base is the gate's own image, already in the engine: the
    suites' setup starts from it, and the engine's own builder builds it, so
    the image lands in the engine with no export and load. Standalone, the
    recipe starts from candidate-gate/Dockerfile.
    """
    projects = [
        str(Path(p).parent)
        for p in subprocess.check_output(
            ["git", "ls-files", "*uv.lock"], cwd=root, text=True
        ).splitlines()
    ]
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
            (f"FROM {base}\n" if base else (root / "candidate-gate/Dockerfile").read_text())
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
    # The run's cleanup removes the image, so its size is kept as evidence.
    size = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Size}}", image],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (evidence / "image-size-bytes").write_text(size + "\n")
    print(f"unit image size: {size} bytes", flush=True)
