#!/usr/bin/env python3
"""Release aweb's Python packages with one command, from the reviewed commit S.

1. build: build each requested package once from S into one directory and
   record the sha256 of every file;
2. gate: one aweb gate run at S on the chosen machine with those files in the
   guest; it installs their server wheel under test and rebuilds them from S;
3. tag: once S is on origin/main (landed unchanged, as a fast-forward), write
   the annotated release tag at S, listing every file's sha256;
4. publish: attach exactly those files to the tag's GitHub release; aweb's
   trusted-publishing workflow uploads them to PyPI, and nothing is rebuilt;
5. check: PyPI serves exactly those files, with those digests, not yanked.

Each step records what it produced in the receipt. A rerun continues from the
first step that is not done, after checking that what was recorded still holds.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Protocol

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_files import (  # noqa: E402
    PACKAGES,
    PUBLICATION_ORDER,
    RELEASE_TAGS,
    SOURCE_DIRECTORIES,
    ReleaseFilesRefusal,
    built_packages,
    digests,
)

STEPS = ("build", "gate", "tag", "publish", "check")
SHA = re.compile(r"[0-9a-f]{40}")
GITHUB = re.compile(
    r"(?:https://github\.com/|git@github\.com:|ssh://(?:git@)?(?:ssh\.)?github\.com(?::443)?/)([^/]+/[^/]+?)(?:\.git)?"
)
WORKFLOW = "pypi-release.yml"
# Until the release gate installs a new awid-service wheel under test, a release
# that needs one is refused. This names what is missing.
AWID_UNGATED = (
    "awid-service {version} is not on PyPI, and the release gate does not yet install a new "
    "awid-service wheel under test: it needs an awid image built from that wheel in the "
    "federation journey, and both wheels handed to the server install. Until then, release "
    "awid-service changes only after that gate exists"
)


class ReleaseRefusal(RuntimeError):
    """The release cannot continue; nothing past the refused step happened."""


class Outside(Protocol):
    """The release's effects beyond git: the build, PyPI, the gate launcher and GitHub."""

    def build(self, source: Path, out: Path) -> None: ...

    def download(self, url: str) -> bytes: ...

    def gate(self, argv: list[str]) -> int: ...

    def github_release(self, repository: str, tag: str, files: list[Path]) -> None: ...

    def workflow_run(self, repository: str, tag: str) -> str | None: ...


def git(cwd: Path, *args: str, check: bool = True) -> str:
    completed = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if check and completed.returncode:
        raise ReleaseRefusal(f"git {' '.join(args)} failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def remote_tag(remote: str, tag: str) -> str | None:
    """The commit a remote tag identifies, or None when the remote has no such tag."""
    ref = f"refs/tags/{tag}"
    listed = subprocess.run(
        ["git", "ls-remote", remote, ref, ref + "^{}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    refs = dict(reversed(line.split("\t")) for line in listed.splitlines())
    return refs.get(ref + "^{}", refs.get(ref))


def tag_lines(files: dict[str, str]) -> str:
    """The files a tag locks, in the format publish_release.py reads: hex, two spaces, name."""
    return "".join(
        f"{digest.removeprefix('sha256:')}  {name}\n"
        for name, digest in sorted(files.items())
    )


class Receipt:
    """The release's state: what each finished step produced, saved after every step."""

    def __init__(self, path: Path, inputs: dict[str, Any]) -> None:
        self.path = path
        if path.exists():
            self.data = json.loads(path.read_text())
            if self.data["inputs"] != inputs:
                raise ReleaseRefusal(
                    f"{path} records another release: {self.data['inputs']}; finish it or remove its state directory"
                )
        else:
            self.data = {"inputs": inputs, "steps": {}}

    def get(self, step: str) -> Any:
        return self.data["steps"].get(step)

    def record(self, step: str, value: Any) -> None:
        self.data["steps"][step] = value
        self.save()

    def attempt(self, value: dict[str, Any]) -> None:
        """Every gate run, red or green, in order: the release's history, not its progress."""
        self.data.setdefault("gate_attempts", []).append(value)
        self.save()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        partial = self.path.with_suffix(".partial")
        partial.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n")
        partial.replace(self.path)


class Release:
    def __init__(
        self,
        root: Path,
        sha: str,
        packages: list[str],
        *,
        machine: str,
        state: Path,
        outside: Outside,
        launcher: str,
        repository: str,
        poll_seconds: float,
        deadline_seconds: float,
    ) -> None:
        if not SHA.fullmatch(sha):
            raise ReleaseRefusal("the release commit must be a full lowercase SHA")
        unknown = sorted(set(packages) - set(PACKAGES))
        if unknown or not packages:
            raise ReleaseRefusal(
                f"packages must be among {', '.join(PACKAGES)}: got {packages}"
            )
        self.root, self.sha, self.machine, self.state = root, sha, machine, state
        self.packages = [name for name in PUBLICATION_ORDER if name in packages]
        self.outside, self.launcher = outside, launcher
        self.poll_seconds, self.deadline_seconds = poll_seconds, deadline_seconds
        self.files = state / "files"
        self.remote = git(root, "remote", "get-url", "origin")
        self.repository = repository
        self.receipt = Receipt(
            state / "receipt.json",
            {"sha": sha, "packages": self.packages, "machine": machine},
        )

    def checkout(self) -> Path:
        """S, alone, outside the operator's checkout: a builder there sees only S's files."""
        checkout = self.state / "aweb"
        if (
            checkout.exists()
            and git(checkout, "rev-parse", "HEAD", check=False) == self.sha
        ):
            return checkout
        shutil.rmtree(checkout, ignore_errors=True)
        checkout.mkdir(parents=True)
        git(checkout, "init", "--quiet")
        git(checkout, "fetch", "--quiet", str(self.root), self.sha)
        git(checkout, "checkout", "--quiet", "--detach", self.sha)
        return checkout

    def version_at(self, name: str) -> str:
        source = self.checkout() / SOURCE_DIRECTORIES[name] / "pyproject.toml"
        return tomllib.loads(source.read_text())["project"]["version"]

    def on_pypi(self, name: str, version: str) -> bool:
        try:
            self.outside.download(f"https://pypi.org/pypi/{name}/{version}/json")
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 404:
                return False
            raise
        return True

    # 1. Build each package once.
    def build(self) -> None:
        recorded = self.receipt.get("build")
        if recorded is not None:
            if not self.files.exists() or digests(self.files) != recorded["files"]:
                raise ReleaseRefusal(
                    f"the built files in {self.files} changed since they were built"
                )
            return
        checkout = self.checkout()
        awid_version = self.version_at("awid-service")
        if "awid-service" in self.packages or not self.on_pypi(
            "awid-service", awid_version
        ):
            raise ReleaseRefusal(AWID_UNGATED.format(version=awid_version))
        if self.files.exists():
            shutil.rmtree(self.files)
        self.files.mkdir(parents=True)
        packages = {}
        for name in self.packages:
            source = checkout / SOURCE_DIRECTORIES[name]
            # A builder whose project path matches the project's own ignore rules
            # drops them all, and then ships files no other build of S ships.
            if git(
                checkout,
                "check-ignore",
                "--no-index",
                str(source.resolve()).lstrip("/"),
                check=False,
            ):
                raise ReleaseRefusal(
                    f"{source.resolve()} lies in a directory the aweb ignore rules name; "
                    "keep the release state elsewhere (--state)"
                )
            version = self.version_at(name)
            if self.on_pypi(name, version):
                raise ReleaseRefusal(
                    f"PyPI already has {name} {version}; {self.sha} cannot release it again"
                )
            self.outside.build(source, self.files)
            packages[name] = version
        # The directory holds exactly the files the release ships; a builder's own markers go.
        keep_shipped(self.files)
        try:
            files = digests(self.files)
        except ReleaseFilesRefusal as error:
            raise ReleaseRefusal(str(error)) from None
        if {
            name: version
            for name, (version, _w, _s) in built_packages(self.files).items()
        } != packages:
            raise ReleaseRefusal(f"the build of {self.sha} is not {packages}")
        self.receipt.record("build", {"files": files, "packages": packages})

    # 2. One gate run at S with the built files.
    def gate(self) -> None:
        if self.receipt.get("gate") is not None:
            return
        built = self.receipt.get("build")
        receipt_path = self.state / "gate-receipt.json"
        receipt_path.unlink(missing_ok=True)
        argv = [
            self.launcher,
            "run",
            "--project",
            "aweb",
            "--repo",
            str(self.root),
            "--sha",
            self.sha,
            "--intent",
            "train",
            "--machine",
            self.machine,
            "--receipt",
            str(receipt_path),
            "--files",
            str(self.files),
        ]
        status = self.outside.gate(argv)
        if not receipt_path.exists():
            raise ReleaseRefusal(f"the gate wrote no receipt (exit {status})")
        result = json.loads(receipt_path.read_text())
        self.receipt.attempt(
            {
                "run_id": result.get("run_id"),
                "status": status,
                "exit": result.get("exit"),
                "error": (result.get("vm_gate") or {}).get("error"),
                "evidence": result.get("evidence"),
            }
        )
        if (result.get("project"), result.get("sha"), result.get("machine")) != (
            "aweb",
            self.sha,
            self.machine,
        ):
            raise ReleaseRefusal(
                "the gate receipt is for another project, commit or machine"
            )
        if result.get("files") != built["files"]:
            raise ReleaseRefusal(
                "the gate receipt tested other files than the ones built for this release"
            )
        vm_gate = result.get("vm_gate") or {}
        if result.get("exit") == 70 or vm_gate.get("infrastructure") not in (
            None,
            "refused",
        ):
            raise ReleaseRefusal(
                f"the gate run hit an infrastructure fault: {vm_gate.get('error')}; rerun make release"
            )
        if result.get("exit") == 2:
            raise ReleaseRefusal(f"the gate refused the run: {vm_gate.get('error')}")
        if status != 0 or result.get("exit") != 0:
            raise ReleaseRefusal(
                f"the gate is red (exit {result.get('exit')}), evidence {result.get('evidence')}; fix and rerun make release"
            )
        if result.get("rebuilt_files") != built["files"]:
            raise ReleaseRefusal("the gate's rebuild of S differs from the built files")
        if "aweb" in built["packages"]:
            wheel = next(
                name
                for name in built["files"]
                if name.startswith("aweb-") and name.endswith(".whl")
            )
            held = {
                service: (record or {}).get("container_wheel_sha256")
                for service, record in (result.get("installed_wheels") or {}).items()
            }
            if held != {
                "aweb-alpha": built["files"][wheel],
                "aweb-beta": built["files"][wheel],
            }:
                raise ReleaseRefusal(
                    f"the gate's servers did not install the built wheel: {held}"
                )
        self.receipt.record("gate", {"run_id": result.get("run_id"), "receipt": result})

    # 3. Tag S once it is on main.
    def tag(self) -> None:
        if self.receipt.get("tag") is not None:
            return
        git(self.root, "fetch", "--quiet", "origin", "main")
        main = git(self.root, "rev-parse", "origin/main")
        if subprocess.run(
            ["git", "merge-base", "--is-ancestor", self.sha, main], cwd=self.root
        ).returncode:
            raise ReleaseRefusal(
                f"origin/main ({main}) does not contain {self.sha}: land it unchanged as a fast-forward, "
                "then rerun make release to tag and publish"
            )
        built, gate = self.receipt.get("build"), self.receipt.get("gate")
        checkout = self.checkout()
        tags = {}
        for name in self.packages:
            tag = RELEASE_TAGS[name] + built["packages"][name]
            prefix = PACKAGES[name] + "-"
            files = {
                file: digest
                for file, digest in built["files"].items()
                if file.startswith(prefix)
            }
            lines = tag_lines(files)
            tagged = remote_tag(self.remote, tag)
            if tagged is None:
                if not git(checkout, "tag", "--list", tag):
                    message = f"{tag}\n\nGated by run {gate['run_id']} on {self.machine}.\n\n{lines}"
                    git(
                        checkout,
                        "-c",
                        "tag.gpgSign=false",
                        "tag",
                        "-a",
                        tag,
                        self.sha,
                        "-m",
                        message,
                    )
                self.require_tag(checkout, tag, lines)
                git(checkout, "push", "--quiet", self.remote, f"refs/tags/{tag}")
            elif tagged != self.sha:
                raise ReleaseRefusal(
                    f"{tag} already identifies {tagged}, not {self.sha}"
                )
            else:
                git(
                    checkout,
                    "fetch",
                    "--quiet",
                    self.remote,
                    f"+refs/tags/{tag}:refs/tags/{tag}",
                )
                self.require_tag(checkout, tag, lines)
            tags[name] = tag
        self.receipt.record("tag", tags)

    def require_tag(self, checkout: Path, tag: str, lines: str) -> None:
        """The tag is annotated, identifies S and ends with exactly the built files' lines."""
        ref = f"refs/tags/{tag}"
        if git(checkout, "cat-file", "-t", ref) != "tag":
            raise ReleaseRefusal(f"{tag} is not an annotated tag")
        if git(checkout, "rev-parse", f"{ref}^{{commit}}") != self.sha:
            raise ReleaseRefusal(
                f"{tag} identifies {git(checkout, 'rev-parse', ref + '^{commit}')}, not {self.sha}"
            )
        if not git(checkout, "for-each-ref", "--format=%(contents)", ref).endswith(
            lines.rstrip("\n")
        ):
            raise ReleaseRefusal(
                f"{tag} at {self.sha} locks other files than the ones built"
            )

    # 4. Attach exactly the files; the trusted-publishing workflow uploads them.
    def publish(self) -> None:
        published = dict(self.receipt.get("publish") or {})
        built, tags = self.receipt.get("build"), self.receipt.get("tag")
        for name in self.packages:
            if name in published:
                continue
            prefix = PACKAGES[name] + "-"
            files = sorted(
                self.files / file for file in built["files"] if file.startswith(prefix)
            )
            self.outside.github_release(self.repository, tags[name], files)
            self.wait(name, built["packages"][name], tags[name])
            published[name] = tags[name]
            self.receipt.record("publish", published)

    def served(self, name: str, version: str) -> None:
        """PyPI serves exactly the built files of this package, with their digests, none yanked."""
        built = self.receipt.get("build")
        prefix = PACKAGES[name] + "-"
        expected = {
            file: digest
            for file, digest in built["files"].items()
            if file.startswith(prefix)
        }
        urls = json.loads(
            self.outside.download(f"https://pypi.org/pypi/{name}/{version}/json")
        )["urls"]
        yanked = sorted(entry["filename"] for entry in urls if entry.get("yanked"))
        if yanked:
            raise ReleaseRefusal(f"PyPI {name} {version} has yanked files: {yanked}")
        served = {
            entry["filename"]: "sha256:" + entry["digests"]["sha256"] for entry in urls
        }
        if served != expected:
            raise ReleaseRefusal(
                f"PyPI {name} {version} serves {served}, not the built {expected}"
            )

    def wait(self, name: str, version: str, tag: str) -> None:
        """Until PyPI serves the files, or the deadline; the refusal names the workflow run."""
        deadline = time.monotonic() + self.deadline_seconds
        while True:
            try:
                self.served(name, version)
                return
            except urllib.error.HTTPError as error:
                error.close()
                if error.code != 404:
                    raise
                reason = f"PyPI has no {name} {version} yet"
            except ReleaseRefusal as error:
                reason = str(error)
            if time.monotonic() >= deadline:
                run = self.outside.workflow_run(self.repository, tag)
                raise ReleaseRefusal(
                    f"{reason} after {self.deadline_seconds:.0f} s; the publish workflow for {tag}: "
                    f"{run or 'no run found'}"
                )
            time.sleep(self.poll_seconds)

    # 5. Check what PyPI serves.
    def check(self) -> None:
        if self.receipt.get("check") is not None:
            return
        built = self.receipt.get("build")
        for name in self.packages:
            self.served(name, built["packages"][name])
        self.receipt.record(
            "check", {name: built["packages"][name] for name in self.packages}
        )

    def summary(self) -> str:
        built, gate = self.receipt.get("build"), self.receipt.get("gate")
        lines = [
            f"Released {', '.join(self.receipt.get('tag').values())} at {self.sha} (gate run {gate['run_id']} on {self.machine})."
        ]
        lines += [
            f"  {digest}  {name}" for name, digest in sorted(built["files"].items())
        ]
        return "\n".join(lines)

    def run(self, through: str | None = None) -> str:
        if through is not None and through not in STEPS:
            raise ReleaseRefusal(f"--through must be one of {', '.join(STEPS)}")
        for step in STEPS:
            getattr(self, step)()
            if step == through:
                return f"Stopped through {step}; state is in {self.receipt.path}. Rerun without --through to continue."
        return self.summary()


def keep_shipped(files: Path) -> None:
    """Leave in `files` only the built wheel and sdist of each package; a builder's own markers go."""
    shipped = set()
    for name, prefix in PACKAGES.items():
        wheels = sorted(files.glob(f"{prefix}-*-py3-none-any.whl"))
        sdists = sorted(files.glob(f"{prefix}-*.tar.gz"))
        if wheels or sdists:
            if len(wheels) != 1 or len(sdists) != 1:
                raise ReleaseRefusal(
                    f"the build left {len(wheels)} {name} wheels and {len(sdists)} sdists"
                )
            shipped.update((wheels[0], sdists[0]))
    for path in files.iterdir():
        if path not in shipped:
            path.unlink()


class Live:
    """The real boundary: uv, PyPI, the gate launcher and gh."""

    def build(self, source: Path, out: Path) -> None:
        subprocess.run(
            [
                "uv",
                "build",
                "--quiet",
                "--wheel",
                "--sdist",
                "--out-dir",
                str(out),
                str(source),
            ],
            check=True,
        )

    def download(self, url: str) -> bytes:
        with urllib.request.urlopen(url, timeout=60) as response:
            return response.read()

    def gate(self, argv: list[str]) -> int:
        return subprocess.run(argv).returncode

    def github_release(self, repository: str, tag: str, files: list[Path]) -> None:
        viewed = subprocess.run(
            ["gh", "release", "view", tag, "--repo", repository, "--json", "assets"],
            capture_output=True,
            text=True,
        )
        if viewed.returncode == 0:
            assets = {
                (asset["name"], asset["size"])
                for asset in json.loads(viewed.stdout)["assets"]
            }
            if assets != {(path.name, path.stat().st_size) for path in files}:
                raise ReleaseRefusal(
                    f"the GitHub release {tag} carries other files: {sorted(assets)}"
                )
            return
        subprocess.run(
            [
                "gh",
                "release",
                "create",
                tag,
                "--repo",
                repository,
                "--verify-tag",
                "--title",
                tag,
                "--notes",
                f"{tag}: the gated files listed in the tag message.",
                *map(str, files),
            ],
            check=True,
        )

    def workflow_run(self, repository: str, tag: str) -> str | None:
        listed = subprocess.run(
            [
                "gh",
                "run",
                "list",
                "--repo",
                repository,
                "--workflow",
                WORKFLOW,
                "--branch",
                tag,
                "--json",
                "url,status,conclusion",
                "--limit",
                "1",
            ],
            capture_output=True,
            text=True,
        )
        if listed.returncode:
            return None
        runs = json.loads(listed.stdout or "[]")
        if not runs:
            return None
        return f"{runs[0]['url']} ({runs[0]['status']}, {runs[0].get('conclusion') or 'no conclusion'})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--sha", required=True, help="the reviewed aweb commit S to release"
    )
    parser.add_argument(
        "--package",
        action="append",
        required=True,
        choices=sorted(PACKAGES),
        help="repeat per package",
    )
    parser.add_argument("--machine", required=True, help="the machine the gate runs on")
    parser.add_argument(
        "--through",
        choices=STEPS,
        help="stop after this step; rerun without it to continue",
    )
    parser.add_argument(
        "--state",
        type=Path,
        help="receipt directory (default ~/.local/state/aweb/releases/<sha>)",
    )
    arguments = parser.parse_args(argv)
    state = (
        arguments.state or Path.home() / ".local/state/aweb/releases" / arguments.sha
    )
    root = Path.cwd().resolve()
    try:
        origin = git(root, "remote", "get-url", "origin")
        match = GITHUB.fullmatch(origin)
        if match is None:
            raise ReleaseRefusal(f"origin {origin} is not a GitHub repository")
        print(
            Release(
                root,
                arguments.sha,
                arguments.package,
                machine=arguments.machine,
                state=state,
                outside=Live(),
                launcher=os.environ.get("VM_GATE", "vm-gate"),
                repository=match[1],
                poll_seconds=15,
                deadline_seconds=1800,
            ).run(arguments.through)
        )
    except (ReleaseRefusal, subprocess.CalledProcessError) as error:
        print(f"release refused: {error}", file=sys.stderr)
        print(
            f"rerun make release to continue; state is in {state}/receipt.json",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
