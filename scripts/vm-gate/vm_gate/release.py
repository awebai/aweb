"""One release job on one machine: aweb's gate and Cloud's gate in one guest.

The controller checks that the release commit still sits on Cloud's main,
ships the Cloud commit as a bundle whose main is that commit, the amd64
member of the Cloud image as a docker archive, the built aweb files and a
test-only Hermes key, and writes one receipt for both suites.
"""

import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

from .config import child_environment
from .errors import Infrastructure, Refused
from .executor import LOGS, REMOTE, Executor

Q = shlex.quote
# A release qualifies the amd64 image that production runs.
RELEASE_PLATFORM = "linux/amd64"
# The machines vm-gate can run a guest on.
BACKENDS = ("merak", "hetzner")
IMAGE = re.compile(r"(?P<repository>[a-z0-9./-]+)@(?P<index>sha256:[0-9a-f]{64})")
SHA = re.compile(r"[0-9a-f]{40}")
GUEST_RELEASE = LOGS + "/release"
GUEST_FILES = REMOTE + "/release-files"
GUEST_KEY_DIRECTORY = "/run/vm-gate-release"
GUEST_KEY = GUEST_KEY_DIRECTORY + "/hermes-key"
# aweb file name prefix -> the aweb project that builds it.
AWEB_PROJECTS = {"awid_service-": "awid", "aweb-": "server"}


def git(repo, *argv, env=None):
    result = subprocess.run(
        ["git", "-C", str(repo), *argv],
        capture_output=True,
        text=True,
        env=env or child_environment(),
    )
    if result.returncode:
        raise Infrastructure(f"git {argv[0]} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_machine(machine, config):
    """The machine is an input; operator config declares its platform."""
    platform = (config.get(machine) or {}).get("platform")
    if platform is None:
        raise Refused(f"operator config declares no platform for machine {machine}")
    if platform != RELEASE_PLATFORM:
        raise Refused(
            f"a release gate needs a {RELEASE_PLATFORM} machine; {machine} is {platform}"
        )
    if machine not in BACKENDS:
        raise Refused(f"vm-gate has no backend for machine {machine}")
    return platform


def cloud_main(repo, cloud_sha):
    """Refuse before boot unless the release commit sits directly on real main."""
    if not SHA.fullmatch(cloud_sha):
        raise Refused("--cloud-sha must be a full commit SHA")
    git(
        repo,
        "fetch",
        "--quiet",
        "--no-tags",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
    )
    real_main = git(repo, "rev-parse", "refs/remotes/origin/main^{commit}")
    parent = git(repo, "rev-parse", cloud_sha + "^{commit}^")
    if parent != real_main:
        raise Refused(
            f"Cloud main moved: real main is {real_main}, the release commit's parent is {parent}; "
            "rerun make release to pin again"
        )
    return {"real_main": {"ac": real_main}, "ac_parent_of_c": parent}


def cloud_bundle(repo, cloud_sha, out):
    """A bundle whose main is the release commit, without touching the Cloud repo's refs."""
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    with tempfile.TemporaryDirectory() as scratch:
        borrowed = Path(scratch) / "borrowed.git"
        git(scratch, "init", "--quiet", "--bare", str(borrowed))
        (borrowed / "objects/info/alternates").write_text(
            str(common / "objects") + "\n"
        )
        git(borrowed, "update-ref", "refs/heads/main", cloud_sha)
        git(borrowed, "bundle", "create", str(out), "refs/heads/main")
        git(borrowed, "bundle", "verify", str(out))
    return sha256(out)


def docker(*argv):
    result = subprocess.run(["docker", *argv], capture_output=True, text=True)
    if result.returncode:
        raise Infrastructure(f"docker {argv[0]} failed: {result.stderr.strip()}")
    return result.stdout


def archive_config(archive):
    """The config digest of the single image in a docker save archive."""
    with tarfile.open(archive) as tar:
        member = tar.extractfile("manifest.json")
        if member is None:
            raise Infrastructure("the image archive has no manifest.json")
        manifest = json.load(member)
    if len(manifest) != 1:
        raise Infrastructure("the image archive must hold exactly one image")
    config = manifest[0]["Config"]
    digest = config.removeprefix("blobs/sha256/").removesuffix(".json")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise Infrastructure("the image archive names no config digest")
    return "sha256:" + digest


def image_archive(image, platform, run_id, out):
    """Resolve the index's member for the machine's platform and save it by a run tag."""
    match = IMAGE.fullmatch(image)
    if match is None:
        raise Refused("--cloud-image must be <repository>@sha256:<index>")
    repository = match["repository"]
    index = json.loads(docker("buildx", "imagetools", "inspect", "--raw", image))
    os_name, architecture = platform.split("/")
    members = [
        m["digest"]
        for m in index.get("manifests", [])
        if m.get("platform", {}).get("os") == os_name
        and m.get("platform", {}).get("architecture") == architecture
    ]
    if len(members) != 1:
        raise Refused(f"the Cloud image index has no single {platform} member")
    member = members[0]
    docker("pull", "--quiet", "--platform", platform, f"{repository}@{member}")
    # Saved by a tag: a docker load then still resolves repository@member.
    tag = f"{repository}:gate-{run_id}"
    docker("tag", f"{repository}@{member}", tag)
    try:
        docker("save", "--output", str(out), tag)
    finally:
        docker("image", "rm", tag)
    return {
        "image": image,
        "member": member,
        "config": archive_config(out),
        "archive_sha256": sha256(out),
    }


def built_files(directory):
    if directory is None:
        return {}
    directory = Path(directory)
    files = {p.name: sha256(p) for p in sorted(directory.iterdir()) if p.is_file()}
    if not files:
        raise Refused(f"--files {directory} holds no built files")
    for name in files:
        if not any(name.startswith(prefix) for prefix in AWEB_PROJECTS):
            raise Refused(f"{name} is not a file aweb builds")
    return files


def hermes_key(path):
    if not path:
        raise Refused("operator config requires hermes_key_file for the Cloud journeys")
    path = Path(path)
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise Refused(
            "hermes_key_file must be a regular file owned by this user, mode 0600"
        )
    return path


def guest_script(
    *,
    cloud_sha,
    bundle_sha256,
    archive_sha256,
    image,
    member,
    lock_source_sha,
    aweb,
    files,
    remote=REMOTE,
    logs=LOGS,
    home="/home/gateuser",
    key=GUEST_KEY,
    files_dir=GUEST_FILES,
):
    """Both suites in parallel; each writes its exit and output under release/."""
    release = logs + "/release"
    cloud_env = [
        f"AWEB_GATE_LEDGER={release}/cloud/ledger.tsv",
        f"AWEB_GATE_LOG_DIR={release}/cloud/gate-logs",
        f"DOCKER_CONFIG={release}/cloud/empty-docker-config",
        f"AC_CANDIDATE_RELEASE_IMAGE={image}",
        f"AC_CANDIDATE_RELEASE_IMAGE_ARCHIVE={remote}/cloud-image.tar",
        f"AC_CANDIDATE_RELEASE_IMAGE_MEMBER={member}",
        f"AC_CANDIDATE_AWEB_LOCK_SOURCE_SHA={lock_source_sha}",
        f"AC_CANDIDATE_HERMES_ANTHROPIC_KEY_FILE={key}",
    ]
    if files:
        cloud_env += [
            f"AC_CANDIDATE_AWEB_WHEELS={files_dir}",
            f"AC_CANDIDATE_AWEB_WHEELS_SOURCE_SHA={aweb}",
        ]
    exports = "export " + " ".join(Q(e) for e in cloud_env)
    projects = sorted(
        {
            AWEB_PROJECTS[p]
            for name in files
            for p in AWEB_PROJECTS
            if name.startswith(p)
        }
    )
    rebuild = "\n".join(
        f"  uv build --quiet --wheel --sdist --out-dir {Q(release + '/aweb/rebuilt')} {Q(project)} || exit 1"
        for project in projects
    )
    aweb_suite = ""
    if aweb:
        aweb_suite = f"""
(
  set -u
  cd {Q(remote + "/source")}
  test "$(git rev-parse HEAD)" = {Q(aweb)} || exit 70
  make candidate-gate > {Q(release + "/aweb/gate-output.log")} 2>&1
  printf '%s\\n' "$?" > {Q(release + "/aweb/exit")}
  mkdir -p {Q(release + "/aweb/rebuilt")}
{rebuild}
  python3 -c 'import hashlib, json, pathlib, sys; d = pathlib.Path(sys.argv[1]); print(json.dumps({{p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.iterdir())}}, sort_keys=True))' {Q(release + "/aweb/rebuilt")} > {Q(release + "/aweb/rebuilt.json")}
) > {Q(release + "/aweb/suite.log")} 2>&1 &
aweb_suite=$!
"""
    return f"""set -u
mkdir -p {Q(release + "/aweb")} {Q(release + "/cloud/empty-docker-config")}
chmod 0700 {Q(release + "/cloud/empty-docker-config")}
echo {Q(bundle_sha256 + "  " + remote + "/cloud.bundle")} | sha256sum -c - || exit 70
echo {Q(archive_sha256 + "  " + remote + "/cloud-image.tar")} | sha256sum -c - || exit 70
cd {Q(home)}
rm -rf cloud-origin cloud-source
git init --quiet --bare cloud-origin || exit 70
git --git-dir=cloud-origin fetch --quiet {Q(remote + "/cloud.bundle")} refs/heads/main:refs/heads/main || exit 70
git --git-dir=cloud-origin symbolic-ref HEAD refs/heads/main || exit 70
git clone --quiet cloud-origin cloud-source || exit 70
test "$(git -C cloud-source rev-parse HEAD)" = {Q(cloud_sha)} || exit 70
{aweb_suite}
(
  cd {Q(home + "/cloud-source")}
  git config user.name 'aweb release gate'
  git config user.email 'release-gate@localhost'
  {exports}
  make release-gate > {Q(release + "/cloud/gate-output.log")} 2>&1
  printf '%s\\n' "$?" > {Q(release + "/cloud/exit")}
) &
cloud_suite=$!
wait "$cloud_suite"
{'wait "$aweb_suite"' if aweb else ""}
status=0
test "$(cat {Q(release + "/cloud/exit")} 2>/dev/null)" = 0 || status=1
{f'test "$(cat {Q(release + "/aweb/exit")} 2>/dev/null)" = 0 || status=1' if aweb else ""}
exit "$status"
"""


class ReleaseExecutor(Executor):
    """The guest executor with the release inputs placed before the gate starts."""

    def __init__(self, config, directory, source, command, provider, *, release):
        super().__init__(config, directory, source, command, provider)
        self.release = release

    def prepare(self, server, timeout):
        super().prepare(server, timeout)
        self.upload(self.release["bundle"], REMOTE + "/cloud.bundle", mode="0444")
        self.upload(self.release["archive"], REMOTE + "/cloud-image.tar", mode="0444")
        self.run(
            f"install -d -m 0755 -o root -g root {GUEST_FILES}",
            "release-files-directory",
        )
        for path in self.release["files"]:
            self.upload(path, GUEST_FILES + "/" + Path(path).name, mode="0444")
        self.run(
            f"install -d -o root -g gateuser -m 0710 {GUEST_KEY_DIRECTORY}",
            "hermes-directory",
        )
        self.upload(
            self.release["hermes_key"],
            GUEST_KEY,
            owner="gateuser:gateuser",
            mode="0600",
        )

    def collect(self, server, timeout):
        self.deadline = time.monotonic() + timeout
        self.run(f"rm -f {GUEST_KEY}", "hermes-key-removed")
        return super().collect(server, timeout)


def suite_record(evidence, suite):
    root = Path(evidence) / ("var/log/vm-gate/release/" + suite)
    exit_file = root / "exit"
    value = exit_file.read_text().strip() if exit_file.exists() else ""
    return {
        "exit": int(value) if value.isdigit() else None,
        "evidence": str(root),
    }


def receipt(
    *,
    machine,
    platform,
    run_id,
    result,
    cloud_sha,
    image,
    main,
    files,
    aweb,
    launcher_sha,
    timeout,
    directory,
):
    """The one record make release reads: both suites, both inputs, the main check."""
    evidence = Path(directory) / "evidence"
    cloud = {
        "sha": cloud_sha,
        "image": image["image"],
        "member": image["member"],
        "config": image["config"],
        "command": "make release-gate",
        **suite_record(evidence, "cloud"),
    }
    record = {
        "machine": machine,
        "machine_platform": platform,
        "run_id": run_id,
        "launcher_sha": launcher_sha,
        "timeout_seconds": timeout,
        "files": files,
        "cloud": cloud,
        **main,
        "vm_gate": {
            "exit": result.get("exit"),
            "infrastructure": result.get("infrastructure"),
            "error": result.get("error"),
            "summary": str(Path(directory) / "summary.json"),
        },
    }
    if aweb:
        rebuilt_path = evidence / "var/log/vm-gate/release/aweb/rebuilt.json"
        rebuilt = (
            json.loads(rebuilt_path.read_text()) if rebuilt_path.exists() else None
        )
        record["aweb"] = {
            "sha": aweb,
            "command": "make candidate-gate",
            "rebuilt_files": (
                {name: rebuilt[name] for name in files if name in rebuilt}
                if rebuilt is not None
                else None
            ),
            "ledger_rows_imported": result.get("ledger_rows_imported"),
            **suite_record(evidence, "aweb"),
        }
    return record


# The release job's exits: green, a red suite, refused before boot, infrastructure.
GREEN, RED, REFUSED, INFRASTRUCTURE = 0, 1, 2, 70


def exit_code(record):
    """Green only when every suite passed and aweb rebuilt the exact files."""
    classification = record["vm_gate"]["infrastructure"]
    if classification == "refused":
        return REFUSED
    if classification is not None:
        return INFRASTRUCTURE
    suites = [record["cloud"]] + ([record["aweb"]] if "aweb" in record else [])
    if any(suite["exit"] is None for suite in suites):
        return INFRASTRUCTURE
    if any(suite["exit"] != 0 for suite in suites):
        return RED
    if "aweb" in record and record["aweb"]["rebuilt_files"] != record["files"]:
        return RED
    return GREEN
