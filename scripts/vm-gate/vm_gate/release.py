"""Cloud's gate in one guest, and the machine and input helpers both projects use.

For a Cloud run (`vm-gate run --project ac`) the controller checks the commit
against Cloud's real main, ships it as a bundle, the amd64 member of the Cloud
image as a docker archive when it is a release, and a test-only Hermes key.
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
# A release qualifies the amd64 image that production runs, on every host:
# an arm64 host runs that same member under its amd64 emulation (Rosetta).
RELEASE_PLATFORM = "linux/amd64"
# merak and hetzner boot a guest; native runs on the host's own Docker.
BACKENDS = ("merak", "hetzner", "native")
IMAGE = re.compile(r"(?P<repository>[a-z0-9./-]+)@(?P<index>sha256:[0-9a-f]{64})")
SHA = re.compile(r"[0-9a-f]{40}")
GUEST_FILES = REMOTE + "/release-files"
GUEST_KEY_DIRECTORY = "/run/vm-gate-release"
GUEST_KEY = GUEST_KEY_DIRECTORY + "/hermes-key"
# aweb file name prefix -> the aweb project that builds it.
AWEB_PROJECTS = {"awid_service-": "awid", "aweb-": "server"}


# What the operator's own git needs to reach a private origin: its config
# (HOME), its SSH agent and its credential helpers (PATH).
OPERATOR_GIT_VARIABLES = (
    "HOME",
    "PATH",
    "SSH_AUTH_SOCK",
    "SSH_AGENT_PID",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
)


def operator_git_environment():
    """The admission fetch's environment, on the controller only.

    Every other git call, and everything in the guest, keeps the credential-free
    child environment.
    """
    environment = child_environment()
    environment.update(
        {name: os.environ[name] for name in OPERATOR_GIT_VARIABLES if name in os.environ}
    )
    return environment


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
    """The machine is an input; operator config declares its platform and backend."""
    settings = config.get(machine) or {}
    platform = settings.get("platform")
    if platform is None:
        raise Refused(f"operator config declares no platform for machine {machine}")
    backend = settings.get("backend", machine)
    if backend not in BACKENDS:
        raise Refused(f"vm-gate has no backend for machine {machine}")
    return platform, backend


def cloud_main(repo, cloud_sha, gate=False):
    """Refuse before boot unless C is where its job needs it on real main.

    A release's version commit C sits directly on real main. A gate's C is a
    train head: real main must be in its history.
    """
    if not SHA.fullmatch(cloud_sha):
        raise Refused("--cloud-sha must be a full commit SHA")
    git(
        repo,
        "fetch",
        "--quiet",
        "--no-tags",
        "origin",
        "+refs/heads/main:refs/remotes/origin/main",
        env=operator_git_environment(),
    )
    real_main = git(repo, "rev-parse", "refs/remotes/origin/main^{commit}")
    if gate:
        over = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", real_main, cloud_sha],
            capture_output=True,
            text=True,
        )
        if over.returncode:
            raise Refused(
                f"Cloud main moved: {cloud_sha} is not over real main {real_main}; "
                "rebase the train onto main"
            )
        return {"real_main": {"ac": real_main}, "ac_main_is_ancestor_of_c": True}
    parent = git(repo, "rev-parse", cloud_sha + "^{commit}^")
    if parent != real_main:
        raise Refused(
            f"Cloud main moved: real main is {real_main}, the release commit's parent is {parent}; "
            "rerun make release to pin again"
        )
    return {"real_main": {"ac": real_main}, "ac_parent_of_c": parent}


def cloud_bundle(repo, cloud_sha, out, main=None):
    """A bundle for the guest, without touching the Cloud repo's refs.

    A release's main is its commit C. A gate's main is real main, and C goes
    as refs/heads/candidate, so the guest's origin/main stays real main.
    """
    common = Path(git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    with tempfile.TemporaryDirectory() as scratch:
        borrowed = Path(scratch) / "borrowed.git"
        git(scratch, "init", "--quiet", "--bare", str(borrowed))
        (borrowed / "objects/info/alternates").write_text(
            str(common / "objects") + "\n"
        )
        git(borrowed, "update-ref", "refs/heads/main", main or cloud_sha)
        refs = ["refs/heads/main"]
        if main:
            git(borrowed, "update-ref", "refs/heads/candidate", cloud_sha)
            refs.append("refs/heads/candidate")
        git(borrowed, "bundle", "create", str(out), *refs)
        git(borrowed, "bundle", "verify", str(out))
    return sha256(out)


def docker(*argv):
    result = subprocess.run(["docker", *argv], capture_output=True, text=True)
    if result.returncode:
        raise Infrastructure(f"docker {argv[0]} failed: {result.stderr.strip()}")
    return result.stdout


def archive_config(archive):
    """The config digest and architecture of the single image in a docker save archive."""
    with tarfile.open(archive) as tar:
        member = tar.extractfile("manifest.json")
        if member is None:
            raise Infrastructure("the image archive has no manifest.json")
        manifest = json.load(member)
        if len(manifest) != 1:
            raise Infrastructure("the image archive must hold exactly one image")
        path = manifest[0]["Config"]
        digest = path.removeprefix("blobs/sha256/").removesuffix(".json")
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise Infrastructure("the image archive names no config digest")
        blob = tar.extractfile(path)
        if blob is None:
            raise Infrastructure("the image archive has no config blob")
        architecture = json.load(blob).get("architecture")
    return "sha256:" + digest, architecture


def shipped_member(archive):
    """Refuse any member but amd64: the release qualifies what production runs."""
    config, architecture = archive_config(archive)
    if architecture != "amd64":
        raise Refused(f"the shipped Cloud member is {architecture}, not amd64")
    return config, architecture


def image_archive(image, run_id, out, platform=RELEASE_PLATFORM):
    """Resolve the index's amd64 member and save it by a run tag."""
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
    config, architecture = shipped_member(out)
    return {
        "image": image,
        "member": member,
        "config": config,
        "member_architecture": architecture,
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
    try:
        info = path.lstat()
    except OSError as error:
        raise Refused(f"hermes_key_file is unreadable: {error.strerror}") from None
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
    remote=REMOTE,
    logs=LOGS,
    home="/home/gateuser",
    key=GUEST_KEY,
    cloud_target="release-gate",
):
    """Cloud's gate alone; its exit and output go under release/cloud/.

    It passes no budget: Cloud's gate sizes itself from the machine it runs on.
    """
    release = logs + "/release"
    if cloud_target not in ("release-gate", "gate"):
        raise ValueError(f"unknown Cloud target {cloud_target!r}")
    cloud_env = [
        f"AWEB_GATE_LEDGER={release}/cloud/ledger.tsv",
        f"AWEB_GATE_LOG_DIR={release}/cloud/gate-logs",
        f"DOCKER_CONFIG={release}/cloud/empty-docker-config",
        # Cloud's journeys run the Hermes journey, which needs its isolated credential.
        f"AC_CANDIDATE_HERMES_ANTHROPIC_KEY_FILE={key}",
    ]
    if cloud_target == "release-gate":
        cloud_env += [
            f"AC_CANDIDATE_RELEASE_IMAGE={image}",
            f"AC_CANDIDATE_RELEASE_IMAGE_ARCHIVE={remote}/cloud-image.tar",
            f"AC_CANDIDATE_RELEASE_IMAGE_MEMBER={member}",
            f"AC_CANDIDATE_AWEB_LOCK_SOURCE_SHA={lock_source_sha}",
        ]
    # A train gate runs every stage on its own head; a release runs release-gate.
    cloud_make = "release-gate" if cloud_target == "release-gate" else "gate GATE_STAGES=all"
    # A gate's candidate is fetched by its own ref, never found by object id:
    # a fetch that keeps only reachable objects would otherwise lose it.
    refs = (
        "refs/heads/main:refs/heads/main"
        if cloud_target == "release-gate"
        else "refs/heads/main:refs/heads/main refs/heads/candidate:refs/heads/candidate"
    )
    checkout = (
        ""
        if cloud_target == "release-gate"
        else "git -C cloud-source checkout --quiet --detach origin/candidate || exit 70"
    )
    image_check = (
        f"echo {Q(archive_sha256 + '  ' + remote + '/cloud-image.tar')} | sha256sum -c - || exit 70"
        if cloud_target == "release-gate"
        else ""
    )
    exports = "export " + " ".join(Q(e) for e in cloud_env)
    return f"""set -u
mkdir -p {Q(release + "/cloud/empty-docker-config")}
{{ uname -m; docker info --format '{{{{.Architecture}}}}'; }} > {Q(release + "/host-architecture")} 2>/dev/null
chmod 0700 {Q(release + "/cloud/empty-docker-config")}
echo {Q(bundle_sha256 + "  " + remote + "/cloud.bundle")} | sha256sum -c - || exit 70
{image_check}
cd {Q(home)}
rm -rf cloud-origin cloud-source
git init --quiet --bare cloud-origin || exit 70
git --git-dir=cloud-origin fetch --quiet {Q(remote + "/cloud.bundle")} {refs} || exit 70
git --git-dir=cloud-origin symbolic-ref HEAD refs/heads/main || exit 70
git clone --quiet cloud-origin cloud-source || exit 70
{checkout}
test "$(git -C cloud-source rev-parse HEAD)" = {Q(cloud_sha)} || exit 70
cd {Q(home + "/cloud-source")}
git config user.name 'aweb release gate'
git config user.email 'release-gate@localhost'
{exports}
make {cloud_make} > {Q(release + "/cloud/gate-output.log")} 2>&1
status=$?
printf '%s\\n' "$status" > {Q(release + "/cloud/exit")}
test "$status" = 0 || exit 1
"""


class ReleaseExecutor(Executor):
    """The guest executor with Cloud's inputs placed before the gate starts."""

    def __init__(self, config, directory, source, command, provider, *, release):
        super().__init__(config, directory, source, command, provider)
        self.release = release

    def prepare(self, server, timeout):
        super().prepare(server, timeout)
        self.upload(self.release["bundle"], REMOTE + "/cloud.bundle", mode="0444")
        if self.release["archive"]:
            self.upload(self.release["archive"], REMOTE + "/cloud-image.tar", mode="0444")
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


# The stages Cloud's full gate records in its summary.tsv
# (scripts/candidate-suite.sh). Preflight writes no row: a failed preflight
# stops the run before any stage row exists. A stage run writes no Cloud ledger
# record, so its receipt is its evidence.
CLOUD_GATE_STAGES = (
    "backend",
    "frontend",
    "image",
    "two-service",
    "cloud-user-journey",
)


def cloud_stage_verdicts(evidence, cloud_sha):
    """Each Cloud stage's verdict, from the gate's own summary in the evidence."""
    verdicts = {}
    for summary in sorted((Path(evidence) / "tmp").glob(f"ac-candidate-gate-{cloud_sha}*/summary.tsv")):
        for line in summary.read_text().splitlines():
            fields = line.split("\t")
            if len(fields) >= 2 and not line.startswith("#"):
                verdicts[fields[0]] = fields[1]
    return {stage: verdicts.get(stage, "MISSING") for stage in CLOUD_GATE_STAGES}


def suite_record(evidence, suite):
    root = Path(evidence) / ("var/log/vm-gate/release/" + suite)
    exit_file = root / "exit"
    value = exit_file.read_text().strip() if exit_file.exists() else ""
    return {
        "exit": int(value) if value.isdigit() else None,
        "evidence": str(root),
    }
