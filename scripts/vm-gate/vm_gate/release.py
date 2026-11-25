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
# A release qualifies the amd64 image that production runs, on every host:
# an arm64 host runs that same member under its amd64 emulation (Rosetta).
RELEASE_PLATFORM = "linux/amd64"
# merak and hetzner boot a guest; native runs on the host's own Docker.
BACKENDS = ("merak", "hetzner", "native")
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


def gate_weights(path=None):
    """Each gate's measured CPU-seconds, from candidate-gate/measured-work.json.

    aweb's weight is the sum of its lanes there; Cloud's is the figure that
    file names by its receipt.
    """
    path = path or Path(__file__).resolve().parents[3] / "candidate-gate/measured-work.json"
    work = json.loads(Path(path).read_text())
    cloud = work.get("gates", {}).get("cloud", {}).get("cpu_seconds")
    if type(cloud) is not int or cloud < 1:
        raise Refused("measured-work.json names no measured Cloud gate CPU-seconds")
    return {"aweb": sum(work["lanes"].values()), "cloud": cloud}


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
    weights=None,
    cloud_target="release-gate",
):
    """Both suites in parallel; each writes its exit and output under release/.

    weights are the gates' measured CPU-seconds (gate_weights); the guest
    divides its own measured capacity by them.
    """
    weights = weights or gate_weights()
    if not aweb:
        weights = {"cloud": weights["cloud"]}
    release = logs + "/release"
    if cloud_target not in ("release-gate", "gate"):
        raise ValueError(f"unknown Cloud target {cloud_target!r}")
    cloud_env = [
        f"AWEB_GATE_LEDGER={release}/cloud/ledger.tsv",
        f"AWEB_GATE_LOG_DIR={release}/cloud/gate-logs",
        f"DOCKER_CONFIG={release}/cloud/empty-docker-config",
        # Both jobs run the Hermes journey, which needs its isolated credential.
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
    if files:
        cloud_env += [
            f"AC_CANDIDATE_AWEB_WHEELS={files_dir}",
            f"AC_CANDIDATE_AWEB_WHEELS_SOURCE_SHA={aweb}",
        ]
    exports = (
        "export "
        + " ".join(Q(e) for e in cloud_env)
        + ' GATE_CPUS="$cloud_cpus" GATE_MEMORY_MIB="$cloud_memory"'
    )
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
  GATE_CPUS="$aweb_cpus" GATE_MEMORY_MIB="$aweb_memory" make candidate-gate > {Q(release + "/aweb/gate-output.log")} 2>&1
  printf '%s\\n' "$?" > {Q(release + "/aweb/exit")}
  mkdir -p {Q(release + "/aweb/rebuilt")}
{rebuild}
  python3 -c 'import hashlib, json, pathlib, sys; d = pathlib.Path(sys.argv[1]); print(json.dumps({{p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.iterdir())}}, sort_keys=True))' {Q(release + "/aweb/rebuilt")} > {Q(release + "/aweb/rebuilt.json")}
) > {Q(release + "/aweb/suite.log")} 2>&1 &
aweb_suite=$!
"""
    return f"""set -u
mkdir -p {Q(release + "/aweb")} {Q(release + "/cloud/empty-docker-config")}
{{ uname -m; docker info --format '{{{{.Architecture}}}}'; }} > {Q(release + "/host-architecture")} 2>/dev/null
chmod 0700 {Q(release + "/cloud/empty-docker-config")}
read -r cloud_cpus cloud_memory aweb_cpus aweb_memory < <(python3 -m vm_gate.budget split {Q(release + "/split.json")} {" ".join(Q(f"{gate}={weight}") for gate, weight in sorted(weights.items()))}) || exit 70
test -n "$cloud_cpus" || exit 70
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
{aweb_suite}
(
  cd {Q(home + "/cloud-source")}
  git config user.name 'aweb release gate'
  git config user.email 'release-gate@localhost'
  {exports}
  make {cloud_make} > {Q(release + "/cloud/gate-output.log")} 2>&1
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
        if self.release["archive"]:
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
    cloud = {"sha": cloud_sha, **suite_record(evidence, "cloud")}
    if image:
        cloud.update(
            image=image["image"],
            member=image["member"],
            config=image["config"],
            member_architecture=image.get("member_architecture"),
            command="make release-gate",
        )
    else:
        cloud["command"] = "make gate GATE_STAGES=all"
        cloud["stages"] = cloud_stage_verdicts(evidence, cloud_sha)
    architecture = evidence / "var/log/vm-gate/release/host-architecture"
    split_path = evidence / "var/log/vm-gate/release/split.json"
    split = json.loads(split_path.read_text()) if split_path.exists() else None
    record = {
        "machine": machine,
        "machine_platform": platform,
        "host_architecture": (
            architecture.read_text().split() if architecture.exists() else None
        ),
        "run_id": run_id,
        "launcher_sha": launcher_sha,
        "timeout_seconds": timeout,
        "files": files,
        "split": split,
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
    """Green only when every suite passed, aweb rebuilt the exact files and,
    for a Cloud gate, every Cloud stage shows PASSED in its summary."""
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
    # A Cloud gate is green only when its own summary shows every stage passed.
    stages = record["cloud"].get("stages")
    if stages is not None and any(v != "PASSED" for v in stages.values()):
        return RED
    return GREEN

