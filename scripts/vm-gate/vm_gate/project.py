"""One project's full gate for its release command, with one flat receipt.

`vm-gate run --project aweb|ac --repo PATH --sha S --intent train --machine M
--receipt R` runs one suite on one machine:

- aweb: aweb's candidate gate at S, a fast-forward of aweb's main, from the
  local checkout, with S as the guest's main (branch scope), since S lands
  only after this gate. With --files, the release command's built files go into
  the guest; the gate installs their server wheel under test, and after the
  gate the guest rebuilds them from S. Green needs the suite green, the
  rebuild equal to the files and each server container holding the wheel.
- ac: Cloud's gate at S from the local checkout, shipped as a bundle. With
  --image (the image index) the controller resolves its amd64 member and the
  guest runs `make release-gate` on that member with the index as its release
  image, with --aweb-source as the aweb commit its journeys build; without
  it, `make gate GATE_STAGES=all`. The commit Cloud's gate built is the
  aweb-built-head line of its own inputs.tsv (git rev-parse HEAD of the tree
  its journeys built), never the input copied. Either way green needs every
  stage PASSED in Cloud's own summary.tsv; a missing row is red.

Every outcome, refusals included, writes the receipt. Every digest in it is
sha256:<hex>.
"""

import json
import re
import sys
import uuid
from functools import partial
from pathlib import Path
from types import SimpleNamespace

from . import release
from .config import load, select_manifest, select_target
from .errors import Infrastructure, Refused
from .executor import LOGS, Executor
from .release import GUEST_FILES, Q
from .signals import handling
from .source import git, prepare

PROJECTS = ("aweb", "ac")
SHA = re.compile(r"[0-9a-f]{40}")
GREEN, RED, REFUSED, INFRASTRUCTURE = 0, 1, 2, 70


def prefixed(files):
    """The launcher's bare hex digests, as every receipt field carries them."""
    return {name: "sha256:" + digest for name, digest in files.items()}


def admit(args):
    """Refuse before any machine is touched unless the request is one of the two shapes."""
    if args.intent != "train":
        raise Refused("a project receipt is a full gate: pass --intent train")
    if args.stages or args.command or args.target or args.type:
        raise Refused("--project runs the full gate on --machine: drop --stages, --command, --target and --type")
    if not args.machine:
        raise Refused("--project needs --machine")
    if not SHA.fullmatch(args.sha):
        raise Refused("--sha must be a full lowercase commit SHA")
    if args.project == "aweb":
        if args.image or args.aweb_source:
            raise Refused("--image and --aweb-source are Cloud's inputs, not aweb's")
    else:
        if args.files:
            raise Refused("--files is aweb's input: Cloud installs aweb from PyPI per its lock")
        if args.image and not release.IMAGE.fullmatch(args.image):
            raise Refused("--image must be <repository>@sha256:<index>")
        if args.image and not args.aweb_source:
            raise Refused("--image needs --aweb-source, the aweb commit the journeys build")
        if args.aweb_source and not SHA.fullmatch(args.aweb_source):
            raise Refused("--aweb-source must be a full lowercase commit SHA")


def aweb_script(sha, files, *, logs=LOGS, files_dir=GUEST_FILES):
    """aweb's gate at S, then a rebuild of the files from S; the suite's exit is kept apart."""
    suite = logs + "/release/aweb"
    projects = sorted(
        {
            release.AWEB_PROJECTS[prefix]
            for name in files
            for prefix in release.AWEB_PROJECTS
            if name.startswith(prefix)
        }
    )
    rebuild = "\n".join(
        f"uv build --quiet --wheel --sdist --out-dir {Q(suite + '/rebuilt')} {Q(project)} || status=1"
        for project in projects
    )
    exports = f"export AWEB_CANDIDATE_RELEASE_FILES={Q(files_dir)}\n" if files else ""
    return f"""set -u
mkdir -p {Q(suite + "/rebuilt")}
{{ uname -m; docker info --format '{{{{.Architecture}}}}'; }} > {Q(logs + "/release/host-architecture")} 2>/dev/null
test "$(git rev-parse HEAD)" = {Q(sha)} || exit 70
{exports}make candidate-gate > {Q(suite + "/gate-output.log")} 2>&1
status=$?
printf '%s\\n' "$status" > {Q(suite + "/exit")}
{rebuild}
python3 -c 'import hashlib, json, pathlib, sys; d = pathlib.Path(sys.argv[1]); print(json.dumps({{p.name: "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(d.iterdir())}}, sort_keys=True))' {Q(suite + "/rebuilt")} > {Q(suite + "/rebuilt.json")}
exit "$status"
"""


class FilesExecutor(Executor):
    """The guest executor with the release command's built files placed before the gate."""

    def __init__(self, config, directory, source, command, provider, *, files):
        super().__init__(config, directory, source, command, provider)
        self.files = files

    def prepare(self, server, timeout):
        super().prepare(server, timeout)
        self.run(f"install -d -m 0755 -o root -g root {GUEST_FILES}", "release-files-directory")
        for path in self.files:
            self.upload(path, GUEST_FILES + "/" + Path(path).name, mode="0444")


def at_most_one(paths, what):
    """The path a run produced, or None. A green suite without it is red: the proof did not run."""
    if len(paths) > 1:
        raise Infrastructure(f"the run holds {len(paths)} {what}, not one")
    return paths[0] if paths else None


def installed_wheels(evidence, sha):
    """What each server container held, as the journey read it inside the container."""
    path = at_most_one(
        sorted((Path(evidence) / "tmp").glob(f"aweb-candidate-gate-{sha}-*/release-wheels.json")),
        "release wheel records",
    )
    return json.loads(path.read_text()) if path else None


def cloud_inputs(evidence, sha):
    """Cloud's gate's own record: the HEAD of the aweb tree its journeys built, and the locked tag.

    Only the aweb-built-head line counts as built; the lock-source line is the input."""
    path = at_most_one(
        sorted((Path(evidence) / "tmp").glob(f"ac-candidate-gate-{sha}*/inputs.tsv")),
        "Cloud gate input records",
    )
    if path is None:
        return None, None
    rows = dict(line.split("\t", 1) for line in path.read_text().splitlines() if "\t" in line)
    return rows.get("aweb-built-head"), rows.get("aweb-lock-tag")


def exit_code(record):
    """Green only when the suite passed and everything the receipt checks holds."""
    classification = record["vm_gate"]["infrastructure"]
    if classification == "refused":
        return REFUSED
    if classification is not None or record.get("suite_exit") is None:
        return INFRASTRUCTURE
    if record["suite_exit"] != 0:
        return RED
    if record["project"] == "aweb" and record.get("files"):
        if record.get("rebuilt_files") != record["files"]:
            return RED
        wheels = record.get("installed_wheels") or {}
        for service in ("aweb-alpha", "aweb-beta"):
            server = wheels.get(service) or {}
            name = server.get("wheel")
            if not (name and name.endswith(".whl") and name in record["files"]):
                return RED
            if server.get("container_wheel_sha256") != record["files"][name]:
                return RED
    if record["project"] == "ac":
        if record.get("aweb_source") and record.get("aweb_source_built") != record["aweb_source"]:
            return RED
        stages = record.get("stages")
        if stages is not None and any(verdict != "PASSED" for verdict in stages.values()):
            return RED
    return GREEN


def project_job(args, *, factory=None, out=None):
    out = out or sys.stdout
    launcher = Path(__file__).resolve().parents[3]
    record = {
        "project": args.project,
        "sha": args.sha,
        "intent": args.intent,
        "machine": args.machine,
        "command": None,
        "suite_exit": None,
        "evidence": None,
        "vm_gate": {"exit": None, "infrastructure": None, "error": None},
    }
    try:
        admit(args)
        if not args.config:
            raise Refused("external --config or VM_GATE_CONFIG is required")
        repo = Path(args.repo).resolve()
        if args.project == "aweb":
            config = load(args.config, repo)
        else:
            # Cloud's guest takes its aweb source from the operator's aweb repository.
            config = load(args.config, launcher)
            config = load(args.config, Path(config.get("repo") or launcher).resolve())
        platform, backend = release.check_machine(args.machine, config)
        machine = config[args.machine]
        timeout = machine.get("release_timeout_seconds")
        if type(timeout) is not int or timeout <= 0:
            raise Refused(f"operator config needs {args.machine}.release_timeout_seconds")
        if backend == "native":
            if args.project == "aweb":
                raise Refused(f"aweb's release gate runs in a guest; {args.machine} is native")
            if not machine.get("root"):
                raise Refused(f"operator config needs {args.machine}.root for its jobs")
        files = release.built_files(args.files)
        record.update(machine_platform=platform, timeout_seconds=timeout)
        target = key = None
        if args.project == "aweb":
            record.update(files=prefixed(files), command="make candidate-gate")
        else:
            key = release.hermes_key(config.get("hermes_key_file"))
            record.update(release.cloud_main(repo, args.sha, gate=not args.image))
            record["command"] = "make release-gate" if args.image else "make gate GATE_STAGES=all"
            record["aweb_source"] = args.aweb_source
        run_id = "vm-" + uuid.uuid4().hex
        record["run_id"] = run_id
        directory = Path(config["state_root"]) / "runs" / run_id
        directory.mkdir(parents=True, mode=0o700)
        if backend != "native":
            target = SimpleNamespace(
                target=backend,
                type=machine.get("server_type", "ccx43") if backend == "hetzner" else None,
                stages=None,
                timeout=timeout,
                intent=args.intent,
            )
            select_target(target, config)
            select_manifest(config, target.target)
        if args.project == "aweb":
            # Branch scope makes S the guest's main, as the release job's aweb
            # suite has it: the full gate refuses a head off the guest's main,
            # and S lands only after this gate. Landing unchanged needs S to be
            # a fast-forward of real main, checked here before boot.
            source = prepare(
                repo,
                args.sha,
                directory,
                observed=config["manifest"]["observed"],
                intent="branch",
                lock_root=config["state_root"],
            )
            if not source["main_is_ancestor"]:
                raise Refused(
                    f"origin/main {source['real_main']} is not in {args.sha}'s history: "
                    "S must land unchanged as a fast-forward"
                )
            record["source_scope"] = source["scope"]
            config["repo"] = str(repo)
            runtime = (factory or release_runtime_factory())(
                config=config,
                directory=directory,
                source=source,
                command=aweb_script(args.sha, files),
                args=target,
                run_id=run_id,
                executor_factory=partial(FilesExecutor, files=[Path(args.files) / name for name in files]),
            )
        else:
            runtime, image = cloud_runtime(
                args, config, backend, machine, target, directory, run_id, key, launcher, timeout, factory
            )
            if image:
                # Every digest in the receipt is the bare sha256:<hex>: the
                # index's digest, not the reference it was named by.
                record["image"] = {
                    "index": release.IMAGE.fullmatch(image["image"])["index"],
                    **{k: image[k] for k in ("member", "config", "member_architecture")},
                }
        with handling():
            result = runtime.run()
        (directory / "cloud-image.tar").unlink(missing_ok=True)
        evidence = directory / "evidence"
        record["evidence"] = str(evidence)
        record["vm_gate"].update(
            exit=result.get("exit"),
            infrastructure=result.get("infrastructure"),
            error=result.get("error"),
            summary=str(directory / "summary.json"),
        )
        record["launcher_sha"] = git(launcher, "rev-parse", "HEAD").stdout.strip()
        architecture = evidence / "var/log/vm-gate/release/host-architecture"
        record["host_architecture"] = architecture.read_text().split() if architecture.exists() else None
        suite = release.suite_record(evidence, "aweb" if args.project == "aweb" else "cloud")
        record["suite_exit"] = suite["exit"]
        if args.project == "aweb":
            rebuilt = evidence / "var/log/vm-gate/release/aweb/rebuilt.json"
            # The builder leaves its own markers (.gitignore) beside the files;
            # only the shipped names are compared, and a missing one is red.
            record["rebuilt_files"] = (
                {name: digest for name, digest in json.loads(rebuilt.read_text()).items() if name in files}
                if rebuilt.exists()
                else None
            )
            record["ledger_rows_imported"] = result.get("ledger_rows_imported")
            if files and suite["exit"] == 0:
                record["installed_wheels"] = installed_wheels(evidence, args.sha)
        else:
            if args.image and suite["exit"] == 0:
                record["aweb_source_built"], record["aweb_source_tag"] = cloud_inputs(evidence, args.sha)
            # Both Cloud gates are green only when their own summary shows every
            # stage PASSED; a missing row reads MISSING and is red.
            record["stages"] = release.cloud_stage_verdicts(evidence, args.sha)
    except (Refused, Infrastructure) as exc:
        record["vm_gate"].update(infrastructure=exc.classification, error=str(exc), exit=int(exc.exit_code))
    code = exit_code(record)
    record["exit"] = code
    Path(args.receipt).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2), file=out)
    return code


def release_runtime_factory():
    from .runtime import Runtime

    return Runtime


def cloud_runtime(args, config, backend, machine, target, directory, run_id, key, launcher, timeout, factory):
    """Cloud's suite alone: its bundle, its image when a release, and the Hermes key."""
    aweb_repo = Path(config.get("repo") or launcher).resolve()
    source_sha = args.aweb_source or git(aweb_repo, "rev-parse", "HEAD").stdout.strip()
    if backend == "native":
        from .admission import aweb_requirements

        observed = aweb_requirements(
            git(aweb_repo, "show", source_sha + ":cli/go/go.mod").stdout,
            git(aweb_repo, "show", source_sha + ":candidate-gate/Dockerfile").stdout,
            source_sha,
        )
    else:
        observed = config["manifest"]["observed"]
    source = prepare(
        aweb_repo, source_sha, directory, observed=observed, intent="branch", lock_root=config["state_root"]
    )
    config["repo"] = str(aweb_repo)
    repo = Path(args.repo).resolve()
    bundle = directory / "cloud.bundle"
    gate_only = not args.image
    real_main = git(repo, "rev-parse", "refs/remotes/origin/main^{commit}").stdout.strip()
    bundle_sha256 = release.cloud_bundle(repo, args.sha, bundle, main=real_main if gate_only else None)
    archive = None if gate_only else directory / "cloud-image.tar"
    # Cloud's gate proves the index and its amd64 member separately: the guest
    # gets the index as its release image and runs the member resolved here.
    image = None if gate_only else release.image_archive(args.image, run_id, archive)
    script = partial(
        release.guest_script,
        cloud_sha=args.sha,
        bundle_sha256=bundle_sha256,
        archive_sha256=image and image["archive_sha256"],
        image=args.image,
        member=image and image["member"],
        lock_source_sha=args.aweb_source,
        cloud_target="gate" if gate_only else "release-gate",
    )
    inputs = {"bundle": bundle, "archive": archive, "hermes_key": key}
    if backend == "native":
        from .native import NativeRuntime

        runtime = (factory or NativeRuntime)(
            config=config,
            directory=directory,
            source=source,
            script=lambda job: script(
                remote=job,
                logs=job + "/logs",
                home=job + "/home",
                key=job + "/hermes-key",
            ),
            machine=machine,
            inputs=inputs,
            timeout=timeout,
        )
    else:
        runtime = (factory or release_runtime_factory())(
            config=config,
            directory=directory,
            source=source,
            command=script(),
            args=target,
            run_id=run_id,
            executor_factory=partial(release.ReleaseExecutor, release=inputs),
        )
    return runtime, image
