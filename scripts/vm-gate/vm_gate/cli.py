"""CLI admission completes locally before constructing a provider client."""

import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

from . import aweb
from .admission import aweb_requirements
from .config import load, select_manifest, select_target
from .errors import Infrastructure, Refused
from .lifecycle import write_summary
from .source import git, prepare
from .signals import handling


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Refused(message)


def parser():
    p = Parser(prog="vm-gate")
    p.add_argument("--config", default=os.environ.get("VM_GATE_CONFIG"))
    sub = p.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run")
    run.add_argument("--repo", required=True)
    run.add_argument("--sha", required=True)
    work = run.add_mutually_exclusive_group()
    work.add_argument("--stages")
    work.add_argument("--command")
    run.add_argument("--intent", choices=["branch", "train"], default="branch")
    run.add_argument("--type", choices=["ccx33", "ccx43"])
    run.add_argument("--target", choices=["merak", "hetzner"])
    run.add_argument("--timeout", type=int, default=7200)
    rel = sub.add_parser("release")
    rel.add_argument("--machine", required=True)
    rel.add_argument("--cloud-repo", required=True)
    rel.add_argument("--cloud-sha", required=True)
    rel.add_argument("--cloud-image", required=True)
    rel.add_argument("--receipt", required=True)
    rel.add_argument("--aweb-lock-source-sha", required=True)
    rel.add_argument("--aweb-sha")
    rel.add_argument("--files")
    snap = sub.add_parser("snapshot")
    snap.add_argument("--sha", required=True)
    snap.add_argument("--repo")
    sub.add_parser("reap")
    sub.add_parser("status")
    return p


def default_factory(*args, **kwargs):
    from .runtime import Runtime

    return Runtime(*args, **kwargs)


def release_job(args, *, factory=None, out=None):
    """make release's one gate job; every outcome, refusals included, writes the receipt."""
    from functools import partial
    from types import SimpleNamespace

    from . import release

    out = out or sys.stdout
    receipt_path = Path(args.receipt)
    record = {
        "machine": args.machine,
        "cloud": {"sha": args.cloud_sha, "exit": None},
        "vm_gate": {"exit": None, "infrastructure": None, "error": None},
    }
    directory = None
    try:
        if not args.config:
            raise Refused("external --config or VM_GATE_CONFIG is required")
        if (args.aweb_sha is None) != (args.files is None):
            raise Refused(
                "--aweb-sha and --files go together: the files are that commit's build"
            )
        launcher = Path(__file__).resolve().parents[3]
        config = load(args.config, launcher)
        repo = Path(config.get("repo") or launcher).resolve()
        config = load(args.config, repo)
        platform = release.check_machine(args.machine, config)
        machine = config[args.machine]
        timeout = machine.get("release_timeout_seconds")
        if type(timeout) is not int or timeout <= 0:
            raise Refused(
                f"operator config needs {args.machine}.release_timeout_seconds"
            )
        files = release.built_files(args.files)
        key = release.hermes_key(config.get("hermes_key_file"))
        cloud_repo = Path(args.cloud_repo).resolve()
        record.update(release.cloud_main(cloud_repo, args.cloud_sha))
        run_id = "vm-" + uuid.uuid4().hex
        directory = Path(config["state_root"]) / "runs" / run_id
        directory.mkdir(parents=True, mode=0o700)
        target = SimpleNamespace(
            target=args.machine,
            type=machine.get("server_type", "ccx43")
            if args.machine == "hetzner"
            else None,
            stages=None,
            timeout=timeout,
            intent="branch",
        )
        select_target(target, config)
        select_manifest(config, target.target)
        source_sha = args.aweb_sha or args.aweb_lock_source_sha
        source = prepare(
            repo,
            source_sha,
            directory,
            observed=config["manifest"]["observed"],
            intent="branch",
            lock_root=config["state_root"],
        )
        config["repo"] = str(repo)
        bundle = directory / "cloud.bundle"
        bundle_sha256 = release.cloud_bundle(cloud_repo, args.cloud_sha, bundle)
        archive = directory / "cloud-image.tar"
        image = release.image_archive(args.cloud_image, platform, run_id, archive)
        command = release.guest_script(
            cloud_sha=args.cloud_sha,
            bundle_sha256=bundle_sha256,
            archive_sha256=image["archive_sha256"],
            image=args.cloud_image,
            member=image["member"],
            lock_source_sha=args.aweb_lock_source_sha,
            aweb=args.aweb_sha,
            files=files,
        )
        executor = partial(
            release.ReleaseExecutor,
            release={
                "bundle": bundle,
                "archive": archive,
                "files": [Path(args.files) / name for name in files],
                "hermes_key": key,
            },
        )
        runtime = (factory or default_factory)(
            config=config,
            directory=directory,
            source=source,
            command=command,
            args=target,
            run_id=run_id,
            executor_factory=executor,
        )
        with handling():
            result = runtime.run()
        archive.unlink(missing_ok=True)
        record = release.receipt(
            machine=args.machine,
            platform=platform,
            run_id=run_id,
            result=result,
            cloud_sha=args.cloud_sha,
            image=image,
            main={k: record[k] for k in ("real_main", "ac_parent_of_c")},
            files=files,
            aweb=args.aweb_sha,
            launcher_sha=git(launcher, "rev-parse", "HEAD").stdout.strip(),
            timeout=timeout,
            directory=directory,
        )
    except (Refused, Infrastructure) as exc:
        record["vm_gate"].update(
            infrastructure=exc.classification, error=str(exc), exit=int(exc.exit_code)
        )
    code = release.exit_code(record)
    record["exit"] = code
    receipt_path.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record, indent=2), file=out)
    return code


def main(argv=None, *, factory=None, out=None):
    os.umask(0o077)
    out = out or sys.stdout
    directory = None
    sha = None
    try:
        args = parser().parse_args(argv)
        if args.action == "release":
            return release_job(args, factory=factory, out=out)
        if not args.config:
            raise Refused("external --config or VM_GATE_CONFIG is required")
        if os.geteuid() == 0:
            raise Refused("UID 0 refused at operator admission")
        repo = Path(
            getattr(args, "repo", None) or Path(__file__).resolve().parents[3]
        ).resolve()
        config = load(args.config, repo)
        if getattr(args, "repo", None) is None and config.get("repo"):
            repo = Path(config["repo"]).resolve()
            config = load(args.config, repo)
        if args.action in {"run", "snapshot"}:
            sha = args.sha
            run_id = "vm-" + uuid.uuid4().hex
            directory = Path(config["state_root"]) / "runs" / run_id
            directory.mkdir(parents=True, mode=0o700)
            if args.action == "run":
                select_target(args, config)
                select_manifest(config, args.target)
                if args.timeout <= 0:
                    raise Refused("timeout must be positive")
                invocation = aweb.command(
                    stages=args.stages, focused=args.command, intent=args.intent
                )
                observed = config["manifest"]["observed"]
                intent = args.intent
            else:
                invocation = None
                intent = "branch"
                observed = aweb_requirements(
                    git(repo, "show", sha + ":cli/go/go.mod").stdout,
                    git(repo, "show", sha + ":candidate-gate/Dockerfile").stdout,
                    sha,
                )
            source = prepare(
                repo,
                sha,
                directory,
                observed=observed,
                intent=intent,
                lock_root=config["state_root"],
            )
            config["repo"] = str(repo)
        else:
            run_id = None
            source = None
            invocation = None
        runtime = (factory or default_factory)(
            config=config,
            directory=directory,
            source=source,
            command=invocation,
            args=args,
            run_id=run_id,
        )
        with handling():
            result = getattr(runtime, args.action)()
        if directory is not None:
            write_summary(directory, result)
        if result.get("spend", {}).get("warn"):
            print(
                "vm-gate: WARNING: daily spend and outstanding reservations reached EUR 20",
                file=sys.stderr,
            )
        print(json.dumps(result, indent=2), file=out)
        return int(result.get("exit", 0))
    except BaseException as exc:
        if isinstance(exc, SystemExit):
            raise
        known = isinstance(exc, (Refused, Infrastructure))
        result = {
            "sha": sha,
            "exit": int(exc.exit_code) if known else 70,
            "infrastructure": exc.classification if known else "infrastructure",
            "error": str(exc) if known else type(exc).__name__,
            "finished": time.time(),
        }
        if directory is not None:
            write_summary(directory, result)
        print(json.dumps(result, indent=2), file=out)
        return result["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
