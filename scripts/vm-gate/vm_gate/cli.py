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
    # A project receipt: one project's full gate for its release command.
    run.add_argument("--project", choices=["aweb", "ac", "servers"])
    run.add_argument("--machine")
    run.add_argument("--receipt")
    run.add_argument("--files")
    run.add_argument("--image")
    run.add_argument("--aweb-source")
    run.add_argument("--steps")
    snap = sub.add_parser("snapshot")
    snap.add_argument("--sha", required=True)
    snap.add_argument("--repo")
    sub.add_parser("reap")
    sub.add_parser("status")
    return p


def default_factory(*args, **kwargs):
    from .runtime import Runtime

    return Runtime(*args, **kwargs)


def main(argv=None, *, factory=None, out=None):
    os.umask(0o077)
    out = out or sys.stdout
    directory = None
    sha = None
    try:
        args = parser().parse_args(argv)
        if args.action == "run" and (args.project or args.receipt):
            if not (args.project and args.receipt):
                raise Refused("--project and --receipt go together")
            from .project import project_job

            return project_job(args, factory=factory, out=out)
        if args.action == "run" and (
            args.machine or args.files or args.image or args.aweb_source or args.steps
        ):
            raise Refused(
                "--machine, --files, --image, --aweb-source and --steps need --project"
            )
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
