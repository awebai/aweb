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
from .config import load
from .errors import Infrastructure, Refused
from .lifecycle import write_summary
from .source import git, prepare
from .signals import handling
from .local_guard import run_guard


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
    run.add_argument("--type", choices=["ccx33", "ccx43", "cax21"], default="ccx33")
    run.add_argument("--timeout", type=int, default=7200)
    archive = run.add_mutually_exclusive_group()
    archive.add_argument(
        "--archive-in", help="retained x86 archive, never rebuilt on ARM"
    )
    archive.add_argument(
        "--archive-out",
        action="store_true",
        help="collect /evidence/server.oci.tar before deletion",
    )
    run.add_argument(
        "--amd64-receipt", help="successful native x86 JSON receipt for --archive-in"
    )
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
    local_checks = None
    try:
        args = parser().parse_args(argv)
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
                if args.timeout <= 0:
                    raise Refused("timeout must be positive")
                invocation = aweb.command(
                    stages=args.stages, focused=args.command, intent=args.intent
                )
                native = config.get("host_profile") == "native-arm64-oci-v1"
                if native:
                    if (
                        args.type != "cax21"
                        or not args.archive_in
                        or not args.amd64_receipt
                        or args.command != "make test-server-image-build"
                        or args.stages
                        or args.intent != "branch"
                        or args.timeout > 900
                    ):
                        raise Refused(
                            "native ARM profile requires CAX21, archive input and x86 receipt for focused image qualification"
                        )
                    from .native_oci import verify_archive

                    try:
                        config["amd64_receipt"] = json.loads(
                            Path(args.amd64_receipt).read_text()
                        )
                    except (OSError, ValueError):
                        raise Refused("x86 native receipt is unavailable") from None
                    config["archive_in"] = str(Path(args.archive_in).resolve())
                    verify_archive(args.archive_in, config["amd64_receipt"])
                elif args.type == "cax21" or args.archive_in or args.amd64_receipt:
                    raise Refused(
                        "CAX21/archive input requires the distinct native ARM profile"
                    )
                if args.archive_out:
                    if (
                        args.command != "make test-server-image-build"
                        or args.stages
                        or args.intent != "branch"
                    ):
                        raise Refused(
                            "archive output requires focused native image qualification"
                        )
                    config["archive_out"] = True
                observed = config["manifest"].get("observed", {})
                intent = args.intent
            else:
                if config.get("host_profile") == "native-arm64-oci-v1":
                    raise Refused("native ARM profile cannot rebuild a snapshot")
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
                host_profile=config.get("host_profile", "snapshot"),
            )
            if args.action == "run":
                local_checks = run_guard(
                    source, directory, config.get("lint_timeout_seconds", 600)
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
            result["local_checks"] = local_checks
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
            "local_checks": getattr(exc, "local_checks", local_checks),
        }
        if directory is not None:
            write_summary(directory, result)
        print(json.dumps(result, indent=2), file=out)
        return result["exit"]


if __name__ == "__main__":
    raise SystemExit(main())
