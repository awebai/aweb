"""Command line for a naapp's Render production operations.

    python -m aweb_naapp.ops [--config FILE] [--env-file FILE] COMMAND

status and verify only read. deploy and rollback mutate the service and require
--apply plus the exact service ID. Each prints one JSON result.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from aweb_naapp.ops import render


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m aweb_naapp.ops", description=__doc__)
    p.add_argument("--config", default=os.environ.get("PROD_CONFIG", "ops/render-production.json"))
    p.add_argument("--env-file", default=os.environ.get("RENDER_ENV_FILE", "~/.aweb-render/env"))
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    deploy = sub.add_parser("deploy")
    deploy.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    deploy.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    deploy.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    deploy.add_argument("--repo-root", default=".")
    deploy.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    deploy.add_argument("--timeout", type=int, default=900)
    deploy.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    wait = sub.add_parser("wait")
    wait.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    wait.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    wait.add_argument("--timeout", type=int, default=900)
    verify = sub.add_parser("verify")
    verify.add_argument("--deploy-id", default=os.environ.get("PROD_DEPLOY_ID", ""))
    verify.add_argument("--commit", default=os.environ.get("PROD_COMMIT", ""))
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--rollback-deploy-id", default=os.environ.get("ROLLBACK_DEPLOY_ID", ""))
    rollback.add_argument("--rollback-commit", default=os.environ.get("ROLLBACK_COMMIT", ""))
    rollback.add_argument("--current-deploy-id", default=os.environ.get("CURRENT_DEPLOY_ID", ""))
    rollback.add_argument("--current-commit", default=os.environ.get("CURRENT_COMMIT", ""))
    rollback.add_argument("--confirm-service-id", default=os.environ.get("CONFIRM_SERVICE_ID", ""))
    rollback.add_argument("--timeout", type=int, default=900)
    rollback.add_argument("--apply", action="store_true", default=os.environ.get("APPLY") == "1")
    return p


def run(args: argparse.Namespace) -> dict:
    config = render.ProductionConfig.load(Path(args.config))
    if args.command in {"deploy", "rollback"}:
        render.confirm_apply(config, apply=args.apply, confirm_service_id=args.confirm_service_id)
    if getattr(args, "timeout", 1) <= 0:
        raise render.OpsError("timeout must be positive")
    client = render.RenderClient(render.load_api_key(Path(args.env_file).expanduser()))
    if args.command == "status":
        return render.status(client, config)
    if args.command == "deploy":
        return render.deploy(
            client,
            config,
            commit=args.commit,
            rollback_deploy_id=args.rollback_deploy_id,
            rollback_commit=args.rollback_commit,
            repo_root=Path(args.repo_root),
            timeout_seconds=args.timeout,
        )
    if args.command == "wait":
        return render.wait(
            client, config, deploy_id=args.deploy_id, commit=args.commit, timeout_seconds=args.timeout
        )
    if args.command == "verify":
        return render.verify(client, config, deploy_id=args.deploy_id, commit=args.commit)
    return render.rollback(
        client,
        config,
        rollback_deploy_id=args.rollback_deploy_id,
        rollback_commit=args.rollback_commit,
        current_deploy_id=args.current_deploy_id,
        current_commit=args.current_commit,
        timeout_seconds=args.timeout,
    )


def main() -> int:
    args = parser().parse_args()
    try:
        result = run(args)
    except render.OpsError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
