"""Local operator commands. The application never receives this private mount."""

import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from pathlib import Path

from approval_service.canonical import InvalidJSON
from approval_service.verify import Refused as ApprovalRefused
from awid.registry import RegistryError
from jsonschema import ValidationError

from .keys import KeyStore, Refused


async def operate(args, parser):
    from approval_service.canonical import parse
    from approval_service.grading import EnrollmentGrading
    from awid.controller_signing import parse_controller_request
    from awid.registry import RegistryClient

    from .enrollment import Holder

    if not all((args.registry_origin, args.origin)):
        parser.error("runtime commands require --registry-origin and --origin")
    configured = any((args.approval_origin, args.rp_id, args.grading))
    if configured and not all((args.approval_origin, args.rp_id, args.grading)):
        parser.error(
            "approval configuration requires --approval-origin, --rp-id and --grading"
        )
    if args.grading == "hardware" and args.mds_cache is None:
        parser.error("hardware grading requires --mds-cache")
    store = KeyStore.open(args.state)

    async def pinned(domain):
        if domain != store.descriptor().domain:
            raise Refused("organisation_mismatch")
        return args.registry_origin

    registry = RegistryClient(args.registry_origin, domain_registry_resolver=pinned)
    grading = (
        EnrollmentGrading.load(
            mode=args.grading, cache_dir=args.mds_cache, manifest_path=args.mds_manifest
        )
        if configured
        else None
    )
    holder = Holder(
        store,
        registry=registry,
        origin=args.origin,
        approval_origin=args.approval_origin,
        rp_id=args.rp_id,
        grading=grading,
    )

    def body():
        return parse(sys.stdin.buffer.read(4 * 1024 * 1024 + 1))

    try:
        if args.command == "serve":
            import uvicorn

            from .http import create_app

            config = uvicorn.Config(
                create_app(holder),
                host=args.bind,
                port=args.port,
                access_log=False,
                proxy_headers=False,
                limit_concurrency=64,
                ssl_certfile=args.tls_cert,
                ssl_keyfile=args.tls_key,
            )
            await uvicorn.Server(config).serve()
            return None
        if args.command == "issue-person":
            return await holder.issue_person(args.person, args.identity_key)
        if args.command == "bootstrap":
            holder.require_approval()
            return await holder.bootstrap(args.person, args.identity_key)
        request = parse_controller_request(body())
        if request.domain != store.descriptor().domain:
            raise Refused("organisation_mismatch")
        return await registry.controller_request(
            request,
            controllers={"controller": store.descriptor(team=args.team)},
            signer=lambda context: store.sign_controller(context, actor="operator"),
        )
    finally:
        await registry.aclose()


def main():
    parser = argparse.ArgumentParser(prog="aweb-key-holder")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--registry-origin")
    parser.add_argument("--origin")
    parser.add_argument("--approval-origin")
    parser.add_argument("--rp-id")
    parser.add_argument("--grading", choices=("passkey_only", "hardware"))
    parser.add_argument("--mds-cache", type=Path)
    parser.add_argument("--mds-manifest", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--organisation", required=True)
    descriptor = commands.add_parser("descriptor")
    descriptor.add_argument("--team")
    team = commands.add_parser("create-team-key")
    team.add_argument("name")
    backup = commands.add_parser("backup")
    backup.add_argument("--offline-public-key", required=True)
    commands.add_parser("migrate")
    configure = commands.add_parser("configure")
    configure.add_argument(
        "--human-issuance", choices=("operator", "approved"), required=True
    )
    issue = commands.add_parser("issue-person")
    issue.add_argument("--person", required=True)
    issue.add_argument("--identity-key", required=True)
    service = commands.add_parser("serve")
    service.add_argument("--bind", default="127.0.0.1")
    service.add_argument("--port", default=8081, type=int)
    service.add_argument("--tls-cert")
    service.add_argument("--tls-key")
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--person", required=True)
    bootstrap.add_argument("--identity-key", required=True)
    registry = commands.add_parser("registry")
    registry.add_argument("--team")
    args = parser.parse_args()
    try:
        if args.command == "init":
            result = asdict(
                KeyStore.create(args.state, organisation=args.organisation).descriptor()
            )
        elif args.command == "configure":
            store = KeyStore.open(args.state)
            store.set_human_issuance(args.human_issuance)
            result = {"human_issuance": store.human_issuance()}
        elif args.command == "migrate":
            KeyStore(args.state).migrate()
            result = {"state": "migrated"}
        elif args.command in {"descriptor", "create-team-key", "backup"}:
            store = KeyStore.open(args.state)
            if args.command == "descriptor":
                result = asdict(store.descriptor(team=args.team))
            elif args.command == "create-team-key":
                result = asdict(store.create_team_key(args.name))
            else:
                sys.stdout.buffer.write(
                    store.encrypted_backup(bytes.fromhex(args.offline_public_key))
                )
                return
        else:
            result = asyncio.run(operate(args, parser))
        if result is not None:
            print(json.dumps(result, separators=(",", ":")))
    except (Refused, ApprovalRefused) as error:
        print(json.dumps({"error": error.code}), file=sys.stderr)
        raise SystemExit(1) from None
    except (InvalidJSON, ValidationError):
        print(json.dumps({"error": "request_invalid"}), file=sys.stderr)
        raise SystemExit(1) from None
    except RegistryError as error:
        print(
            json.dumps(
                {"error": error.code or "registry_error", "status": error.status_code}
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
