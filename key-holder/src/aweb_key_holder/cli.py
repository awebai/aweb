"""Local operator commands. The application never receives this private mount."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import asdict
from enum import StrEnum
from pathlib import Path
from urllib.parse import urlsplit

from approval_service.canonical import InvalidJSON
from approval_service.verify import Refused as ApprovalRefused
from awid.registry import RegistryError
from jsonschema import ValidationError

from .enrollment import HolderAnswer, WireObject
from .keys import AuditEntry, KeyStore, RetiredPerson
from .refusals import Refusal, Refused, describe_refusal


class OperatorCommand(StrEnum):
    """Closed private operator commands; no HTTP command grants custody."""

    INIT = "init"
    DESCRIPTOR = "descriptor"
    CREATE_TEAM_KEY = "create-team-key"
    BACKUP = "backup"
    MIGRATE = "migrate"
    AUDIT = "audit"
    RETIRE_PERSON = "retire-person"
    ISSUE_PERSON = "issue-person"
    SERVE = "serve"
    BOOTSTRAP = "bootstrap"
    REGISTRY = "registry"


async def operate(
    args: argparse.Namespace, parser: argparse.ArgumentParser
) -> HolderAnswer | None:
    """Run a configured runtime command; registry authority stays pinned."""
    from approval_service.canonical import parse
    from approval_service.grading import EnrollmentGrading
    from awid.controller_signing import parse_controller_request
    from awid.registry import RegistryClient

    from .enrollment import Holder

    if not all((args.registry_origin, args.origin)):
        parser.error("runtime commands require --registry-origin and --origin")
    store = KeyStore.open(args.state)
    if args.human_approval_config is not None:
        from approval_service.gate import load_policy

        policy = load_policy(
            args.human_approval_config, organisation=store.descriptor().domain
        )
        if policy.service is not None:
            args.approval_origin = args.approval_origin or policy.service
            args.rp_id = args.rp_id or urlsplit(policy.service).hostname
            args.grading = args.grading or "passkey_only"
    configured = any((args.approval_origin, args.rp_id, args.grading))
    if configured and not all((args.approval_origin, args.rp_id, args.grading)):
        parser.error(
            "approval configuration requires --approval-origin, --rp-id and --grading"
        )
    if args.grading == "hardware" and args.mds_cache is None:
        parser.error("hardware grading requires --mds-cache")

    async def pinned(domain: str) -> str:
        if domain != store.descriptor().domain:
            raise Refused(Refusal.ORGANISATION_MISMATCH)
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
        human_approval_config=args.human_approval_config,
    )

    def body() -> WireObject:
        return parse(sys.stdin.buffer.read(4 * 1024 * 1024 + 1))

    try:
        if args.command == OperatorCommand.SERVE:
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
        if args.command == OperatorCommand.ISSUE_PERSON:
            return await holder.issue_person(args.person, args.identity_key)
        if args.command == OperatorCommand.BOOTSTRAP:
            holder.require_approval()
            return await holder.bootstrap(args.person, args.identity_key)
        request = parse_controller_request(body())
        if request.domain != store.descriptor().domain:
            raise Refused(Refusal.ORGANISATION_MISMATCH)
        return await registry.controller_request(
            request,
            controllers={"controller": store.descriptor(team=args.team)},
            signer=lambda context: store.sign_controller(context, actor="operator"),
        )
    finally:
        await registry.aclose()


def main() -> None:
    """Dispatch private operator commands without exporting custody inputs."""
    parser = argparse.ArgumentParser(prog="aweb-key-holder")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--registry-origin")
    parser.add_argument("--origin")
    parser.add_argument(
        "--human-approval-config",
        type=Path,
        default=os.environ.get("HUMAN_APPROVAL_CONFIG_FILE"),
        help="Read-only organisation policy rendered from deployment.yaml; omission means approval off",
    )
    parser.add_argument("--approval-origin")
    parser.add_argument("--rp-id")
    parser.add_argument("--grading", choices=("passkey_only", "hardware"))
    parser.add_argument("--mds-cache", type=Path)
    parser.add_argument("--mds-manifest", type=Path)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser(OperatorCommand.INIT.value)
    initialize.add_argument("--organisation", required=True)
    descriptor = commands.add_parser(OperatorCommand.DESCRIPTOR.value)
    descriptor.add_argument("--team")
    team = commands.add_parser(OperatorCommand.CREATE_TEAM_KEY.value)
    team.add_argument("name")
    backup = commands.add_parser(OperatorCommand.BACKUP.value)
    backup.add_argument("--offline-public-key", required=True)
    commands.add_parser(OperatorCommand.MIGRATE.value)
    audit = commands.add_parser(OperatorCommand.AUDIT.value)
    audit.add_argument("--after", type=int, default=0)
    audit.add_argument("--limit", type=int, default=100)
    retire = commands.add_parser(OperatorCommand.RETIRE_PERSON.value)
    retire.add_argument("--person", required=True)
    issue = commands.add_parser(OperatorCommand.ISSUE_PERSON.value)
    issue.add_argument("--person", required=True)
    issue.add_argument("--identity-key", required=True)
    service = commands.add_parser(OperatorCommand.SERVE.value)
    service.add_argument("--bind", default="127.0.0.1")
    service.add_argument("--port", default=8081, type=int)
    service.add_argument("--tls-cert")
    service.add_argument("--tls-key")
    bootstrap = commands.add_parser(OperatorCommand.BOOTSTRAP.value)
    bootstrap.add_argument("--person", required=True)
    bootstrap.add_argument("--identity-key", required=True)
    registry = commands.add_parser(OperatorCommand.REGISTRY.value)
    registry.add_argument("--team")
    args = parser.parse_args()
    result: HolderAnswer | list[AuditEntry] | RetiredPerson | None
    try:
        if args.command == OperatorCommand.INIT:
            result = asdict(
                KeyStore.create(args.state, organisation=args.organisation).descriptor()
            )
        elif args.command == OperatorCommand.AUDIT:
            result = KeyStore.open(args.state).audit(after=args.after, limit=args.limit)
        elif args.command == OperatorCommand.RETIRE_PERSON:
            result = KeyStore.open(args.state).retire_person(args.person)
        elif args.command == OperatorCommand.MIGRATE:
            from approval_service.gate import load_policy

            store = KeyStore(args.state)
            policy = (
                load_policy(
                    args.human_approval_config, organisation=store.descriptor().domain
                )
                if args.human_approval_config is not None
                else None
            )
            store.migrate(policy=policy)
            result = {"state": "migrated"}
        elif args.command in {
            OperatorCommand.DESCRIPTOR,
            OperatorCommand.CREATE_TEAM_KEY,
            OperatorCommand.BACKUP,
        }:
            store = KeyStore.open(args.state)
            if args.command == OperatorCommand.DESCRIPTOR:
                result = asdict(store.descriptor(team=args.team))
            elif args.command == OperatorCommand.CREATE_TEAM_KEY:
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
        failure = describe_refusal(error)
        result = {"error": failure.code}
        if failure.advice is not None:
            result["message"] = failure.advice
        print(json.dumps(result), file=sys.stderr)
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
