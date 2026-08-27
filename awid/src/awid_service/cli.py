from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import uuid

import typer
import uvicorn

from awid.dns_verify import verify_domain, verify_domain_with_authoritative_ttl

from .config import get_settings
from .controller_rollover_operator import (
    MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS,
    ControllerRolloverOperator,
)
from .db import AwidDatabaseInfra
from .registry_migration import RegistryMigrationService

app = typer.Typer(help="awid.ai registry service CLI")
registry_migration_app = typer.Typer(
    help="Internal DB-operator registry migration protocol (not an HTTP authority)"
)
app.add_typer(registry_migration_app, name="registry-migration")
controller_rollover_app = typer.Typer(help="Internal controller-rollover operator controls")
app.add_typer(controller_rollover_app, name="controller-rollover")


async def _with_migration_service(callback):
    settings = get_settings()
    infra = AwidDatabaseInfra(schema=settings.db_schema)
    await infra.initialize(run_migrations=True)
    try:
        return await callback(
            RegistryMigrationService(
                infra.get_manager("aweb"),
                verify_domain=verify_domain_with_authoritative_ttl,
                public_origin=settings.public_origin,
            )
        )
    finally:
        await infra.close()


async def _with_rollover_operator(callback):
    settings = get_settings()
    infra = AwidDatabaseInfra(schema=settings.db_schema)
    await infra.initialize(run_migrations=True)
    try:
        operator = ControllerRolloverOperator(
            infra.get_manager("aweb"),
            verify_domain=verify_domain,
            public_origin=settings.public_origin,
        )
        return await callback(operator)
    finally:
        await infra.close()


@controller_rollover_app.command("accept-overlap-risk")
def controller_rollover_accept_overlap_risk(
    rollover_id: str = typer.Option(...),
    dns_changed_at: str = typer.Option(...),
    assumed_previous_ttl_seconds: int = typer.Option(
        ..., min=1, max=MAX_ROLLOVER_RISK_SAFETY_WINDOW_SECONDS
    ),
    reason_file: Path = typer.Option(..., exists=True, dir_okay=False),
    operator_id: str = typer.Option(...),
    new_controller_signature: str = typer.Option(...),
    signature_timestamp: str = typer.Option(...),
    i_accept_unverified_previous_ttl_risk: bool = typer.Option(False),
) -> None:
    async def run(operator):
        return await operator.accept_overlap_risk(
            rollover_id=rollover_id,
            dns_changed_at=dns_changed_at,
            assumed_previous_ttl_seconds=assumed_previous_ttl_seconds,
            reason_bytes=reason_file.read_bytes(),
            operator_id=operator_id,
            new_controller_signature=new_controller_signature,
            signature_timestamp=signature_timestamp,
            explicit_acceptance=i_accept_unverified_previous_ttl_risk,
        )

    typer.echo(json.dumps(asyncio.run(_with_rollover_operator(run)), sort_keys=True))


@registry_migration_app.command("prepare")
def registry_migration_prepare(
    root_domain: str = typer.Option(...),
    destination_registry_id: str = typer.Option(...),
    artifact: Path = typer.Option(...),
    expected_source_origin: str = typer.Option(...),
    expected_destination_origin: str = typer.Option(...),
    cutover_id: str | None = typer.Option(None),
) -> None:
    cutover_id = cutover_id or str(uuid.uuid4())
    typer.echo(json.dumps({"cutover_id": cutover_id, "phase": "before_source_fence"}))

    async def run(service):
        return await service.prepare(
            root_domain=root_domain,
            destination_registry_id=destination_registry_id,
            cutover_id=cutover_id,
            expected_source_origin=expected_source_origin,
            expected_destination_origin=expected_destination_origin,
        )

    result = asyncio.run(_with_migration_service(run))
    temporary = artifact.with_name(f".{artifact.name}.{cutover_id}.tmp")
    temporary.write_text(
        json.dumps(result.as_dict(), sort_keys=True, separators=(",", ":")) + "\n"
    )
    os.replace(temporary, artifact)
    typer.echo(json.dumps({"cutover_id": result.payload["cutover_id"], "snapshot_digest": result.snapshot_digest}))


@registry_migration_app.command("import")
def registry_migration_import(
    artifact: Path = typer.Option(..., exists=True, dir_okay=False),
    receipt: Path = typer.Option(...),
) -> None:
    value = json.loads(artifact.read_text())

    async def run(service):
        return await service.import_artifact(value)

    result = asyncio.run(_with_migration_service(run))
    receipt.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    typer.echo(json.dumps(result, sort_keys=True))


@registry_migration_app.command("confirm-readback")
def registry_migration_confirm_readback(
    cutover_id: str = typer.Option(...),
    receipt: Path = typer.Option(..., exists=True, dir_okay=False),
) -> None:
    value = json.loads(receipt.read_text())

    async def run(service):
        return await service.confirm_readback(cutover_id, value)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("apply-dns-authorization")
def registry_migration_apply_dns_authorization(
    cutover_id: str = typer.Option(...),
    authorization: Path = typer.Option(..., exists=True, dir_okay=False),
) -> None:
    value = json.loads(authorization.read_text())

    async def run(service):
        return await service.apply_dns_authorization(cutover_id, value)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("observe-destination")
def registry_migration_observe_destination(
    cutover_id: str = typer.Option(...),
    receipt: Path = typer.Option(...),
) -> None:
    async def run(service):
        return await service.observe_destination(
            cutover_id,
        )

    value = asyncio.run(_with_migration_service(run))
    receipt.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    typer.echo(json.dumps(value, sort_keys=True))


@registry_migration_app.command("establish-overlap")
def registry_migration_establish_overlap(
    cutover_id: str = typer.Option(...),
    destination_observation: Path = typer.Option(..., exists=True, dir_okay=False),
    receipt: Path = typer.Option(...),
) -> None:
    observation = json.loads(destination_observation.read_text())

    async def run(service):
        return await service.establish_overlap(
            cutover_id,
            observation,
        )

    value = asyncio.run(_with_migration_service(run))
    receipt.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    typer.echo(json.dumps(value, sort_keys=True))


@registry_migration_app.command("apply-overlap")
def registry_migration_apply_overlap(
    cutover_id: str = typer.Option(...),
    overlap_receipt: Path = typer.Option(..., exists=True, dir_okay=False),
) -> None:
    value = json.loads(overlap_receipt.read_text())

    async def run(service):
        return await service.apply_overlap(cutover_id, value)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("complete-destination")
def registry_migration_complete_destination(
    cutover_id: str = typer.Option(...),
    receipt: Path = typer.Option(...),
) -> None:
    async def run(service):
        return await service.complete_destination(cutover_id)

    value = asyncio.run(_with_migration_service(run))
    receipt.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
    typer.echo(json.dumps(value, sort_keys=True))


@registry_migration_app.command("complete-source")
def registry_migration_complete_source(
    cutover_id: str = typer.Option(...),
    destination_complete: Path = typer.Option(..., exists=True, dir_okay=False),
) -> None:
    value = json.loads(destination_complete.read_text())

    async def run(service):
        return await service.complete_source(cutover_id, value)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("cancel-source")
def registry_migration_cancel_source(cutover_id: str = typer.Option(...)) -> None:
    async def run(service):
        return await service.cancel_source(cutover_id)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("cancel-destination")
def registry_migration_cancel(cutover_id: str = typer.Option(...)) -> None:
    async def run(service):
        return await service.cancel_destination(cutover_id)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@registry_migration_app.command("status")
def registry_migration_status(cutover_id: str = typer.Option(...)) -> None:
    async def run(service):
        return await service.status(cutover_id)

    typer.echo(json.dumps(asyncio.run(_with_migration_service(run)), sort_keys=True))


@app.command()
def serve(
    host: str | None = typer.Option(None, help="Host interface to bind"),
    port: int | None = typer.Option(None, help="Port to bind"),
    reload: bool | None = typer.Option(None, help="Enable auto-reload (development only)"),
    log_level: str | None = typer.Option(None, help="Log level for the server"),
) -> None:
    settings = get_settings()
    uvicorn.run(
        "awid_service.main:create_app",
        host=host or settings.host,
        port=port or settings.port,
        reload=reload if reload is not None else settings.reload,
        log_level=log_level or settings.log_level,
        factory=True,
    )
