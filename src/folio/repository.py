from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager

from folio.auth import Principal
from folio.config import Settings
from folio.presentation import sanitize_theme_tokens

ACTIVE_TIER = "active"


def _caps_for_tier(*, tier: str, settings: Settings) -> dict[str, int | None]:
    if tier == ACTIVE_TIER:
        return {"max_documents": None, "max_versions_per_doc": None}
    return {
        "max_documents": settings.free_max_documents,
        "max_versions_per_doc": settings.free_max_versions_per_doc,
    }


def _limit_exceeded(*, limit: str, current: int, maximum: int) -> HTTPException:
    return HTTPException(
        status_code=402,
        detail={
            "code": "free_tier_limit_exceeded",
            "limit": limit,
            "current": current,
            "max": maximum,
            "subscriptions_available": False,
            "message": "Free tier limit reached; subscriptions are not yet available.",
        },
    )


async def ensure_subscription(db: AsyncDatabaseManager, *, team_id: str) -> str:
    await db.execute(
        """
        INSERT INTO {{tables.subscriptions}} (team_id, tier)
        VALUES ($1, 'free')
        ON CONFLICT (team_id) DO NOTHING
        """,
        team_id,
    )
    row = await db.fetch_one(
        "SELECT tier FROM {{tables.subscriptions}} WHERE team_id = $1",
        team_id,
    )
    if row is None:
        return "free"
    return str(row["tier"] or "free")


async def _team_usage(db: AsyncDatabaseManager, *, team_id: str) -> dict[str, int]:
    document_count = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM {{tables.documents}} WHERE team_id = $1",
        team_id,
    )
    max_versions = await db.fetch_one(
        """
        SELECT COALESCE(MAX(version_count), 0) AS n
        FROM (
            SELECT COUNT(*) AS version_count
            FROM {{tables.documents}} d
            JOIN {{tables.document_versions}} v ON v.document_id = d.document_id
            WHERE d.team_id = $1
            GROUP BY d.document_id
        ) counts
        """,
        team_id,
    )
    return {
        "documents": int(document_count["n"] if document_count is not None else 0),
        "max_versions_per_doc": int(max_versions["n"] if max_versions is not None else 0),
    }


async def get_billing_status(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
) -> dict:
    tier = await ensure_subscription(db, team_id=principal.team_id)
    return {
        "team_id": principal.team_id,
        "tier": tier,
        "caps": _caps_for_tier(tier=tier, settings=settings),
        "usage": await _team_usage(db, team_id=principal.team_id),
    }


async def _enforce_document_cap(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
) -> None:
    tier = await ensure_subscription(db, team_id=principal.team_id)
    if tier == ACTIVE_TIER:
        return
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM {{tables.documents}} WHERE team_id = $1",
        principal.team_id,
    )
    current = int(row["n"] if row is not None else 0)
    if current >= settings.free_max_documents:
        raise _limit_exceeded(
            limit="documents",
            current=current,
            maximum=settings.free_max_documents,
        )


async def _enforce_version_cap(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    document_id: UUID,
    settings: Settings,
) -> None:
    tier = await ensure_subscription(db, team_id=principal.team_id)
    if tier == ACTIVE_TIER:
        return
    row = await db.fetch_one(
        "SELECT COUNT(*) AS n FROM {{tables.document_versions}} WHERE document_id = $1",
        document_id,
    )
    current = int(row["n"] if row is not None else 0)
    if current >= settings.free_max_versions_per_doc:
        raise _limit_exceeded(
            limit="versions_per_doc",
            current=current,
            maximum=settings.free_max_versions_per_doc,
        )


async def create_document(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
    slug: str,
    title: str,
    body: str,
) -> dict:
    await _enforce_document_cap(db, principal=principal, settings=settings)
    document_id = uuid4()
    version_id = uuid4()
    try:
        async with db.transaction() as tx:
            await tx.execute(
                """
                INSERT INTO {{tables.documents}}
                  (document_id, team_id, slug, title, created_by_did_key, created_by_did_aw, created_by_alias)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                document_id,
                principal.team_id,
                slug,
                title,
                principal.did_key,
                principal.did_aw,
                principal.alias,
            )
            await tx.execute(
                """
                INSERT INTO {{tables.document_versions}}
                  (version_id, document_id, version_number, body, created_by_did_key,
                   created_by_did_aw, created_by_address, created_by_alias, certificate_id)
                VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8)
                """,
                version_id,
                document_id,
                body,
                principal.did_key,
                principal.did_aw,
                principal.address,
                principal.alias,
                principal.certificate_id,
            )
    except Exception as exc:
        if "unique" in str(exc).lower():
            raise HTTPException(status_code=409, detail="Document slug already exists for this team") from exc
        raise
    return await get_document(db, principal=principal, slug=slug)


async def list_documents(db: AsyncDatabaseManager, *, principal: Principal) -> list[dict]:
    rows = await db.fetch_all(
        """
        SELECT d.document_id, d.slug, d.title, d.created_at, d.updated_at,
               COALESCE(MAX(v.version_number), 0) AS current_version
        FROM {{tables.documents}} d
        LEFT JOIN {{tables.document_versions}} v ON v.document_id = d.document_id
        WHERE d.team_id = $1
        GROUP BY d.document_id, d.slug, d.title, d.created_at, d.updated_at
        ORDER BY d.updated_at DESC, d.slug ASC
        """,
        principal.team_id,
    )
    return [dict(row) for row in rows]


async def get_document(db: AsyncDatabaseManager, *, principal: Principal, slug: str) -> dict:
    row = await db.fetch_one(
        """
        SELECT d.document_id, d.slug, d.title, d.created_at, d.updated_at,
               v.version_id, v.version_number, v.body, v.created_by_did_key,
               v.created_by_did_aw, v.created_by_address, v.created_by_alias,
               v.certificate_id, v.created_at AS version_created_at
        FROM {{tables.documents}} d
        JOIN {{tables.document_versions}} v ON v.document_id = d.document_id
        WHERE d.team_id = $1 AND d.slug = $2
        ORDER BY v.version_number DESC
        LIMIT 1
        """,
        principal.team_id,
        slug,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Document not found")
    data = dict(row)
    return {
        "document_id": data["document_id"],
        "slug": data["slug"],
        "title": data["title"],
        "body": data["body"],
        "current_version": data["version_number"],
        "created_at": data["created_at"],
        "updated_at": data["updated_at"],
        "latest": {
            "version_id": data["version_id"],
            "version_number": data["version_number"],
            "body": data["body"],
            "created_by_did_key": data["created_by_did_key"],
            "created_by_did_aw": data["created_by_did_aw"],
            "created_by_address": data["created_by_address"],
            "created_by_alias": data["created_by_alias"],
            "certificate_id": data["certificate_id"],
            "created_at": data["version_created_at"],
        },
    }


async def append_version(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
    slug: str,
    body: str,
) -> dict:
    document = await db.fetch_one(
        "SELECT document_id FROM {{tables.documents}} WHERE team_id = $1 AND slug = $2",
        principal.team_id,
        slug,
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    document_id: UUID = document["document_id"]
    await _enforce_version_cap(db, principal=principal, document_id=document_id, settings=settings)
    version_id = uuid4()
    async with db.transaction() as tx:
        current = await tx.fetch_one(
            "SELECT COALESCE(MAX(version_number), 0) AS n FROM {{tables.document_versions}} WHERE document_id = $1",
            document_id,
        )
        next_version = int(current["n"] if current is not None else 0) + 1
        await tx.execute(
            """
            INSERT INTO {{tables.document_versions}}
              (version_id, document_id, version_number, body, created_by_did_key,
               created_by_did_aw, created_by_address, created_by_alias, certificate_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """,
            version_id,
            document_id,
            next_version,
            body,
            principal.did_key,
            principal.did_aw,
            principal.address,
            principal.alias,
            principal.certificate_id,
        )
        await tx.execute(
            "UPDATE {{tables.documents}} SET updated_at = NOW() WHERE document_id = $1",
            document_id,
        )
    return await get_document(db, principal=principal, slug=slug)


async def list_versions(db: AsyncDatabaseManager, *, principal: Principal, slug: str) -> list[dict]:
    document = await db.fetch_one(
        "SELECT document_id FROM {{tables.documents}} WHERE team_id = $1 AND slug = $2",
        principal.team_id,
        slug,
    )
    if document is None:
        raise HTTPException(status_code=404, detail="Document not found")
    rows = await db.fetch_all(
        """
        SELECT version_id, version_number, NULL::TEXT AS body, created_by_did_key,
               created_by_did_aw, created_by_address, created_by_alias,
               certificate_id, created_at
        FROM {{tables.document_versions}}
        WHERE document_id = $1
        ORDER BY version_number DESC
        """,
        document["document_id"],
    )
    return [dict(row) for row in rows]


async def mint_presentation_link(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
    slug: str,
    version: int | None,
    ttl_seconds: int | None,
) -> dict[str, Any]:
    selected = await db.fetch_one(
        """
        SELECT d.document_id, COALESCE($3::integer, MAX(v.version_number)) AS version_number
        FROM {{tables.documents}} d
        JOIN {{tables.document_versions}} v ON v.document_id = d.document_id
        WHERE d.team_id = $1 AND d.slug = $2
        GROUP BY d.document_id
        """,
        principal.team_id,
        slug,
        version,
    )
    if selected is None or selected["version_number"] is None:
        raise HTTPException(status_code=404, detail="Document not found")

    document_id: UUID = selected["document_id"]
    version_number = int(selected["version_number"])
    exists = await db.fetch_one(
        "SELECT 1 FROM {{tables.document_versions}} WHERE document_id = $1 AND version_number = $2",
        document_id,
        version_number,
    )
    if exists is None:
        raise HTTPException(status_code=404, detail="Document version not found")

    ttl = min(ttl_seconds or settings.default_present_ttl_seconds, settings.max_present_ttl_seconds)
    expires_at = datetime.now(UTC) + timedelta(seconds=ttl)
    token = secrets.token_urlsafe(32)
    await db.execute(
        """
        INSERT INTO {{tables.presentation_links}}
          (token, document_id, version_number, expires_at, created_by_did_key,
           created_by_did_aw, created_by_alias, certificate_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        """,
        token,
        document_id,
        version_number,
        expires_at,
        principal.did_key,
        principal.did_aw,
        principal.alias,
        principal.certificate_id,
    )
    return {
        "token": token,
        "url": f"{settings.public_origin.rstrip('/')}/present/{token}",
        "expires_at": expires_at,
    }


async def revoke_presentation_link(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    token: str,
) -> None:
    row = await db.fetch_one(
        """
        SELECT p.token
        FROM {{tables.presentation_links}} p
        JOIN {{tables.documents}} d ON d.document_id = p.document_id
        WHERE p.token = $1 AND d.team_id = $2
        """,
        token,
        principal.team_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Presentation not found")
    await db.execute(
        "UPDATE {{tables.presentation_links}} SET revoked_at = NOW() WHERE token = $1",
        token,
    )


async def get_presented_document(db: AsyncDatabaseManager, *, token: str) -> dict[str, Any]:
    row = await db.fetch_one(
        """
        SELECT v.body, p.expires_at, d.team_id, t.tokens, t.logo_asset_id, t.header, t.footer
        FROM {{tables.presentation_links}} p
        JOIN {{tables.document_versions}} v
          ON v.document_id = p.document_id AND v.version_number = p.version_number
        JOIN {{tables.documents}} d ON d.document_id = p.document_id
        LEFT JOIN {{tables.themes}} t ON t.team_id = d.team_id
        WHERE p.token = $1 AND p.revoked_at IS NULL AND p.expires_at > NOW()
        """,
        token,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Presentation not found")
    body = str(row["body"])
    return {
        "body": body,
        "expires_at": row["expires_at"],
        "theme": _theme_from_row(row, public_origin=None),
        "allowed_asset_ids": await _allowed_asset_ids_for_body(db, team_id=str(row["team_id"]), body=body),
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value


def _theme_from_row(row: Any, *, public_origin: str | None) -> dict[str, Any] | None:
    data = dict(row)
    if "tokens" not in data:
        return None
    tokens = sanitize_theme_tokens(_json_value(data.get("tokens")) or {})
    logo_asset_id = data.get("logo_asset_id")
    logo_url = None
    if logo_asset_id is not None and public_origin is not None:
        logo_url = f"{public_origin.rstrip('/')}/assets/{logo_asset_id}"
    if not tokens and logo_asset_id is None and data.get("header") is None and data.get("footer") is None:
        return None
    return {
        "tokens": tokens,
        "logo_asset_id": logo_asset_id,
        "logo_url": logo_url,
        "header": data.get("header"),
        "footer": data.get("footer"),
        "updated_at": data.get("updated_at"),
    }


def _asset_response(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {"bytes": bytes(data["bytes"]), "content_type": data["content_type"]}


_SAFE_IMAGE_CONTENT_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
_ASSET_REFERENCE_RE = re.compile(r"/assets/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})")


def _image_magic_matches(payload: bytes, content_type: str) -> bool:
    if content_type == "image/png":
        return payload.startswith(b"\x89PNG\r\n\x1a\n")
    if content_type == "image/jpeg":
        return payload.startswith(b"\xff\xd8\xff")
    if content_type == "image/gif":
        return payload.startswith((b"GIF87a", b"GIF89a"))
    if content_type == "image/webp":
        return len(payload) >= 12 and payload.startswith(b"RIFF") and payload[8:12] == b"WEBP"
    return False


def _decode_image_asset(image: Any, *, label: str = "Image") -> tuple[bytes, str]:
    content_type = str(image.content_type).strip().lower()
    if content_type not in _SAFE_IMAGE_CONTENT_TYPES:
        raise HTTPException(status_code=400, detail=f"{label} content_type must be image/png, image/jpeg, image/gif, or image/webp")
    try:
        payload = base64.b64decode(str(image.data_base64), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{label} data_base64 must be valid base64") from exc
    if not payload:
        raise HTTPException(status_code=400, detail=f"{label} must not be empty")
    if len(payload) > 256 * 1024:
        raise HTTPException(status_code=400, detail=f"{label} must be <= 256 KiB")
    if not _image_magic_matches(payload, content_type):
        raise HTTPException(status_code=400, detail=f"{label} bytes must match content_type")
    return payload, content_type


def _decode_logo(logo: Any) -> tuple[bytes, str]:
    return _decode_image_asset(logo, label="Logo")


def _asset_ids_referenced_by_body(body: str) -> set[UUID]:
    asset_ids: set[UUID] = set()
    for match in _ASSET_REFERENCE_RE.finditer(body):
        try:
            asset_ids.add(UUID(match.group(1)))
        except ValueError:
            continue
    return asset_ids


async def _allowed_asset_ids_for_body(db: AsyncDatabaseManager, *, team_id: str, body: str) -> set[UUID]:
    referenced = _asset_ids_referenced_by_body(body)
    if not referenced:
        return set()
    rows = await db.fetch_all(
        "SELECT asset_id FROM {{tables.assets}} WHERE team_id = $1 AND asset_id = ANY($2::uuid[])",
        team_id,
        list(referenced),
    )
    return {row["asset_id"] for row in rows}


async def upload_image_asset(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
    image: Any,
) -> dict[str, Any]:
    payload, content_type = _decode_image_asset(image, label="Image")
    asset_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.assets}} (asset_id, team_id, bytes, content_type)
        VALUES ($1, $2, $3, $4)
        """,
        asset_id,
        principal.team_id,
        payload,
        content_type,
    )
    return {
        "asset_id": asset_id,
        "url": f"{settings.public_origin.rstrip('/')}/assets/{asset_id}",
        "content_type": content_type,
    }


async def get_theme(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
) -> dict[str, Any]:
    row = await db.fetch_one(
        """
        SELECT tokens, logo_asset_id, header, footer, updated_at
        FROM {{tables.themes}}
        WHERE team_id = $1
        """,
        principal.team_id,
    )
    if row is None:
        return {"tokens": {}, "logo_asset_id": None, "logo_url": None, "header": None, "footer": None, "updated_at": None}
    theme = _theme_from_row(row, public_origin=settings.public_origin)
    if theme is None:
        return {"tokens": {}, "logo_asset_id": None, "logo_url": None, "header": None, "footer": None, "updated_at": None}
    return theme


async def upsert_theme(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    settings: Settings,
    tokens: dict[str, dict[str, str]],
    logo: Any | None,
    clear_logo: bool,
    header: str | None,
    footer: str | None,
) -> dict[str, Any]:
    safe_tokens = sanitize_theme_tokens(tokens)
    token_bytes = json.dumps(safe_tokens, separators=(",", ":"))
    async with db.transaction() as tx:
        current = await tx.fetch_one(
            "SELECT logo_asset_id FROM {{tables.themes}} WHERE team_id = $1",
            principal.team_id,
        )
        logo_asset_id = None if clear_logo else (current["logo_asset_id"] if current is not None else None)
        if logo is not None:
            logo_bytes, content_type = _decode_logo(logo)
            logo_asset_id = uuid4()
            await tx.execute(
                """
                INSERT INTO {{tables.assets}} (asset_id, team_id, bytes, content_type)
                VALUES ($1, $2, $3, $4)
                """,
                logo_asset_id,
                principal.team_id,
                logo_bytes,
                content_type,
            )
        await tx.execute(
            """
            INSERT INTO {{tables.themes}} (team_id, tokens, logo_asset_id, header, footer)
            VALUES ($1, $2::jsonb, $3, $4, $5)
            ON CONFLICT (team_id) DO UPDATE SET
                tokens = EXCLUDED.tokens,
                logo_asset_id = EXCLUDED.logo_asset_id,
                header = EXCLUDED.header,
                footer = EXCLUDED.footer,
                updated_at = NOW()
            """,
            principal.team_id,
            token_bytes,
            logo_asset_id,
            header,
            footer,
        )
    return await get_theme(db, principal=principal, settings=settings)


async def get_public_asset(db: AsyncDatabaseManager, *, asset_id: UUID) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT bytes, content_type FROM {{tables.assets}} WHERE asset_id = $1",
        asset_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return _asset_response(row)
