from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DeclarativeTemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=80)
    slots: dict[str, Any] = Field(default_factory=dict)


class CreateDocumentRequest(BaseModel):
    slug: str = Field(..., min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    title: str = Field(..., min_length=1, max_length=240)
    body: str | None = None
    template: DeclarativeTemplateRequest | None = None


class AppendVersionRequest(BaseModel):
    body: str


class AppendTemplateVersionRequest(DeclarativeTemplateRequest):
    pass


class DocumentSummary(BaseModel):
    document_id: UUID
    slug: str
    title: str
    current_version: int
    updated_at: datetime
    created_at: datetime


class DocumentVersion(BaseModel):
    version_id: UUID
    version_number: int
    body: str | None = None
    created_by_did_key: str
    created_by_did_aw: str | None = None
    created_by_address: str | None = None
    created_by_alias: str
    certificate_id: str
    created_by_editor_name: str | None = None
    created_at: datetime


class DocumentResponse(BaseModel):
    document_id: UUID
    slug: str
    title: str
    body: str
    current_version: int
    created_at: datetime
    updated_at: datetime
    latest: DocumentVersion


class CreatePresentationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    slug: str = Field(..., min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")
    version: int | None = Field(default=None, ge=1)
    ttl_seconds: int | None = Field(default=None, ge=1)
    editable: bool = False


class PresentationResponse(BaseModel):
    token: str
    url: str
    expires_at: datetime


class PresentationEditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str
    base_version: int = Field(..., ge=1)
    editor_name: str | None = Field(default=None, max_length=120)


class PresentationPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    body: str = Field(..., max_length=200_000)


class PresentationEditResponse(BaseModel):
    version_number: int


class PresentationStateResponse(BaseModel):
    version_number: int


class ImageAssetUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_type: str = Field(..., min_length=1, max_length=100)
    data_base64: str = Field(..., min_length=1)


class ImageAssetResponse(BaseModel):
    asset_id: UUID
    kind: str = "image"
    url: str
    content_type: str


class VideoDirectUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content_type: str = Field(..., min_length=1, max_length=100)
    filename: str | None = Field(default=None, max_length=240)
    max_duration_seconds: int | None = Field(default=None, ge=1)


class VideoDirectUploadResponse(BaseModel):
    asset_id: UUID
    kind: str
    stream_uid: str
    upload_url: str
    upload_expires_at: datetime
    status: str
    content_type: str


class AssetMetadataResponse(BaseModel):
    asset_id: UUID
    kind: str
    content_type: str | None = None
    url: str | None = None
    stream_uid: str | None = None
    stream_status: str | None = None
    upload_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime | None = None


class ThemeLogoInput(ImageAssetUploadRequest):
    pass


class ThemeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    tokens: dict[str, dict[str, str]] = Field(default_factory=dict)
    logo: ThemeLogoInput | None = None
    clear_logo: bool = False
    header: str | None = Field(default=None, max_length=2_000)
    footer: str | None = Field(default=None, max_length=2_000)


class ThemeResponse(BaseModel):
    tokens: dict[str, dict[str, str]]
    logo_asset_id: UUID | None = None
    logo_url: str | None = None
    header: str | None = None
    footer: str | None = None
    updated_at: datetime | None = None


class BillingCaps(BaseModel):
    max_documents: int | None
    max_versions_per_doc: int | None


class BillingUsage(BaseModel):
    documents: int
    max_versions_per_doc: int


class BillingResponse(BaseModel):
    team_id: str
    tier: str
    caps: BillingCaps
    usage: BillingUsage
