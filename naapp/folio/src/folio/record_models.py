"""Callable record inputs; identity and collection policy come from the server."""

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

Identifier = Annotated[str, Field(min_length=1, max_length=128)]
Scalar = str | int | Annotated[float, Field(allow_inf_nan=False)] | bool | None


class RecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    collection_id: Identifier


class RecordWriteRequest(RecordRequest):
    request_id: Identifier


class CollectionDefineRequest(RecordWriteRequest):
    title: str = Field(min_length=1, max_length=256)
    record_schema: dict[str, JsonValue] = Field(alias="schema")


class RecordAddRequest(RecordWriteRequest):
    record_id: Identifier | None = None
    values: dict[str, JsonValue]


class RecordDeleteRequest(RecordWriteRequest):
    record_id: Identifier
    expected_rev: int = Field(ge=1)


class RecordUpdateRequest(RecordDeleteRequest):
    patch: dict[str, JsonValue] = Field(min_length=1)


class RecordFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    field: Identifier
    op: Literal["eq", "ne", "lt", "lte", "gt", "gte", "in"]
    value: Scalar | Annotated[list[Scalar], Field(max_length=50)]

    @model_validator(mode="after")
    def check_operand(self) -> Self:
        if (self.op == "in") != isinstance(self.value, list):
            raise ValueError("in requires a list; comparison operators require a scalar")
        return self


class RecordSort(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    field: Identifier
    direction: Literal["asc", "desc"]


class RecordQueryRequest(RecordRequest):
    filter: list[RecordFilter] = Field(default_factory=list, max_length=20)
    sort: list[RecordSort] = Field(default_factory=list, max_length=8)
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
