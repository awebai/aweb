"""Delivery-server metadata, independent of author content and verification."""
from __future__ import annotations

import json
import re
from typing import Any


def validate_ingress(value: Any) -> dict[str, str]:
    """Snapshot the closed public context; never infer facts from a label."""
    fields = {"platform", "presence_kind", "input_origin", "confidentiality"}
    if type(value) is not dict or value.keys() != fields or any(type(v) is not str for v in value.values()):
        raise ValueError("invalid channel ingress fields")
    if re.fullmatch(r"[a-z][a-z0-9_]{0,31}", value["platform"], flags=re.ASCII) is None:
        raise ValueError("invalid channel ingress platform")
    if value["presence_kind"] not in {"shared", "dedicated", "native"}:
        raise ValueError("invalid channel ingress presence kind")
    if value["input_origin"] != "external_human":
        raise ValueError("invalid channel ingress input origin")
    if value["confidentiality"] not in {"end_to_end", "hosted_readable", "bridge_readable", "server_readable"}:
        raise ValueError("invalid channel ingress confidentiality")
    return dict(value)


def ingress_from_row(row: Any) -> dict[str, str] | None:
    """Read only the stored server column, never signed/decrypted metadata."""
    value = row.get("ingress")
    if value is None:
        return None
    return validate_ingress(json.loads(value) if isinstance(value, str) else value)


def ingress_projection(row: Any) -> dict[str, Any]:
    value = ingress_from_row(row)
    return {"ingress": value} if value is not None else {}
