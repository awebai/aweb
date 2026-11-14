"""Unsigned, definition-owned intent materialization; this module grants no authority.

The executor supplies the current custody key and original pending window, then
materializes once under exact-act UV. Only the existing codec signs bytes. A
historical validator checks the issued artifact without renewing its freshness.
"""

import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from awid.signing import canonical_json_bytes

from .types import SignerRefused

_FORMAT = "aweb.protected-artifact-intent"
_MEMBERS = {"v", "type", "template", "delivery", "issuance_window"}
_WINDOW_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


def _aware(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("aware time required")
    return value.astimezone(UTC)


def _window_time(value):
    if type(value) is not str or not _WINDOW_TIME.fullmatch(value):
        raise ValueError("invalid window time")
    return _aware(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _stamp(value):
    return _aware(value).isoformat().replace("+00:00", "Z")


def _parent(value, path):
    for name in path[:-1]:
        value = value[name]
    if type(value) is not dict:
        raise ValueError("non-object path")
    return value, path[-1]


def _read(value, path):
    parent, name = _parent(value, path)
    return parent[name]


@dataclass(frozen=True)
class ArtifactIssuance:
    """Code-owned recipe; no field of a request can install one of these."""

    issued_fields: tuple[tuple[str, ...], ...]
    fixed_route: str | None = None
    route_field: tuple[str, ...] | None = None
    expiry_field: tuple[str, ...] | None = None
    lifetime_seconds: int | None = None

    def __post_init__(self):
        if (not self.issued_fields or len(set(self.issued_fields)) != len(self.issued_fields)
            or any(not path or not all(type(name) is str and name for name in path) for path in self.issued_fields)
            or (self.fixed_route is None) == (self.route_field is None)
            or (self.expiry_field is None) != (self.lifetime_seconds is None)
            or self.expiry_field in self.issued_fields
            or (self.lifetime_seconds is not None and (type(self.lifetime_seconds) is not int or self.lifetime_seconds <= 0))):
            raise ValueError("invalid code-owned issuance recipe")

    def delivery(self, operation, template):
        route = self.fixed_route if self.fixed_route is not None else _read(template, self.route_field)
        return {"audience": operation.audience, "method": "POST", "path": route}

    def fields(self):
        return {"issued_fields": ["/" + "/".join(path) for path in self.issued_fields],
            "expiry_field": None if self.expiry_field is None else "/" + "/".join(self.expiry_field),
            "lifetime_seconds": self.lifetime_seconds,
            "fixed_route": self.fixed_route,
            "route_field": None if self.route_field is None else "/" + "/".join(self.route_field)}

    def without_times(self, artifact):
        template = deepcopy(artifact)
        for path in (*self.issued_fields, *((self.expiry_field,) if self.expiry_field else ())):
            parent, name = _parent(template, path)
            del parent[name]
        return template


def _rule(operation):
    rule = operation.spec.codec.issuance
    if not operation.spec.needs_human or type(rule) is not ArtifactIssuance:
        raise SignerRefused("operation_not_served")
    return rule


def _descriptor(operation, descriptor):
    rule = _rule(operation)
    if (type(descriptor) is not dict or set(descriptor) != _MEMBERS
        or type(descriptor["v"]) is not int or descriptor["v"] != 1
        or descriptor["type"] != _FORMAT or type(descriptor["template"]) is not dict):
        raise ValueError("invalid intent descriptor")
    window = descriptor["issuance_window"]
    if type(window) is not dict or set(window) != {"not_before", "not_after"}:
        raise ValueError("invalid issuance window")
    start, until = (_window_time(window[name]) for name in ("not_before", "not_after"))
    if not start < until <= start + timedelta(hours=24):
        raise ValueError("invalid pending bound")
    if descriptor["delivery"] != rule.delivery(operation, descriptor["template"]):
        raise ValueError("delivery does not match the definition")
    # An execution-issued field is absent, not an optional requester value.
    for path in (*rule.issued_fields, *((rule.expiry_field,) if rule.expiry_field else ())):
        parent, name = _parent(descriptor["template"], path)
        if name in parent:
            raise ValueError("execution field already supplied")
    return rule, start, until


def prepare_artifact_intent(operation, key, not_before, not_after):
    """Freeze the codec's exact template; no caller-supplied signing shape."""
    rule = _rule(operation)
    try:
        start, until = _aware(not_before), _aware(not_after)
        artifact = operation.spec.codec.build_artifact(operation, key, start)
        operation.spec.codec.signing_bytes(operation, artifact)
        template = rule.without_times(artifact)
        descriptor = {"v": 1, "type": _FORMAT, "template": template,
            "delivery": rule.delivery(operation, template),
            "issuance_window": {"not_before": _stamp(start), "not_after": _stamp(until)}}
        _descriptor(operation, descriptor)
        return descriptor
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SignerRefused("operation_mismatch") from None


def materialize_artifact(operation, descriptor, at):
    """Materialize declared time fields once; signing/storage live in the engine."""
    try:
        rule, start, until = _descriptor(operation, descriptor)
        at = _aware(at).replace(microsecond=0)
        if at < start or at >= until:
            raise SignerRefused("operation_expired")
        artifact = deepcopy(descriptor["template"])
        for path in rule.issued_fields:
            parent, name = _parent(artifact, path)
            parent[name] = _stamp(at)
        if rule.expiry_field is not None:
            parent, name = _parent(artifact, rule.expiry_field)
            parent[name] = _stamp(min(until, at + timedelta(seconds=rule.lifetime_seconds)).replace(microsecond=0))
        validate_issued_artifact(operation, descriptor, artifact)
        return artifact
    except SignerRefused:
        raise
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SignerRefused("operation_mismatch") from None


def validate_issued_artifact(operation, descriptor, artifact):
    """Validate as history. This never grants a fresh signing/delivery window."""
    try:
        rule, start, until = _descriptor(operation, descriptor)
        issued = [_window_time(_read(artifact, path)) for path in rule.issued_fields]
        if not issued or any(stamp != issued[0] for stamp in issued) or not start <= issued[0] < until:
            raise ValueError("issuance outside frozen window")
        if rule.expiry_field is not None:
            expiry = _window_time(_read(artifact, rule.expiry_field))
            if expiry != min(until, issued[0] + timedelta(seconds=rule.lifetime_seconds)).replace(microsecond=0) or expiry <= issued[0]:
                raise ValueError("lifetime differs from the definition")
        if canonical_json_bytes(rule.without_times(artifact)) != canonical_json_bytes(descriptor["template"]):
            raise ValueError("issued artifact changed the frozen template")
        if rule.delivery(operation, artifact) != descriptor["delivery"]:
            raise ValueError("issued artifact changed delivery")
        return operation.spec.codec.signing_bytes(operation, artifact)
    except (ValueError, TypeError, KeyError, OverflowError):
        raise SignerRefused("operation_mismatch") from None
