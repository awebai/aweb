"""The aweb.hooks catalog: each hook's class, producers and strict payload allowlist.

``packaged_catalog`` loads aweb.hooks v1 from the copy shipped in this package,
which is byte for byte the public catalog vector, so an installed app needs no
repository checkout. ``load_catalog`` reads a
catalog file strictly: an unknown key at any level, a duplicate key, a float or a reference
that does not resolve refuses the whole file. ``Catalog.validate`` then checks
one event payload against its hook, in the fixed order the file's scheme
states, and reports the first fault as ``PayloadRefused(code, field)``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from typing import Any

PAYLOAD_ERRORS = (
    "unknown_hook",
    "unknown_field",
    "missing_field",
    "invalid_value",
    "rule_violation",
    "direction_mismatch",
)
HOOK_CLASSES = ("server", "client")
PRODUCER_KINDS = ("core", "app", "client")
AUDIT_CRITICAL = ("always", "widening_acts", "action_rules", "never")
DIRECTIONS = ("widening", "narrowing")
MAX_SAFE_INTEGER = 2**53 - 1


class CatalogError(ValueError):
    """The catalog file is malformed or inconsistent."""


class PayloadRefused(ValueError):
    """An event payload does not satisfy its hook's allowlist."""

    def __init__(self, code: str, field: str | None = None) -> None:
        super().__init__(code if field is None else f"{code}: {field}")
        self.code = code
        self.field = field


@dataclass(frozen=True)
class ValueType:
    kind: str
    pattern: re.Pattern[str] | None = None
    minimum: int | None = None
    maximum: int | None = None

    def accepts(self, value: Any) -> bool:
        if self.kind == "string":
            return (
                isinstance(value, str)
                and self.pattern is not None
                and bool(self.pattern.fullmatch(value))
            )
        if self.kind == "integer":
            return (
                type(value) is int
                and self.minimum is not None
                and self.maximum is not None
                and self.minimum <= value <= self.maximum
            )
        return type(value) is bool


@dataclass(frozen=True)
class FieldSpec:
    name: str
    required: bool
    value_type: ValueType | None = None
    enum: tuple[Any, ...] | None = None
    item_type: ValueType | None = None
    item_enum: tuple[Any, ...] | None = None
    min_items: int = 0
    max_items: int = 0
    const: Any = None
    has_const: bool = False

    @property
    def is_list(self) -> bool:
        return self.item_type is not None or self.item_enum is not None

    def accepts(self, value: Any) -> bool:
        if self.has_const and not _same(value, self.const):
            return False
        if self.is_list:
            if not isinstance(value, list) or not self.min_items <= len(value) <= self.max_items:
                return False
            if len({json.dumps(item, sort_keys=True) for item in value}) != len(value):
                return False
            return all(self._accepts_item(item) for item in value)
        if self.enum is not None:
            return any(_same(value, option) for option in self.enum)
        assert self.value_type is not None
        return self.value_type.accepts(value)

    def _accepts_item(self, item: Any) -> bool:
        if self.item_enum is not None:
            return any(_same(item, option) for option in self.item_enum)
        assert self.item_type is not None
        return self.item_type.accepts(item)


@dataclass(frozen=True)
class Rule:
    when_field: str
    when_in: tuple[Any, ...] | None
    when_present: bool | None
    require: tuple[str, ...]
    forbid: tuple[str, ...]
    require_in: tuple[tuple[str, tuple[Any, ...]], ...]

    def applies(self, payload: Mapping[str, Any]) -> bool:
        if self.when_present is not None:
            return (self.when_field in payload) is self.when_present
        assert self.when_in is not None
        return self.when_field in payload and any(
            _same(payload[self.when_field], option) for option in self.when_in
        )

    def first_violation(self, payload: Mapping[str, Any]) -> str | None:
        for name in self.require:
            if name not in payload:
                return name
        for name in self.forbid:
            if name in payload:
                return name
        for name, allowed in self.require_in:
            if name not in payload or not any(_same(payload[name], v) for v in allowed):
                return name
        return None


@dataclass(frozen=True)
class MutationType:
    name: str
    fields: Mapping[str, FieldSpec]
    rules: tuple[Rule, ...]


@dataclass(frozen=True)
class ActionAuditRule:
    """One action's fixed classification, optionally split by an enum field."""

    critical: bool = True
    field: str | None = None
    values: Mapping[str, bool] | None = None

    def is_critical(self, payload: Mapping[str, Any]) -> bool:
        if self.field is None:
            return self.critical
        assert self.values is not None
        # Validation normally runs first. An unclassified value never obtains
        # an availability exception when this predicate is called directly.
        return self.values.get(str(payload.get(self.field)), True)


@dataclass(frozen=True)
class Hook:
    name: str
    hook_class: str
    producer_kinds: tuple[str, ...]
    audit_critical: str
    fields: Mapping[str, FieldSpec]
    rules: tuple[Rule, ...]
    discriminator: str | None = None
    types: Mapping[str, MutationType] | None = None
    excluded_core_events: Mapping[str, str] | None = None
    act_directions: Mapping[str, str] | None = None
    command_classes: Mapping[str, tuple[str, ...]] | None = None
    action_audit_critical: Mapping[str, ActionAuditRule] | None = None


@dataclass(frozen=True)
class Catalog:
    id: str
    version: int
    hooks: Mapping[str, Hook]
    precedence: tuple[tuple[str, str], ...]

    def superseded_by(self, hook: str) -> tuple[str, ...]:
        """The specific hooks that take an effect away from ``hook``."""
        return tuple(specific for specific, general in self.precedence if general == hook)

    def is_audit_critical(self, hook: str, payload: Mapping[str, Any]) -> bool:
        spec = self.hooks[hook]
        if spec.audit_critical == "always":
            return True
        if spec.audit_critical == "never":
            return False
        if spec.audit_critical == "action_rules":
            assert spec.action_audit_critical is not None
            rule = spec.action_audit_critical.get(str(payload.get("action")))
            return True if rule is None else rule.is_critical(payload)
        assert spec.act_directions is not None
        return spec.act_directions.get(str(payload.get("act"))) == "widening"

    def validate(self, hook: str, payload: Any) -> None:
        """Refuse ``payload`` with its first fault, or return if it is allowed."""
        spec = self.hooks.get(hook)
        if spec is None:
            raise PayloadRefused("unknown_hook")
        if not isinstance(payload, Mapping) or not all(isinstance(k, str) for k in payload):
            raise PayloadRefused("invalid_value")

        fields, rules = spec.fields, spec.rules
        if spec.discriminator is not None:
            assert spec.types is not None
            discriminator = spec.discriminator
            if discriminator not in payload:
                raise PayloadRefused("missing_field", discriminator)
            if not spec.fields[discriminator].accepts(payload[discriminator]):
                raise PayloadRefused("invalid_value", discriminator)
            mutation_type = spec.types[payload[discriminator]]
            fields, rules = mutation_type.fields, spec.rules + mutation_type.rules

        for name in sorted(payload):
            if name not in fields:
                raise PayloadRefused("unknown_field", name)
        for name in sorted(fields):
            if fields[name].required and name not in payload:
                raise PayloadRefused("missing_field", name)
        for name in sorted(payload):
            if not fields[name].accepts(payload[name]):
                raise PayloadRefused("invalid_value", name)
        for rule in rules:
            if rule.applies(payload):
                violation = rule.first_violation(payload)
                if violation is not None:
                    raise PayloadRefused("rule_violation", violation)

        if spec.act_directions is not None:
            if spec.act_directions[payload["act"]] != payload["direction"]:
                raise PayloadRefused("direction_mismatch", "direction")
            if (
                payload["act"] == "resource.changed"
                and payload["before_ref"] == payload["after_ref"]
            ):
                raise PayloadRefused("rule_violation", "after_ref")
        if spec.command_classes is not None:
            allowed = spec.command_classes[payload["command_class"]]
            if any(effect not in allowed for effect in payload["local_effects"]):
                raise PayloadRefused("rule_violation", "local_effects")


@cache
def packaged_catalog() -> Catalog:
    """The aweb.hooks v1 catalog shipped in this package."""
    return load_catalog(files("aweb_naapp.hooks").joinpath("catalog-v1.json").read_bytes())


def load_catalog(data: bytes) -> Catalog:
    """Read a catalog file strictly; refuse anything unknown or inconsistent."""
    try:
        document = json.loads(
            data,
            object_pairs_hook=_unique_object,
            parse_float=_refuse_float,
            parse_constant=_refuse_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CatalogError(f"catalog is not JSON: {exc}") from None
    return _Reader(document).catalog()


def _same(value: Any, expected: Any) -> bool:
    return type(value) is type(expected) and value == expected


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError(f"duplicate key: {key}")
        result[key] = value
    return result


def _refuse_float(text: str) -> None:
    raise CatalogError(f"catalog values are never floats: {text}")


TOP_KEYS = {
    "name",
    "status",
    "catalog",
    "scheme",
    "types",
    "hooks",
    "precedence",
    "positive_cases",
    "negative_cases",
}
SCHEME_KEYS = {
    "authority",
    "payload",
    "unknown_fields",
    "integers",
    "lists",
    "rules",
    "audit_critical",
    "precedence",
    "order",
    "cases",
    "errors",
}
HOOK_KEYS = {"class", "producer_kinds", "audit_critical", "fields", "rules"}
HOOK_OPTIONAL_KEYS = {
    "discriminator",
    "types",
    "excluded_core_events",
    "act_directions",
    "command_classes",
    "action_audit_critical",
}


class _Reader:
    def __init__(self, document: Any) -> None:
        self.document = document
        self.types: dict[str, ValueType] = {}

    def catalog(self) -> Catalog:
        top = self._object(self.document, "catalog file", TOP_KEYS)
        self._object(top["scheme"], "scheme", SCHEME_KEYS)
        if top["scheme"]["errors"] != list(PAYLOAD_ERRORS):
            raise CatalogError("scheme errors differ from the reader's")
        identity = self._object(top["catalog"], "catalog", {"id", "version"})
        catalog_id = self._string(identity["id"], "catalog id")
        version = identity["version"]
        if type(version) is not int or version < 1:
            raise CatalogError("catalog version must be a positive integer")

        for name, spec in self._mapping(top["types"], "types").items():
            self.types[name] = self._value_type(name, spec)

        hooks = {
            name: self._hook(name, spec)
            for name, spec in self._mapping(top["hooks"], "hooks").items()
        }
        precedence = []
        for entry in self._list(top["precedence"], "precedence"):
            entry = self._object(entry, "precedence entry", {"specific", "supersedes"})
            if entry["specific"] not in hooks or entry["supersedes"] not in hooks:
                raise CatalogError(f"precedence names an unknown hook: {entry}")
            precedence.append((entry["specific"], entry["supersedes"]))

        for kind, keys, optional in (
            ("positive_cases", {"name", "hook"}, {"payload", "payload_json"}),
            ("negative_cases", {"name", "hook", "error"}, {"payload", "payload_json", "field"}),
        ):
            for case in self._list(top[kind], kind):
                case = self._object(case, f"{kind} entry", keys, optional)
                if ("payload" in case) == ("payload_json" in case):
                    raise CatalogError(f"{kind} entry needs one of payload and payload_json")

        return Catalog(catalog_id, version, hooks, tuple(precedence))

    def _hook(self, name: str, spec: Any) -> Hook:
        spec = self._object(spec, f"hook {name}", HOOK_KEYS, HOOK_OPTIONAL_KEYS)
        if spec["class"] not in HOOK_CLASSES:
            raise CatalogError(f"hook {name} has an unknown class")
        producers = tuple(self._list(spec["producer_kinds"], f"{name} producer_kinds"))
        if not producers or any(kind not in PRODUCER_KINDS for kind in producers):
            raise CatalogError(f"hook {name} has an unknown producer kind")
        if spec["audit_critical"] not in AUDIT_CRITICAL:
            raise CatalogError(f"hook {name} has an unknown audit_critical value")

        fields = self._fields(name, spec["fields"])
        rules = self._rules(name, spec["rules"], fields)

        discriminator = spec.get("discriminator")
        types = None
        if discriminator is not None:
            if "types" not in spec or discriminator not in fields:
                raise CatalogError(f"hook {name} has a discriminator without types")
            types = {}
            for type_name, type_spec in self._mapping(spec["types"], f"{name} types").items():
                type_spec = self._object(type_spec, f"{name} type {type_name}", {"fields", "rules"})
                own = self._fields(f"{name} {type_name}", type_spec["fields"])
                if set(own) & set(fields):
                    raise CatalogError(f"{name} type {type_name} redefines a common field")
                merged = {**fields, **own}
                types[type_name] = MutationType(
                    type_name,
                    merged,
                    self._rules(f"{name} {type_name}", type_spec["rules"], merged),
                )
            if fields[discriminator].enum != tuple(types):
                raise CatalogError(f"hook {name} discriminator enum differs from its types")
        elif "types" in spec or "excluded_core_events" in spec:
            raise CatalogError(f"hook {name} has types without a discriminator")

        excluded = None
        if "excluded_core_events" in spec:
            excluded = {
                event: self._string(reason, f"{name} exclusion reason")
                for event, reason in self._mapping(
                    spec["excluded_core_events"], f"{name} excluded_core_events"
                ).items()
            }
            if types is not None and set(excluded) & set(types):
                raise CatalogError(f"hook {name} both includes and excludes an event")

        act_directions = None
        if "act_directions" in spec:
            act_directions = dict(self._mapping(spec["act_directions"], f"{name} act_directions"))
            if "act" not in fields or set(act_directions) != set(fields["act"].enum or ()):
                raise CatalogError(f"hook {name} act_directions differ from its act enum")
            if any(direction not in DIRECTIONS for direction in act_directions.values()):
                raise CatalogError(f"hook {name} has an unknown direction")
            if "direction" not in fields or fields["direction"].enum != DIRECTIONS:
                raise CatalogError(f"hook {name} direction field differs from the directions")
        if (spec["audit_critical"] == "widening_acts") != (act_directions is not None):
            raise CatalogError(f"hook {name} audit_critical needs act directions")

        action_audit_critical = None
        if "action_audit_critical" in spec:
            entries = self._mapping(spec["action_audit_critical"], f"{name} action_audit_critical")
            action = fields.get("action")
            if action is None or action.enum is None or set(entries) != set(action.enum):
                raise CatalogError(f"hook {name} audit classification differs from its action enum")
            action_audit_critical = {}
            for action_name, entry in entries.items():
                if type(entry) is bool:
                    action_audit_critical[action_name] = ActionAuditRule(critical=entry)
                    continue
                entry = self._object(entry, f"{name} action {action_name}", {"field", "values"})
                field_name = self._string(entry["field"], f"{name} audit field")
                field = fields.get(field_name)
                values = self._mapping(entry["values"], f"{name} audit values")
                if field is None or field.enum is None or set(values) != set(field.enum):
                    raise CatalogError(f"hook {name} audit values differ from their field enum")
                if any(type(value) is not bool for value in values.values()):
                    raise CatalogError(f"hook {name} audit classifications must be booleans")
                action_audit_critical[action_name] = ActionAuditRule(
                    field=field_name, values=values
                )
        if (spec["audit_critical"] == "action_rules") != (action_audit_critical is not None):
            raise CatalogError(f"hook {name} audit_critical needs action rules")

        command_classes = None
        if "command_classes" in spec:
            command_classes = {
                cls: tuple(self._list(effects, f"{name} class {cls}"))
                for cls, effects in self._mapping(
                    spec["command_classes"], f"{name} command_classes"
                ).items()
            }
            effects = fields.get("local_effects")
            classes = fields.get("command_class")
            if effects is None or effects.item_enum is None or classes is None:
                raise CatalogError(f"hook {name} command classes need their fields")
            if set(command_classes) != set(classes.enum or ()):
                raise CatalogError(f"hook {name} command classes differ from their enum")
            for cls, cls_effects in command_classes.items():
                if not cls_effects or any(e not in effects.item_enum for e in cls_effects):
                    raise CatalogError(f"hook {name} class {cls} names an unknown effect")

        return Hook(
            name=name,
            hook_class=spec["class"],
            producer_kinds=producers,
            audit_critical=spec["audit_critical"],
            fields=fields,
            rules=rules,
            discriminator=discriminator,
            types=types,
            excluded_core_events=excluded,
            act_directions=act_directions,
            command_classes=command_classes,
            action_audit_critical=action_audit_critical,
        )

    def _fields(self, owner: str, specs: Any) -> dict[str, FieldSpec]:
        return {
            name: self._field(f"{owner}.{name}", name, spec)
            for name, spec in self._mapping(specs, f"{owner} fields").items()
        }

    def _field(self, where: str, name: str, spec: Any) -> FieldSpec:
        shapes = {"type", "enum", "list_of", "list_of_enum"}
        if not isinstance(spec, dict):
            raise CatalogError(f"field {where} is not an object")
        present = shapes & set(spec)
        if len(present) != 1:
            raise CatalogError(f"field {where} needs exactly one of {sorted(shapes)}")
        shape = present.pop()
        optional = {"const"}
        keys = {shape, "required"}
        if shape in ("list_of", "list_of_enum"):
            keys |= {"min_items", "max_items"}
        spec = self._object(spec, f"field {where}", keys, optional)
        if type(spec["required"]) is not bool:
            raise CatalogError(f"field {where} required must be a boolean")

        values: dict[str, Any] = {"name": name, "required": spec["required"]}
        if shape == "type":
            values["value_type"] = self._type_ref(where, spec["type"])
        elif shape == "enum":
            values["enum"] = self._enum(where, spec["enum"])
        else:
            minimum, maximum = spec["min_items"], spec["max_items"]
            if type(minimum) is not int or type(maximum) is not int or not 0 <= minimum <= maximum:
                raise CatalogError(f"field {where} has bad list bounds")
            values["min_items"], values["max_items"] = minimum, maximum
            if shape == "list_of":
                values["item_type"] = self._type_ref(where, spec["list_of"])
            else:
                values["item_enum"] = self._enum(where, spec["list_of_enum"])
        if "const" in spec:
            values["const"], values["has_const"] = spec["const"], True
        field = FieldSpec(**values)
        if field.has_const and not FieldSpec(**{**values, "has_const": False}).accepts(field.const):
            raise CatalogError(f"field {where} const is not a valid value")
        return field

    def _rules(self, owner: str, specs: Any, fields: Mapping[str, FieldSpec]) -> tuple[Rule, ...]:
        rules = []
        for spec in self._list(specs, f"{owner} rules"):
            consequences = {"require", "forbid", "require_equals", "require_in"}
            spec = self._object(spec, f"{owner} rule", {"when"}, consequences)
            if not consequences & set(spec):
                raise CatalogError(f"{owner} rule has no consequence")
            when = spec["when"]
            if not isinstance(when, dict) or len(when) != 2 or "field" not in when:
                raise CatalogError(f"{owner} rule has a bad condition")
            condition = self._object(when, f"{owner} rule condition", {"field"}, {"in", "present"})
            when_field = condition["field"]
            if when_field not in fields:
                raise CatalogError(f"{owner} rule names unknown field {when_field}")
            when_in = when_present = None
            if "in" in condition:
                when_in = tuple(self._list(condition["in"], f"{owner} rule values"))
                if not when_in or not all(fields[when_field].accepts(v) for v in when_in):
                    raise CatalogError(f"{owner} rule matches an impossible value")
            else:
                when_present = condition["present"]
                if type(when_present) is not bool:
                    raise CatalogError(f"{owner} rule present must be a boolean")
            require = tuple(self._list(spec.get("require", []), f"{owner} rule require"))
            forbid = tuple(self._list(spec.get("forbid", []), f"{owner} rule forbid"))
            allowed: list[tuple[str, tuple[Any, ...]]] = [
                (name, (value,))
                for name, value in self._mapping(
                    spec.get("require_equals", {}), f"{owner} rule equals"
                ).items()
            ]
            for name, values in self._mapping(
                spec.get("require_in", {}), f"{owner} rule in"
            ).items():
                values = tuple(self._list(values, f"{owner} rule allowed values"))
                if not values:
                    raise CatalogError(f"{owner} rule allows no value for {name}")
                allowed.append((name, values))
            for name in (*require, *forbid, *(name for name, _ in allowed)):
                if name not in fields:
                    raise CatalogError(f"{owner} rule names unknown field {name}")
            for name, values in allowed:
                if not all(fields[name].accepts(value) for value in values):
                    raise CatalogError(f"{owner} rule requires an impossible value for {name}")
            rules.append(Rule(when_field, when_in, when_present, require, forbid, tuple(allowed)))
        return tuple(rules)

    def _value_type(self, name: str, spec: Any) -> ValueType:
        if not isinstance(spec, dict) or "kind" not in spec:
            raise CatalogError(f"type {name} needs a kind")
        kind = spec["kind"]
        if kind == "string":
            spec = self._object(spec, f"type {name}", {"kind", "pattern"})
            try:
                pattern = re.compile(self._string(spec["pattern"], f"type {name} pattern"))
            except re.error as exc:
                raise CatalogError(f"type {name} pattern does not compile: {exc}") from None
            return ValueType(kind, pattern=pattern)
        if kind == "integer":
            spec = self._object(spec, f"type {name}", {"kind", "min", "max"})
            minimum, maximum = spec["min"], spec["max"]
            if (
                type(minimum) is not int
                or type(maximum) is not int
                or not 0 <= minimum <= maximum <= MAX_SAFE_INTEGER
            ):
                raise CatalogError(f"type {name} has bad bounds")
            return ValueType(kind, minimum=minimum, maximum=maximum)
        if kind == "boolean":
            self._object(spec, f"type {name}", {"kind"})
            return ValueType(kind)
        raise CatalogError(f"type {name} has an unknown kind")

    def _type_ref(self, where: str, name: Any) -> ValueType:
        if name not in self.types:
            raise CatalogError(f"field {where} names unknown type {name}")
        return self.types[name]

    def _enum(self, where: str, values: Any) -> tuple[Any, ...]:
        options = tuple(self._list(values, f"field {where} enum"))
        if not options or any(not isinstance(v, (str, bool)) for v in options):
            raise CatalogError(f"field {where} enum must hold strings")
        if len(set(options)) != len(options):
            raise CatalogError(f"field {where} enum repeats a value")
        return options

    @staticmethod
    def _object(
        value: Any, where: str, required: set[str], optional: set[str] | None = None
    ) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise CatalogError(f"{where} is not an object")
        allowed = required | (optional or set())
        unknown = set(value) - allowed
        if unknown:
            raise CatalogError(f"{where} has unknown keys: {sorted(unknown)}")
        missing = required - set(value)
        if missing:
            raise CatalogError(f"{where} lacks keys: {sorted(missing)}")
        return value

    @staticmethod
    def _mapping(value: Any, where: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise CatalogError(f"{where} is not an object")
        return value

    @staticmethod
    def _list(value: Any, where: str) -> list[Any]:
        if not isinstance(value, list):
            raise CatalogError(f"{where} is not a list")
        return value

    @staticmethod
    def _string(value: Any, where: str) -> str:
        if not isinstance(value, str) or not value:
            raise CatalogError(f"{where} must be a non-empty string")
        return value
