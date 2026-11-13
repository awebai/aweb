"""The shared configuration schema of one team's deployment (deploy/team)."""

import copy
import json
from pathlib import Path

import jsonschema
import pytest
import yaml

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
SCHEMA = json.loads((TEAM / "config.schema.json").read_text(encoding="utf-8"))
EXAMPLE = yaml.safe_load((TEAM / "deployment.example.yaml").read_text(encoding="utf-8"))


def refused(config: dict) -> bool:
    return bool(list(jsonschema.Draft202012Validator(SCHEMA).iter_errors(config)))


def changed(path: tuple[str, ...], value) -> dict:
    config = copy.deepcopy(EXAMPLE)
    target = config
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return config


def test_the_schema_is_a_schema_and_accepts_the_example():
    jsonschema.Draft202012Validator.check_schema(SCHEMA)
    assert not refused(EXAMPLE)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("aweb", "image"), "ghcr.io/awebai/aweb:latest"),
        (("aweb", "publicOrigin"), "http://aweb.example.com"),
        (("aweb", "databaseUrl"), "postgresql://aweb:password@postgres:5432/aweb"),
        (("aweb", "secrets"), "../etc"),
        (("postgres", "password"), "password"),
        (("team", "id"), "devteam"),
        (("unknown",), {}),
    ],
)
def test_a_tag_only_image_a_plain_origin_and_any_key_it_does_not_define_are_refused(path, value):
    assert refused(changed(path, value))


def test_every_section_refuses_keys_it_does_not_define():
    # A credential cannot be added under a name the schema does not know.
    def objects(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                yield node
            for child in node.values():
                yield from objects(child)

    assert all(node.get("additionalProperties") is False for node in objects(SCHEMA))
