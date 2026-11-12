"""Render a team's deployment.yaml to the env file the Compose layer reads.

    python render_env.py deployment.yaml > .env

The file is checked against config.schema.json first. Each input that the
schema marks with ``x-env`` becomes that setting, with the schema's default
when the file does not give it. The output holds no credential, because the
schema has no key that could hold one.
"""

import json
import sys
from pathlib import Path

import jsonschema
import yaml

SCHEMA = json.loads((Path(__file__).parent / "config.schema.json").read_text(encoding="utf-8"))


class Refused(Exception):
    """The configuration cannot be rendered; the message never quotes a value."""


def _resolved(node: dict) -> dict:
    """The node with its ``$ref`` target's keywords under its own."""
    if "$ref" not in node:
        return node
    target = SCHEMA
    for part in node["$ref"].removeprefix("#/").split("/"):
        target = target[part]
    return {**target, **node}


def _check(config: object) -> None:
    errors = sorted(
        jsonschema.Draft202012Validator(SCHEMA).iter_errors(config), key=lambda e: list(map(str, e.path))
    )
    if not errors:
        return
    said = []
    for error in errors:
        where = ".".join(map(str, error.path)) or "the file"
        if error.validator == "additionalProperties":
            unknown = sorted(set(error.instance) - set(error.schema.get("properties", {})))
            said.append(f"{where}: no such key: {', '.join(unknown)}")
        elif error.validator == "required":
            missing = sorted(set(error.validator_value) - set(error.instance))
            said.append(f"{where}: missing {', '.join(missing)}")
        else:
            said.append(f"{where}: not a valid value ({error.validator})")
    raise Refused("; ".join(said))


def _collect(schema: dict, value: object, out: dict[str, str]) -> None:
    schema = _resolved(schema)
    if schema.get("type") == "object":
        given = value if isinstance(value, dict) else {}
        for key, child in schema.get("properties", {}).items():
            _collect(child, given.get(key), out)
        return
    name = schema.get("x-env")
    if name is None:
        return
    if value is None:
        value = schema.get("default")
    if value is None:
        return
    # A list or a boolean keeps its JSON form: the service parses it as JSON.
    out[name] = value if isinstance(value, str) else json.dumps(value)


# The components an operator can leave out, each in its own Compose file.
OPTIONAL_COMPONENTS = ("secrets", "logs", "signer", "agents")

# Where the signer's public configuration is mounted, outside its secrets.
SIGNER_CONFIG = "/etc/aweb/signer"


def _check_signer_profile(config: dict, registry_url: str) -> None:
    """The bundle and the signer's profile name the same origins and registry."""
    signer = config["signer"]
    try:
        profile = json.loads(Path(signer["profileFile"]).read_text(encoding="utf-8"))
        named = {
            "signer.requestOrigin": (profile["request_origin"], signer["requestOrigin"]),
            "signer.humanOrigin": (profile["human_origin"], signer["humanOrigin"]),
            "team.registryUrl": (profile["registry_origin"], registry_url),
        }
    except (OSError, ValueError, TypeError, KeyError):
        raise Refused("signer.profileFile: cannot be read as a protected service profile") from None
    differ = [key for key, (in_profile, given) in named.items() if in_profile != given]
    if differ:
        raise Refused(f"{', '.join(differ)}: not the one signer.profileFile names")


def render(config: object) -> dict[str, str]:
    """The settings of the Compose layer for this configuration."""
    _check(config)
    if "compose" not in config:
        raise Refused("compose: missing; the Compose layer needs compose.secretsDir")
    if "servicesCidr" not in config.get("network", {}):
        raise Refused("network.servicesCidr: missing; the Compose layer creates the services network with it")
    if "agents" in config and "compose" not in config["agents"]:
        raise Refused("agents: missing compose; the Compose layer needs agents.compose")
    if "agents" in config:
        # Agents reach nothing but through egress, whose DNS answers for the
        # namespaces the signer's profile names, and only the five origins of
        # aweb, Secrets, Logs, the signer's requests and the registry.
        for needed in ("signer", "egress", "secrets", "logs"):
            if needed not in config:
                raise Refused(f"agents: requires {needed}")
        # The signer refuses custody that a worker's uid could read; it has to know the agents' uid.
        if config["agents"].get("uid", 20001) not in config["signer"]["workerUids"]:
            raise Refused("signer.workerUids: does not name agents.uid")
    out: dict[str, str] = {}
    # A component the file leaves out is not deployed: none of its defaults is rendered.
    for section, schema in SCHEMA["properties"].items():
        if section in config:
            _collect(schema, config[section], out)
    if "signer" in config:
        _check_signer_profile(config, out["AWID_REGISTRY_URL"])
        out["SIGNER_PROFILE_FILE"] = f"{SIGNER_CONFIG}/profile.json"
        out["SIGNER_SCOPE_FILE"] = f"{SIGNER_CONFIG}/scope.json"
        if "emailCaFile" in config["signer"]:
            out["AWEB_PROTECTED_EMAIL_CA_FILE"] = f"{SIGNER_CONFIG}/email-ca.pem"
    if "agents" in config:
        out["EGRESS_ADDRESS"] = config["agents"]["resolverIp"]
        # The name the agent's own Compose file gives the network; the
        # deployment's agents network takes its place.
        out["AGENTS_NETWORK"] = "agents"
        out["TEAM_LOGIN_DIR"] = f"{config['compose']['secretsDir']}/{out['AGENTS_SECRETS']}"
    # Secrets holds its custody key as a mounted file unless the operator names a KMS key.
    if "secrets" in config and "kmsKeyId" not in config["secrets"]:
        out["SECRETS_CUSTODY_KEY_FILE"] = "/run/secrets/secrets/custody-key"
    # aweb fetches app manifests from internal addresses only inside the services range.
    if "appInternalOrigins" in config["aweb"]:
        out["AWEB_APP_INTERNAL_CIDR"] = config["network"]["servicesCidr"]
    # An app takes the three settings of internal hook destinations together.
    for app in ("secrets", "logs"):
        if "hookInternalOrigins" in config.get(app, {}):
            out[f"{app.upper()}_HOOK_INTERNAL_DESTINATIONS"] = "allowed"
            out[f"{app.upper()}_HOOK_INTERNAL_CIDR"] = config["network"]["servicesCidr"]
    # A component the operator leaves out has no file in the model.
    out["COMPOSE_FILE"] = ":".join(
        ["compose.yaml", *(f"compose.{name}.yaml" for name in OPTIONAL_COMPONENTS if name in config)]
    )
    if config["postgres"].get("bundled", True):
        out["COMPOSE_PROFILES"] = "postgres"
    return out


def env_file(settings: dict[str, str]) -> str:
    for name, value in settings.items():
        if any(character in value for character in "\n\r\0"):
            raise Refused(f"{name}: a value cannot hold a line break")
    return "".join(f"{name}={settings[name]}\n" for name in sorted(settings))


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: render_env.py deployment.yaml", file=sys.stderr)
        return 2
    try:
        config = yaml.safe_load(Path(argv[1]).read_text(encoding="utf-8"))
        sys.stdout.write(env_file(render(config)))
    except (OSError, yaml.YAMLError) as exc:
        print(f"render_env: {argv[1]} cannot be read: {type(exc).__name__}", file=sys.stderr)
        return 1
    except Refused as refused:
        print(f"render_env: {refused}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
