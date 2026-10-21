"""Immutable owner job definitions (§9.4) and their sole CURRENT resolver.

The passkey-confirmed change-set writer calls create_job. A current pointer
names one digest; edits create another immutable record and require fresh
pins in grants and policies. Jobs are installation-scoped, never scoped to
an individual secret. Credentials refer to the secret slots they consume.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aweb_naapp.pages import inline_schema_errors, inline_value_valid
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager, TransactionManager

from aweb_secrets.operation import CHARSETS
from aweb_secrets.policy import IDENTIFIER
from aweb_secrets.runner_protocol import HEX64, RUNNER_ID, canonical

FIELDS = frozenset(
    {
        "v",
        "job_id",
        "runner_ids",
        "kind",
        "exec",
        "oci",
        "argv",
        "env",
        "cwd",
        "timeout_s",
        "output",
        "params",
        "credentials",
        "allow_durable",
    }
)
DIGEST_PREFIX = b"aweb.secrets.job/1\n"
# S13 must configure runner dispatch sweeping strictly beyond this plus its margin.
MAX_TIMEOUT_S = 3600
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PARAM = re.compile(r"[a-z_][a-z0-9_]{0,63}")
_IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}")
_POINTER = re.compile(r"(/([^~/]|~[01])*)+")
_DANGEROUS_ENV = frozenset(
    {
        "PATH",
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "NODE_OPTIONS",
        "PERL5OPT",
        "RUBYOPT",
        "SSH_ASKPASS",
        "IFS",
        "NODE_PATH",
        "PERL5LIB",
        "PERLLIB",
        "RUBYLIB",
        "PYTHONHOME",
        "PYTHONBREAKPOINT",
        "CLASSPATH",
        "GCONV_PATH",
        "BASHOPTS",
        "SHELLOPTS",
        "PS4",
        "PROMPT_COMMAND",
    }
)


class JobInvalid(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.code = "job_invalid"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise JobInvalid(message)


def _exact(value: Any, fields: set[str], name: str) -> None:
    _require(isinstance(value, dict) and set(value) == fields, name + " shape")


def _absolute(path: Any) -> bool:
    return (
        isinstance(path, str)
        and path.startswith("/")
        and "\0" not in path
        and ".." not in path.split("/")
    )


def _safe_env(name: Any) -> bool:
    return (
        isinstance(name, str)
        and _ENV.fullmatch(name) is not None
        and name not in _DANGEROUS_ENV
        and not name.startswith(("LD_", "DYLD_", "GIT_"))
        and not name.endswith("_OPTIONS")
        and not name.upper().endswith("_PROXY")
    )


def _no_nul(value: Any) -> None:
    if isinstance(value, str):
        _require("\0" not in value, "job record strings contain no NUL")
    elif isinstance(value, dict):
        for key, item in value.items():
            _no_nul(key)
            _no_nul(item)
    elif isinstance(value, list):
        for item in value:
            _no_nul(item)


def _mount_path(path: Any) -> bool:
    return (
        _absolute(path)
        and path != "/"
        and not path.startswith("//")
        and posixpath.normpath(path) == path
    )


def _check(after: dict[str, Any]) -> None:
    _no_nul(after)
    _require(set(after) == FIELDS and type(after["v"]) is int and after["v"] == 1, "job/1 shape")
    _require(
        isinstance(after["job_id"], str) and IDENTIFIER.fullmatch(after["job_id"]) is not None,
        "job id",
    )
    runners = after["runner_ids"]
    _require(
        isinstance(runners, list)
        and bool(runners)
        and all(isinstance(r, str) and RUNNER_ID.fullmatch(r) for r in runners),
        "runner ids",
    )
    _require(runners == sorted(set(runners)), "runner ids sorted and distinct")
    _require(after["kind"] in ("exec", "oci"), "kind is exec or oci")
    if after["kind"] == "exec":
        _require(after["oci"] is None, "exec has no OCI specification")
        e = after["exec"]
        _exact(e, {"path", "sha256", "files"}, "exec")
        _require(
            _absolute(e["path"])
            and isinstance(e["sha256"], str)
            and HEX64.fullmatch(e["sha256"]) is not None,
            "executable pin",
        )
        _require(isinstance(e["files"], list), "declared files")
        paths = []
        for f in e["files"]:
            _exact(f, {"path", "sha256"}, "declared file")
            _require(
                _absolute(f["path"])
                and isinstance(f["sha256"], str)
                and HEX64.fullmatch(f["sha256"]) is not None,
                "declared file pin",
            )
            paths.append(f["path"])
        _require(paths == sorted(set(paths)), "declared paths sorted and distinct")
    else:
        _require(after["exec"] is None, "OCI has no executable specification")
        oci = after["oci"]
        _exact(oci, {"image", "read_only_paths"}, "OCI")
        _require(
            isinstance(oci["image"], str) and _IMAGE.fullmatch(oci["image"]) is not None,
            "image by digest",
        )
        paths = oci["read_only_paths"]
        _require(
            isinstance(paths, list) and all(_mount_path(p) for p in paths),
            "normalized nonroot readonly paths",
        )
        _require(paths == sorted(set(paths)), "readonly paths sorted and distinct")
    _require(_absolute(after["cwd"]), "absolute working directory")
    _require(
        type(after["timeout_s"]) is int and 1 <= after["timeout_s"] <= MAX_TIMEOUT_S,
        "bounded timeout",
    )
    output = after["output"]
    _exact(output, {"max_bytes", "projection"}, "output")
    _require(
        type(output["max_bytes"]) is int and 1 <= output["max_bytes"] <= 16 * 1024 * 1024,
        "bounded output",
    )
    projection = output["projection"]
    _require(
        isinstance(projection, list)
        and bool(projection)
        and all(isinstance(p, str) and _POINTER.fullmatch(p) for p in projection),
        "output projection",
    )
    _require(len(projection) == len(set(projection)), "distinct projection fields")
    params = after["params"]
    _require(isinstance(params, dict), "params object")
    for name, p in params.items():
        _require(_PARAM.fullmatch(name) is not None, "parameter name")
        _exact(p, {"schema", "charset"}, "parameter")
        _require(
            isinstance(p["schema"], dict) and not inline_schema_errors(p["schema"]),
            "bounded typed schema",
        )
        _require(
            p["charset"] is None
            or (
                isinstance(p["charset"], str)
                and p["charset"] in CHARSETS
                and p["schema"]["type"] == "string"
            ),
            "fixed string charset",
        )
    _require(type(after["allow_durable"]) is bool, "durable flag")
    _require(isinstance(after["credentials"], list), "credentials list")
    refs = []
    used_params: set[str] = set()
    for credential in after["credentials"]:
        _exact(credential, {"secret_ref", "delivery", "mint"}, "credential")
        ref = credential["secret_ref"]
        _require(isinstance(ref, str) and IDENTIFIER.fullmatch(ref) is not None, "secret reference")
        _require(credential["delivery"] in ("short_lived", "durable"), "credential delivery")
        _require(
            credential["delivery"] != "durable" or after["allow_durable"],
            "durable requires owner-confirmed flag",
        )
        recipe = credential["mint"]
        if credential["delivery"] == "durable":
            _require(recipe is None, "durable has no mint recipe")
        else:
            _exact(recipe, {"operation_id", "digest", "params"}, "mint recipe")
            _require(
                isinstance(recipe["operation_id"], str)
                and IDENTIFIER.fullmatch(recipe["operation_id"]) is not None,
                "mint operation id",
            )
            _require(
                isinstance(recipe["digest"], str) and HEX64.fullmatch(recipe["digest"]) is not None,
                "mint operation digest",
            )
            _require(isinstance(recipe["params"], dict), "mint parameters object")
            for name, mapping in recipe["params"].items():
                _require(_PARAM.fullmatch(name) is not None, "issuer parameter name")
                _require(isinstance(mapping, dict), "tagged mint parameter mapping")
                if set(mapping) == {"$param"}:
                    _require(
                        isinstance(mapping["$param"], str) and mapping["$param"] in params,
                        "known job parameter in mint recipe",
                    )
                    used_params.add(mapping["$param"])
                else:
                    _exact(mapping, {"value"}, "typed literal")
        refs.append(ref)
    _require(len(refs) == len(set(refs)), "distinct credential references")
    argv = after["argv"]
    _require(isinstance(argv, list), "argv array")
    used_credentials: set[str] = set()
    for i, arg in enumerate(argv):
        if isinstance(arg, str):
            _require("\0" not in arg, "literal argument has no NUL")
            continue
        _exact(arg, {"$param", "slot"}, "argument slot")
        _require(isinstance(arg["$param"], str) and arg["$param"] in params, "known parameter")
        _require(
            params[arg["$param"]]["schema"].get("type") in ("string", "integer", "boolean"),
            "argument parameter is scalar",
        )
        slot = arg["slot"]
        if slot == "positional":
            _require("--" in argv[:i], "positional parameter follows literal --")
        elif slot == "option_value":
            _require(
                i > 0
                and isinstance(argv[i - 1], str)
                and argv[i - 1].startswith("-")
                and argv[i - 1] != "--"
                and "=" not in argv[i - 1]
                and "--" not in argv[:i],
                "option value follows a fixed option",
            )
        else:
            raise JobInvalid("slot is positional or option_value")
        used_params.add(arg["$param"])
    env = after["env"]
    _require(isinstance(env, dict), "env object")
    for name, value in env.items():
        _require(_safe_env(name), "environment target cannot load code or alter resolution")
        if isinstance(value, str):
            _require("\0" not in value, "literal env has no NUL")
        elif (
            isinstance(value, dict)
            and set(value) == {"$param"}
            and isinstance(value["$param"], str)
            and value["$param"] in params
        ):
            _require(
                params[value["$param"]]["schema"].get("type") in ("string", "integer", "boolean"),
                "environment parameter is scalar",
            )
            used_params.add(value["$param"])
        elif (
            isinstance(value, dict)
            and set(value) == {"$credential"}
            and isinstance(value["$credential"], str)
            and value["$credential"] in refs
        ):
            used_credentials.add(value["$credential"])
        else:
            raise JobInvalid("env value is fixed text or one declared parameter/credential")
    _require(used_params == set(params), "each declared parameter has a slot")
    _require(used_credentials == set(refs), "each credential has a declared env target")


@dataclass(frozen=True)
class JobDefinition:
    job_id: str
    digest: str
    _raw: bytes

    @classmethod
    def from_after(cls, after: Mapping[str, Any]) -> JobDefinition:
        try:
            raw = canonical(dict(after))
            body = json.loads(raw)
            _check(body)
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            if isinstance(exc, JobInvalid):
                raise
            raise JobInvalid("invalid job/1 JSON value") from None
        return cls(
            body["job_id"],
            hashlib.sha256(
                DIGEST_PREFIX + canonical({k: v for k, v in body.items() if k != "v"})
            ).hexdigest(),
            raw,
        )

    @property
    def after(self) -> dict[str, Any]:
        return json.loads(self._raw)

    def params_valid(self, params: Mapping[str, Any]) -> bool:
        body = self.after
        declared = body["params"]
        if not isinstance(params, Mapping) or set(params) != set(declared):
            return False
        try:
            canonical(dict(params))
        except (ValueError, TypeError, RecursionError):
            return False
        positional = {
            a["$param"] for a in body["argv"] if isinstance(a, dict) and a["slot"] == "positional"
        }
        for name, value in params.items():
            schema = declared[name]
            if not inline_value_valid(schema["schema"], value):
                return False
            if isinstance(value, str) and (
                "\0" in value or name in positional and value.startswith("-")
            ):
                return False
            if schema["charset"] is not None and not CHARSETS[schema["charset"]].fullmatch(value):
                return False
        return True

    def expand_mint_params(self, slot: int, params: Mapping[str, Any]) -> dict[str, Any]:
        """Expand tagged recipe mappings without coercion, after job-parameter checks.

        This supplies no mint authority. The caller must resolve the parent's
        CURRENT issuer pin and validate these values against its constraints.
        """
        if not self.params_valid(params):
            raise JobRefused("params_invalid")
        credentials = self.after["credentials"]
        if type(slot) is not int or not 0 <= slot < len(credentials):
            raise JobRefused("job_not_allowed")
        recipe = credentials[slot]["mint"]
        if recipe is None:
            raise JobRefused("operation_not_allowed")
        return {
            name: mapping["value"] if "value" in mapping else params[mapping["$param"]]
            for name, mapping in recipe["params"].items()
        }


async def apply_job_migrations(db: AsyncDatabaseManager) -> None:
    await AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "job_migrations"),
        module_name="aweb_secrets_jobs",
    ).apply_pending_migrations()


async def create_job(
    tx: TransactionManager, installation_id: str, team_id: str, job: JobDefinition
) -> None:
    """Write a passkey-confirmed definition and point CURRENT at its digest."""
    await tx.execute(
        "INSERT INTO {{tables.job_definitions}} (installation_id,team_id,job_id,digest,record) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING",
        installation_id,
        team_id,
        job.job_id,
        job.digest,
        json.dumps(job.after),
    )
    await tx.execute(
        "INSERT INTO {{tables.current_jobs}} (installation_id,job_id,digest) VALUES ($1,$2,$3) ON CONFLICT (installation_id,job_id) DO UPDATE SET digest=EXCLUDED.digest",
        installation_id,
        job.job_id,
        job.digest,
    )


async def current_job(
    tx: TransactionManager, installation_id: str, job_id: str
) -> JobDefinition | None:
    raw = await tx.fetch_value(
        "SELECT d.record FROM {{tables.current_jobs}} c JOIN {{tables.job_definitions}} d USING (installation_id,job_id,digest) WHERE c.installation_id=$1 AND c.job_id=$2 FOR SHARE OF c",
        installation_id,
        job_id,
    )
    return None if raw is None else JobDefinition.from_after(json.loads(raw))


async def job_by_digest(
    tx: TransactionManager, installation_id: str, job_id: str, digest: str
) -> JobDefinition | None:
    raw = await tx.fetch_value(
        "SELECT record FROM {{tables.job_definitions}} WHERE installation_id=$1 AND job_id=$2 AND digest=$3",
        installation_id,
        job_id,
        digest,
    )
    return None if raw is None else JobDefinition.from_after(json.loads(raw))


class JobRefused(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


async def resolve_job_pin(
    tx: TransactionManager,
    installation_id: str,
    job_id: str,
    approved_digest: str,
) -> JobDefinition:
    """Resolve exactly CURRENT then compare the pin; history never supplies authority."""
    job = await current_job(tx, installation_id, job_id)
    if job is None or job.digest != approved_digest:
        raise JobRefused("job_not_allowed")
    return job


def unique_durable_slot(job: JobDefinition, *, lineage_refs: Sequence[str]) -> int:
    """Return the one durable selector matching a child or any of its ancestors.

    The caller obtains these refs from the shared, same-installation/team
    lineage check and freezes the resulting ordinal with the actual child ID.
    This pure selector supplies no grant or mint authority and does not check
    run binding. The release fence rechecks those boundaries and the lineage.
    Exact child matches have no priority over ancestors; ambiguity refuses.
    """
    refs = set(lineage_refs)
    matches = [
        ordinal
        for ordinal, slot in enumerate(job.after["credentials"])
        if slot["delivery"] == "durable" and slot["secret_ref"] in refs
    ]
    if len(matches) != 1:
        raise JobRefused("job_not_allowed")
    return matches[0]
