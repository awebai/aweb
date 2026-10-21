"""Runner-local job pins and execution preparation; no service authority or registry."""

import hashlib
import json
import posixpath
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aweb_naapp.pages import inline_schema_errors, inline_value_valid
from aweb_secrets_values import CAPTURE_FIELDS, ValueInvalid, decode_value
from aweb_secrets_values.redaction import KnownValues
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import Refused
from .filesystem import FileGuard, require_separate_users
from .protocol import HASH, ID, canonical, decrypt_credential, parse_json

FIELDS = {
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
IDENTIFIER = r"[a-z0-9][a-z0-9_-]{0,63}"
CHARSETS = {
    "digits": r"[0-9]+",
    "hex": r"[0-9a-f]+",
    "alnum": r"[A-Za-z0-9]+",
    "slug": r"[a-z0-9][a-z0-9_-]*",
    "base64url": r"[A-Za-z0-9_-]+",
}
DENIED_ENV = {
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


def _need(condition: Any) -> None:
    if not condition:
        raise Refused("job_invalid")


def _exact(value: Any, keys: set[str]) -> None:
    _need(isinstance(value, dict) and set(value) == keys)


def _match(pattern: str, value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def _path(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("/") and ".." not in value.split("/")


def _no_nul(value: Any) -> None:
    if isinstance(value, str):
        _need("\0" not in value)
    elif isinstance(value, list):
        for item in value:
            _no_nul(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            _no_nul(key)
            _no_nul(item)


def _family(fields: set[str]) -> str:
    families = [
        kind
        for kind in ("bearer", "basic", "oauth2-client-credentials", "aws-sigv4")
        if fields and fields <= (CAPTURE_FIELDS[kind][0] | CAPTURE_FIELDS[kind][1])
    ]
    _need(len(families) == 1)
    return families[0]


def job_digest(definition: dict[str, Any]) -> str:
    return hashlib.sha256(
        b"aweb.secrets.job/1\n" + canonical({k: v for k, v in definition.items() if k != "v"})
    ).hexdigest()


def _check(job: dict[str, Any]) -> None:
    _exact(job, FIELDS)
    _no_nul(job)
    _need(type(job["v"]) is int and job["v"] == 1 and _match(IDENTIFIER, job["job_id"]))
    runners = job["runner_ids"]
    _need(isinstance(runners, list) and runners and all(_match("rnr_" + ID, r) for r in runners))
    _need(runners == sorted(set(runners)))
    _need(job["kind"] in ("exec", "oci"))
    if job["kind"] == "exec":
        _need(job["oci"] is None)
        spec = job["exec"]
        _exact(spec, {"path", "sha256", "files"})
        _need(_path(spec["path"]) and _match(HASH, spec["sha256"]))
        _need(isinstance(spec["files"], list))
        paths = []
        for item in spec["files"]:
            _exact(item, {"path", "sha256"})
            _need(_path(item["path"]) and _match(HASH, item["sha256"]))
            paths.append(item["path"])
        _need(paths == sorted(set(paths)))
    else:
        _need(job["exec"] is None)
        _exact(job["oci"], {"image", "read_only_paths"})
        _need(_match(r"[A-Za-z0-9][A-Za-z0-9./:_-]*@sha256:[0-9a-f]{64}", job["oci"]["image"]))
        paths = job["oci"]["read_only_paths"]
        _need(
            isinstance(paths, list)
            and all(
                _path(p) and p != "/" and not p.startswith("//") and posixpath.normpath(p) == p
                for p in paths
            )
        )
        _need(paths == sorted(set(paths)))
    _need(_path(job["cwd"]))
    _need(type(job["timeout_s"]) is int and 1 <= job["timeout_s"] <= 3600)
    _exact(job["output"], {"max_bytes", "projection"})
    _need(
        type(job["output"]["max_bytes"]) is int
        and 1 <= job["output"]["max_bytes"] <= 16 * 1024 * 1024
    )
    projection = job["output"]["projection"]
    _need(
        isinstance(projection, list)
        and projection
        and all(_match(r"(/([^~/]|~[01])*)+", p) for p in projection)
    )
    _need(len(projection) == len(set(projection)))
    params = job["params"]
    _need(isinstance(params, dict))
    for name, spec in params.items():
        _need(_match(r"[a-z_][a-z0-9_]{0,63}", name))
        _exact(spec, {"schema", "charset"})
        _need(isinstance(spec["schema"], dict) and not inline_schema_errors(spec["schema"]))
        _need(
            spec["charset"] is None
            or spec["charset"] in CHARSETS
            and spec["schema"].get("type") == "string"
        )
    credentials = job["credentials"]
    _need(type(job["allow_durable"]) is bool and isinstance(credentials, list))
    refs = []
    used_params = set()
    for slot in credentials:
        _exact(slot, {"secret_ref", "delivery", "mint"})
        _need(
            _match(IDENTIFIER, slot["secret_ref"])
            and slot["delivery"] in ("durable", "short_lived")
        )
        refs.append(slot["secret_ref"])
        if slot["delivery"] == "durable":
            _need(job["allow_durable"] and slot["mint"] is None)
        else:
            recipe = slot["mint"]
            _exact(recipe, {"operation_id", "digest", "params"})
            _need(
                _match(IDENTIFIER, recipe["operation_id"])
                and _match(HASH, recipe["digest"])
                and isinstance(recipe["params"], dict)
            )
            for name, mapping in recipe["params"].items():
                _need(_match(r"[a-z_][a-z0-9_]{0,63}", name) and isinstance(mapping, dict))
                if set(mapping) == {"$param"}:
                    _need(isinstance(mapping["$param"], str) and mapping["$param"] in params)
                    used_params.add(mapping["$param"])
                else:
                    _exact(mapping, {"value"})
    _need(len(refs) == len(set(refs)) and isinstance(job["argv"], list))
    if job["kind"] == "oci":
        # OCI argv is complete; image defaults never supply an executable.
        _need(job["argv"] and _path(job["argv"][0]))
    for index, arg in enumerate(job["argv"]):
        if isinstance(arg, str):
            continue
        _exact(arg, {"$param", "slot"})
        _need(isinstance(arg["$param"], str) and arg["$param"] in params)
        _need(params[arg["$param"]]["schema"].get("type") in ("string", "integer", "boolean"))
        if arg["slot"] == "positional":
            _need("--" in job["argv"][:index])
        else:
            previous = job["argv"][index - 1] if index else None
            _need(
                arg["slot"] == "option_value"
                and isinstance(previous, str)
                and previous.startswith("-")
                and previous != "--"
                and "=" not in previous
                and "--" not in job["argv"][:index]
            )
        used_params.add(arg["$param"])
    _need(isinstance(job["env"], dict))
    selected: dict[str, set[str]] = {ref: set() for ref in refs}
    for name, binding in job["env"].items():
        _need(
            _match(r"[A-Za-z_][A-Za-z0-9_]*", name)
            and name not in DENIED_ENV
            and not name.startswith(("LD_", "DYLD_", "GIT_"))
            and not name.endswith("_OPTIONS")
            and not name.upper().endswith("_PROXY")
        )
        if isinstance(binding, str):
            continue
        _need(isinstance(binding, dict))
        if set(binding) == {"$param"}:
            _need(isinstance(binding["$param"], str) and binding["$param"] in params)
            _need(
                params[binding["$param"]]["schema"].get("type") in ("string", "integer", "boolean")
            )
            used_params.add(binding["$param"])
        else:
            _exact(binding, {"$credential", "field"})
            _need(
                isinstance(binding["$credential"], str)
                and binding["$credential"] in selected
                and isinstance(binding["field"], str)
            )
            selected[binding["$credential"]].add(binding["field"])
    _need(used_params == set(params))
    for fields in selected.values():
        _family(fields)


@dataclass(frozen=True)
class PreparedJob:
    kind: str
    argv: tuple[str, ...]
    cwd: str
    timeout_s: int
    output_max_bytes: int
    env: dict[str, str] = field(repr=False)
    known: KnownValues = field(repr=False)
    image: str | None = None
    read_only_paths: tuple[str, ...] = ()


@dataclass(frozen=True, repr=False)
class CredentialInput:
    """An actual signed ref and a deferred, local HPKE opening operation."""

    secret_ref: str
    sealed: str
    key: X25519PrivateKey
    dispatch_id: str

    def open(self) -> bytes:
        return decrypt_credential(self.sealed, self.key, self.dispatch_id)


def _checked_executable(job: dict[str, Any]) -> Path:
    guard = FileGuard()
    if job["kind"] != "exec":
        raise Refused("runner_runtime_unavailable")
    spec = job["exec"]
    executable = guard.pinned_file(spec["path"], spec["sha256"], executable=True)
    for item in spec["files"]:
        guard.pinned_file(item["path"], item["sha256"])
    guard.directory(job["cwd"])
    return executable


@dataclass(frozen=True, repr=False)
class RunnerConfig:
    _raw: bytes
    _source: Path

    @classmethod
    def load(cls, path: Path) -> "RunnerConfig":
        try:
            raw = FileGuard().read_config(path)
            config = parse_json(raw)
            _exact(config, {"v", "agent_uids", "jobs"})
            _need(type(config["v"]) is int and config["v"] == 1)
            _need(isinstance(config["agent_uids"], list))
            require_separate_users(config["agent_uids"])
            _need(isinstance(config["jobs"], dict))
            for name, pin in config["jobs"].items():
                _exact(pin, {"digest", "definition"})
                _need(isinstance(pin["definition"], dict))
                _check(pin["definition"])
                _need(
                    name == pin["definition"]["job_id"]
                    and pin["digest"] == job_digest(pin["definition"])
                )
            return cls(canonical(config), path)
        except (ValueError, KeyError, TypeError, RecursionError):
            raise Refused("job_invalid") from None

    def _current(self) -> dict[str, Any]:
        try:
            current = canonical(parse_json(FileGuard().read_config(self._source)))
        except (ValueError, TypeError, RecursionError):
            raise Refused("config_invalid") from None
        if current != self._raw:
            raise Refused("config_changed")
        config = json.loads(self._raw)
        require_separate_users(config["agent_uids"])
        return dict(config)

    def doctor(self, runner_id: str) -> tuple[str, ...]:
        config = self._current()
        for pin in config["jobs"].values():
            job = pin["definition"]
            if runner_id not in job["runner_ids"]:
                raise Refused("job_not_allowed")
            _checked_executable(job)
        return tuple(sorted(config["jobs"]))

    def prepare(
        self,
        *,
        job_id: str,
        digest: str,
        runner_id: str,
        params: dict[str, Any],
        credentials: list[CredentialInput],
    ) -> PreparedJob:
        config = self._current()
        pin = config["jobs"].get(job_id)
        if (
            pin is None
            or pin["digest"] != digest
            or runner_id not in pin["definition"]["runner_ids"]
        ):
            raise Refused("job_not_allowed")
        job = pin["definition"]
        try:
            canonical(params)
            if not isinstance(params, dict) or set(params) != set(job["params"]):
                raise ValueError("params")
            positional = {
                a["$param"]
                for a in job["argv"]
                if isinstance(a, dict) and a["slot"] == "positional"
            }
            for name, value in params.items():
                spec = job["params"][name]
                if (
                    not inline_value_valid(spec["schema"], value)
                    or isinstance(value, str)
                    and ("\0" in value or name in positional and value.startswith("-"))
                ):
                    raise ValueError("params")
                if spec["charset"] is not None and not re.fullmatch(
                    CHARSETS[spec["charset"]], value
                ):
                    raise ValueError("charset")
        except (ValueError, TypeError, RecursionError):
            raise Refused("params_invalid") from None
        # No credential is opened until every local pin, parameter and file
        # check is complete. OCI stays closed until its image runtime exists.
        executable = _checked_executable(job)
        known = KnownValues()
        opened: dict[str, tuple[str, dict[str, str]]] = {}
        if len(credentials) != len(job["credentials"]) or any(
            not isinstance(credential, CredentialInput)
            or credential.secret_ref != job["credentials"][index]["secret_ref"]
            for index, credential in enumerate(credentials)
        ):
            # First-release FIXED-selector release only. Accepted substituted
            # child paths remain guarded; enabling them needs the reviewed
            # signed-ordinal rules, never a global ref==parent-label rule.
            raise Refused("credential_invalid")
        try:
            for index, slot in enumerate(job["credentials"]):
                credential = credentials[index]
                ref = slot["secret_ref"]
                fields = {
                    binding["field"]
                    for binding in job["env"].values()
                    if isinstance(binding, dict) and binding.get("$credential") == ref
                }
                kind = _family(fields)
                value = decode_value(kind, credential.open())
                if any(name not in value or "\0" in value[name] for name in fields):
                    raise ValueError("selected field")
                opened[ref] = (credential.secret_ref, value)
                for item in value.values():
                    if item:
                        known.add(ref, item)
                if kind == "basic":
                    known.add_basic(ref, value["username"], value["password"])
        except (ValueInvalid, ValueError):
            raise Refused("credential_invalid") from None
        argv = [
            arg if isinstance(arg, str) else _scalar(params[arg["$param"]]) for arg in job["argv"]
        ]
        env = {}
        for name, binding in job["env"].items():
            if isinstance(binding, str):
                env[name] = binding
            elif "$param" in binding:
                env[name] = _scalar(params[binding["$param"]])
            else:
                env[name] = opened[binding["$credential"]][1][binding["field"]]
        argv.insert(0, str(executable))
        return PreparedJob(
            kind=job["kind"],
            argv=tuple(argv),
            env=env,
            cwd=job["cwd"],
            timeout_s=job["timeout_s"],
            output_max_bytes=job["output"]["max_bytes"],
            known=known,
            image=job["oci"]["image"] if job["kind"] == "oci" else None,
            read_only_paths=tuple(job["oci"]["read_only_paths"]) if job["kind"] == "oci" else (),
        )


def _scalar(value: Any) -> str:
    if isinstance(value, str) and "\0" not in value:
        return value
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    raise Refused("params_invalid")
