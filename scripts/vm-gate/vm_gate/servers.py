"""The controller side of `vm-gate run --project servers`: admit one reviewed spec and ship it.

`vm-gate run --project servers --repo <servers bundle> --sha S --intent train
--machine M --receipt R --steps SPEC` runs the spec's steps in one guest with
servers_run.py. The spec is the reviewed input: every source is an author's
bundle with its sha256, the ref that holds it and the commit; every step names
its user, its checkout, its command, its expected exit, the lines and files it
must show and the artifacts it keeps. Nothing about a particular rehearsal is
known here.

Admission refuses before boot unless every bundle has its author's digest and
holds its commit at its ref, --repo and --sha are the servers source, and every
step is well formed. Steps run as the gate user; a root step is refused.
"""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from .admission import validate_command
from .errors import Refused
from .executor import LOGS, REMOTE, Executor

SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
PINNED_IMAGE = re.compile(r"[^\s@]+@sha256:[0-9a-f]{64}")
GUEST_SPEC = REMOTE + "/servers-spec.json"
GUEST_BUNDLES = REMOTE + "/bundles"
GUEST_SOURCES = REMOTE + "/sources"
GUEST_RUNS = REMOTE + "/runs"
GUEST_OUT = LOGS + "/servers"
STEP_FIELDS = {
    "name",
    "user",
    "cwd",
    "command",
    "expect_exit",
    "needs",
    "require",
    "forbid",
    "json",
    "files",
    "inputs",
    "artifacts",
    "optional_artifacts",
}


def sha256(path):
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def bundle_commit(bundle, ref):
    """The commit the bundle holds at ref, read with git itself."""
    listed = subprocess.run(
        ["git", "bundle", "list-heads", str(bundle), ref],
        capture_output=True,
        text=True,
    )
    heads = [
        line.split()[0]
        for line in listed.stdout.splitlines()
        if line.split()[1:] == [ref]
    ]
    return heads[0] if listed.returncode == 0 and len(heads) == 1 else None


def admit_step(step, seen, sources):
    name = step.get("name")
    if not isinstance(name, str) or not NAME.fullmatch(name) or name in seen:
        raise Refused(f"step name {name!r} must be a unique short slug")
    unknown = set(step) - STEP_FIELDS
    if unknown:
        raise Refused(f"step {name} has unknown fields: {', '.join(sorted(unknown))}")
    if step.get("user") != "gateuser":
        raise Refused(
            f"step {name} runs as {step.get('user')!r}: a servers step runs as gateuser"
        )
    if step.get("cwd") not in sources:
        raise Refused(f"step {name} runs in {step.get('cwd')!r}, which is not a source")
    if not isinstance(step.get("command"), str):
        raise Refused(f"step {name} needs a command")
    validate_command(step["command"])
    expected = step.get("expect_exit")
    if not (expected == "nonzero" or (type(expected) is int and 0 <= expected <= 255)):
        raise Refused(f'step {name}: expect_exit is an exit code or "nonzero"')
    for need in step.get("needs", []):
        if need not in seen:
            raise Refused(f"step {name} needs {need!r}, which is not an earlier step")
    for pattern in step.get("require", []) + step.get("forbid", []):
        try:
            re.compile(pattern)
        except (re.error, TypeError) as error:
            raise Refused(
                f"step {name}: line pattern {pattern!r} is not a regular expression: {error}"
            ) from None
    for item in step.get("inputs", []):
        producer = seen.get(item.get("from"))
        if producer is None or item.get("path") not in producer.get("files", []):
            raise Refused(
                f"step {name}'s input {item!r} is not a file an earlier step records"
            )
        if item.get("from") not in step.get("needs", []):
            raise Refused(
                f"step {name} takes {item['from']}'s file, so it needs {item['from']}"
            )
    for relative in (
        step.get("files", [])
        + step.get("artifacts", [])
        + step.get("optional_artifacts", [])
        + [i["to"] for i in step.get("inputs", [])]
        + [i["path"] for i in step.get("inputs", [])]
    ):
        path = relative.removeprefix("{run_dir}/")
        if (
            not isinstance(relative, str)
            or path.startswith("/")
            or ".." in Path(path).parts
        ):
            raise Refused(
                f"step {name}: {relative!r} must be a path inside its checkout or run directory"
            )


def admit(spec_path, repo, sha):
    """The reviewed spec, its digest and the sources to ship, or a refusal before boot."""
    try:
        text = Path(spec_path).read_bytes()
        spec = json.loads(text)
    except (OSError, ValueError) as error:
        raise Refused(f"--steps is not a readable JSON spec: {error}") from None
    sources = spec.get("sources")
    if not isinstance(sources, dict) or "servers" not in sources:
        raise Refused("the spec names its sources, servers among them")
    shipped = {}
    for name, source in sources.items():
        if not NAME.fullmatch(name):
            raise Refused(f"source name {name!r} must be a short slug")
        bundle = Path(source.get("bundle", ""))
        if not bundle.is_file():
            raise Refused(f"source {name}: no bundle at {bundle}")
        if not DIGEST.fullmatch(source.get("bundle_sha256", "")) or not SHA.fullmatch(
            source.get("commit", "")
        ):
            raise Refused(
                f"source {name} needs its author's bundle_sha256 and a full commit"
            )
        digest = sha256(bundle)
        if digest != source["bundle_sha256"]:
            raise Refused(
                f"source {name}: the bundle is {digest}, not its author's {source['bundle_sha256']}"
            )
        held = bundle_commit(bundle, source.get("ref", ""))
        if held != source["commit"]:
            raise Refused(
                f"source {name}: {source.get('ref')} in the bundle is {held}, not {source['commit']}"
            )
        shipped[name] = bundle
    if (
        Path(repo).resolve() != shipped["servers"].resolve()
        or sha != sources["servers"]["commit"]
    ):
        raise Refused("--repo and --sha are the spec's servers bundle and its commit")
    registry = spec.get("registry")
    if registry is not None:
        if not PINNED_IMAGE.fullmatch(registry.get("image", "")):
            raise Refused("the registry image is pinned by digest")
        if (
            not NAME.fullmatch(registry.get("name", ""))
            or type(registry.get("port")) is not int
        ):
            raise Refused("the registry needs a name and a port")
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        raise Refused("the spec has at least one step")
    seen = {}
    for step in steps:
        admit_step(step, seen, sources)
        seen[step["name"]] = step
    return {
        "spec_sha256": "sha256:" + hashlib.sha256(text).hexdigest(),
        # The guest gets the reviewed bytes themselves, read once here.
        "spec_bytes": text,
        "bundles": shipped,
        "sources": {
            name: {
                "ref": source["ref"],
                "commit": source["commit"],
                "author_bundle_sha256": source["bundle_sha256"],
            }
            for name, source in sources.items()
        },
    }


def command(spec_sha256):
    """The guest step: the runner over the shipped spec, which it checks against the admitted digest."""
    return (
        f"python3 {REMOTE}/operator/vm_gate/servers_run.py {GUEST_SPEC} {GUEST_OUT} "
        f"--spec-sha256 {spec_sha256} "
        f"--bundles {GUEST_BUNDLES} --sources {GUEST_SOURCES} --runs {GUEST_RUNS}"
    )


class ServersExecutor(Executor):
    """The guest executor with the spec and its bundles placed before the run."""

    def __init__(self, config, directory, source, command, provider, *, servers):
        super().__init__(config, directory, source, command, provider)
        self.servers = servers

    def prepare(self, server, timeout):
        super().prepare(server, timeout)
        self.run(
            f"install -d -m 0755 -o root -g root {GUEST_BUNDLES} && "
            f"install -d -m 0755 -o gateuser -g gateuser {GUEST_SOURCES} {GUEST_RUNS}",
            "servers-directories",
        )
        spec = Path(self.directory) / "servers-spec.json"
        spec.write_bytes(self.servers["spec_bytes"])
        self.upload(spec, GUEST_SPEC, mode="0444")
        for name, bundle in self.servers["bundles"].items():
            local = Path(self.directory) / f"{name}.bundle"
            shutil.copyfile(bundle, local)
            self.upload(local, f"{GUEST_BUNDLES}/{name}.bundle", mode="0444")


def result(evidence):
    """What the runner wrote in the guest, or None when it wrote nothing."""
    path = Path(evidence) / ("var/log/vm-gate/servers/result.json")
    exit_file = Path(evidence) / ("var/log/vm-gate/servers/exit")
    value = exit_file.read_text().strip() if exit_file.exists() else ""
    return (json.loads(path.read_text()) if path.exists() else None), (
        int(value) if value.isdigit() else None
    )


def infrastructure(record):
    """Why the run's record cannot be judged, or None: no record, another spec, or a runner or collector failure."""
    run = record.get("result")
    if run is None:
        return "the runner left no record"
    if run.get("spec_sha256") != record.get("spec_sha256"):
        return f"the guest ran spec {run.get('spec_sha256')}, not the admitted {record.get('spec_sha256')}"
    if run.get("error"):
        return "the runner failed: " + run["error"]
    failed = [step["name"] for step in run["steps"] if step.get("collector_error")]
    if failed:
        return "evidence collection failed for " + ", ".join(failed)
    return None


def green(record):
    """Green only when the runner said so and every outcome it recorded holds."""
    run = record.get("result")
    if run is None:
        return False
    sources_ok = all(
        source.get("error") is None
        and source.get("guest_commit") == record["sources"][name]["commit"]
        for name, source in run["sources"].items()
    ) and set(run["sources"]) == set(record["sources"])
    steps_ok = bool(run["steps"]) and all(
        step.get("verdict") == "passed" for step in run["steps"]
    )
    registry_ok = run.get("registry") is None or run["registry"].get("removed") is True
    return sources_ok and steps_ok and registry_ok
