#!/usr/bin/env python3
"""Bound a lab child and independently reconcile its declared Docker resources.

The plan is written before mutations by the reviewed child. The caller supplies
the admitted fixture/run/source/IP separately. Raw observations stay private.
Provider teardown is outside this program and has its own result.
"""
import datetime
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
from lab_process import Containment
from lab_ingress import Ingress
import time


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def created_epoch(value):
    stamp = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("resource creation timestamp has no timezone")
    return stamp.timestamp()


def validate_plan(plan, admission):
    for key in ("fixture_id", "provider_run_id", "cloud_source_sha"):
        if plan[key] != admission[key]:
            raise ValueError("resource plan differs from admission: " + key)
    label_key = plan["owner_label"]["key"]
    if plan["schema_version"] != 1 or label_key not in {"aweb.ac.candidate-gate", "aweb.adaz.default"}:
        raise ValueError("unsupported resource plan")
    names = [plan["owner_label"]["value"], plan["runner_name"], plan["network_name"],
             *plan["compose_projects"], *plan["volume_names"]]
    if not all(isinstance(n, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,180}", n) for n in names):
        raise ValueError("invalid resource name")
    listener = plan["published_listener"]
    default = label_key == "aweb.adaz.default"
    if (listener["host_ip"] != admission["public_ipv4"]
            or (not default and listener["project"] not in plan["compose_projects"])
            or listener["service"] != "awid" or listener["published_port"] != (443 if default else 8010)
            or listener["target_port"] != 8010 or listener["protocol"] != "tcp"):
        raise ValueError("public listener differs from admission")
    if (not isinstance(plan["created_unix_seconds"], (int, float))
            or not math.isfinite(plan["created_unix_seconds"])):
        raise ValueError("missing plan creation time")
    return plan


class Resources:
    def __init__(self, root, plan, deadline, *, baseline=None):
        self.root, self.plan, self.deadline = root, plan, deadline
        self.baseline = baseline
        self.observed = {}
        self.errors = []
        self.uncertain = []
        self.listener_seen = False
        self.publications = {}
        self.started_containers = set()
        self.linked_volumes = set()

    def builder_name(self):
        shared = self.plan.get("shared_resources", {})
        builder = shared.get("builder_name")
        return "buildx_buildkit_" + builder + "0" if builder else None

    def call(self, args, mutate=False):
        left = self.deadline - time.monotonic()
        record = {"argv": args, "started_unix_seconds": time.time()}
        try:
            if left <= 0:
                raise TimeoutError("aggregate deadline exhausted")
            process = subprocess.run(["docker", *args], capture_output=True, text=True,
                                     timeout=min(10, left))
            record.update(rc=process.returncode, stdout=process.stdout, stderr=process.stderr)
        except (OSError, subprocess.TimeoutExpired, TimeoutError) as error:
            record.update(rc=None, stdout="", stderr=type(error).__name__)
            if mutate:
                self.uncertain.append(args)
        with (self.root / "docker-calls.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")
        if record["rc"] != 0:
            self.errors.append({"argv": args, "rc": record["rc"]})
        return record

    def inventory(self, kind, selector):
        commands = {"container": ["ps", "-aq", "--no-trunc"],
                    "network": ["network", "ls", "-q", "--no-trunc"],
                    "volume": ["volume", "ls", "-q"]}
        result = self.call([*commands[kind], "--filter", "label=" + selector])
        if result["rc"] != 0:
            raise RuntimeError("Docker inventory is UNKNOWN")
        return self.identifiers(kind, result["stdout"])

    @staticmethod
    def identifiers(kind, stdout):
        values = stdout.split()
        pattern = r"[A-Za-z0-9][A-Za-z0-9_.-]*" if kind == "volume" else r"[0-9a-f]{64}"
        if any(not re.fullmatch(pattern, value) for value in values):
            raise RuntimeError("unexpected Docker resource inventory")
        return values

    def inspect(self, kind, reference, *, exact_from_inventory=False):
        result = self.call([kind, "inspect", reference])
        if result["rc"] != 0:
            # A short-lived labelled seed can disappear between list/inspect.
            # Do not parse diagnostics or equate names with IDs. A separate
            # complete successful inventory may establish this exact ID gone.
            # Keep both calls and the failed inspect in the raw receipt.
            if exact_from_inventory and (kind == "volume" or re.fullmatch("[0-9a-f]{64}", reference)):
                failed = self.errors[-1]
                if reference not in self.all_objects(kind):
                    failed["resolved_absent_after_inspect"] = True
                    return None
            raise RuntimeError("Docker inspect is UNKNOWN")
        values = json.loads(result["stdout"])
        if not isinstance(values, list) or len(values) != 1:
            raise RuntimeError("unexpected Docker inspect response")
        return values[0]

    def ownership(self, kind, value):
        labels = (value.get("Config", {}).get("Labels") if kind == "container" else value.get("Labels")) or {}
        owner = self.plan["owner_label"]
        belongs = (labels.get(owner["key"]) == owner["value"]
                   or labels.get("com.docker.compose.project") in self.plan["compose_projects"])
        # The complete pre-child inventory proved this exclusive host had no
        # containers/volumes. The reviewed Cloud plan separately names its new
        # Buildx/cache; these resources are not adopted from another run.
        if self.baseline is not None:
            if kind == "container" and value["Name"].lstrip("/") == self.builder_name():
                mounts = value.get("Mounts", [])
                belongs = any(m.get("Type") == "volume" and m.get("Name") == self.builder_name() + "_state"
                              for m in mounts)
            elif kind == "volume":
                cache = self.plan.get("shared_resources", {}).get("package_cache_volume")
                belongs = belongs or value["Name"] in self.linked_volumes or (
                    value["Name"] == cache and labels.get("aweb.ac.candidate-cache") == "packages")
        stamp = value.get("CreatedAt" if kind == "volume" else "Created")
        exact = value["Name"] if kind == "volume" else value["Id"]
        created = created_epoch(stamp)
        boundary = self.plan["created_unix_seconds"]
        # Docker volume creation timestamps can have only second precision.
        # Relax that precision only with the independent pre-child inventory;
        # an object present there is never adopted even if labels match.
        if kind == "volume" and self.baseline is not None:
            boundary = math.floor(boundary)
        if (not belongs or created < boundary or created > time.time() + 1
                or (self.baseline is not None and exact in self.baseline[kind])):
            raise RuntimeError("resource is not owned by this attempt")
        return labels, stamp

    def discover(self):
        owner = self.plan["owner_label"]
        selectors = [owner["key"] + "=" + owner["value"],
                     *("com.docker.compose.project=" + p for p in self.plan["compose_projects"])]
        for kind in ("container", "network", "volume"):
            refs = set()
            for selector in selectors:
                refs.update(self.inventory(kind, selector))
            if kind == "container" and self.builder_name():
                result = self.call(["ps", "-aq", "--no-trunc", "--filter", "name=^/" + self.builder_name() + "$"])
                if result["rc"] != 0:
                    raise RuntimeError("builder inventory is UNKNOWN")
                refs.update(self.identifiers(kind, result["stdout"]))
            if kind == "volume":
                # Names come from independently inspected owned mounts. A
                # complete successful inventory distinguishes absence from an
                # inspect failure without guessing Docker diagnostics.
                existing = self.all_objects("volume")
                cache = self.plan.get("shared_resources", {}).get("package_cache_volume")
                refs.update((self.linked_volumes | ({cache} if cache else set())) & existing)
            if len(refs) > 128:
                raise RuntimeError("unexpectedly large lab resource set")
            for ref in sorted(refs):
                if (kind, ref) in self.observed and (kind != "container" or ref in self.started_containers):
                    continue
                value = self.inspect(kind, ref, exact_from_inventory=True)
                if value is None:
                    continue
                labels, stamp = self.ownership(kind, value)
                exact = value["Name"] if kind == "volume" else value["Id"]
                identity = {"kind": kind, "id": exact, "name": value.get("Name"),
                            "created": stamp, "labels": labels}
                self.observed[(kind, exact)] = identity
                if kind == "container":
                    self.linked_volumes.update(m["Name"] for m in value.get("Mounts", []) if m.get("Type") == "volume")
                    identity["mounts"] = value.get("Mounts", [])
                    identity["image_id"] = value["Image"]
                    identity["network_ids"] = {name: item["NetworkID"] for name, item in
                        (value.get("NetworkSettings", {}).get("Networks") or {}).items()}
                    identity["limits"] = {key: value["HostConfig"].get(key) for key in
                        ("NanoCpus", "CpuQuota", "Memory", "PidsLimit", "NetworkMode")}
                    if value["State"]["Running"]:
                        self.started_containers.add(ref)
                    ports = value.get("NetworkSettings", {}).get("Ports") or {}
                    if any(ports.values()):
                        self.publications[exact] = {**identity, "ports": ports}
                    expected = self.plan["published_listener"]
                    selected = (labels.get("com.docker.compose.project") == expected["project"]
                                and labels.get("com.docker.compose.service") == expected["service"])
                    if self.plan["owner_label"]["key"] == "aweb.adaz.default":
                        selected = value["Name"].lstrip("/") == expected["container_name"]
                    if selected:
                        wanted = [{"HostIp": expected["host_ip"], "HostPort": str(expected["published_port"])}]
                        if ports.get("8010/tcp") == wanted:
                            self.listener_seen = True
                        else:
                            raise RuntimeError("public AWID binding differs from the admitted listener")

    def reconcile(self):
        # Keep the observations that failed separate; later success does not
        # erase a timeout or turn an unanswered daemon mutation into CLEAN.
        try:
            self.discover()
        except Exception as error:
            self.errors.append({"phase": "pre-cleanup", "error": type(error).__name__})
        for kind in ("container", "network", "volume"):
            ordered = sorted(self.observed.items(), key=lambda item:
                             item[1].get("name", "").lstrip("/") != self.builder_name())
            for (item_kind, ref), identity in ordered:
                if item_kind != kind:
                    continue
                try:
                    # A successful complete inventory can establish that an
                    # already-removed object is gone; no guessed error text.
                    current = self.all_objects(kind)
                    if ref not in current:
                        continue
                    value = self.inspect(kind, ref, exact_from_inventory=True)
                    if value is None:
                        continue
                    _, stamp = self.ownership(kind, value)
                    if stamp != identity["created"]:
                        raise RuntimeError("resource identity changed before cleanup")
                    args = [kind, "rm", *( ["-f", "-v"] if kind == "container" else []), ref]
                    self.call(args, mutate=True)
                except Exception as error:
                    self.errors.append({"kind": kind, "id": ref, "error": type(error).__name__})
        terminal = {}
        try:
            for kind in ("container", "network", "volume"):
                current = self.all_objects(kind)
                expected = {ref for k, ref in self.observed if k == kind}
                terminal[kind] = {"remaining_exact": sorted(expected & current)}
                owner = self.plan["owner_label"]
                selectors = [owner["key"] + "=" + owner["value"],
                             *("com.docker.compose.project=" + p for p in self.plan["compose_projects"])]
                terminal[kind]["remaining_scoped"] = sorted(set().union(
                    *(set(self.inventory(kind, s)) for s in selectors)))
            clean = not any(v["remaining_exact"] or v["remaining_scoped"] for v in terminal.values())
        except Exception as error:
            self.errors.append({"phase": "terminal", "error": type(error).__name__})
            clean = False
        listener = self.plan["published_listener"]
        connection = {"host": listener["host_ip"], "port": listener["published_port"], "closed": False}
        try:
            left = self.deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("listener observation deadline exhausted")
            with socket.create_connection((connection["host"], connection["port"]), timeout=min(2, left)):
                connection["result"] = "OPEN"
        except OSError as error:
            connection["errno"] = error.errno
            connection["closed"] = error.errno == errno.ECONNREFUSED
        except TimeoutError:
            connection["result"] = "UNKNOWN"
        clean = clean and connection["closed"]
        unresolved_errors = [e for e in self.errors if not e.get("resolved_absent_after_inspect")]
        return {"verdict": "CLEAN" if clean and not unresolved_errors and not self.uncertain else "UNKNOWN",
                "terminal": terminal, "errors": self.errors, "uncertain_mutations": self.uncertain,
                "terminal_listener": connection,
                "observed": list(self.observed.values()), "publications": list(self.publications.values()),
                "public_listener_seen": self.listener_seen}

    def all_objects(self, kind):
        commands = {"container": ["ps", "-aq", "--no-trunc"],
                    "network": ["network", "ls", "-q", "--no-trunc"],
                    "volume": ["volume", "ls", "-q"]}
        result = self.call(commands[kind])
        if result["rc"] != 0:
            raise RuntimeError("terminal full inventory is UNKNOWN")
        return set(self.identifiers(kind, result["stdout"]))


def fresh_host_baseline(root, deadline):
    """Read before the child can mutate; only Docker's built-in networks exist."""
    observer = Resources(root, {}, deadline)
    baseline = {kind: observer.all_objects(kind) for kind in ("container", "network", "volume")}
    if baseline["container"] or baseline["volume"]:
        raise RuntimeError("exclusive fresh host has existing containers or volumes")
    for ref in baseline["network"]:
        value = observer.inspect("network", ref, exact_from_inventory=True)
        if value["Name"] not in {"bridge", "host", "none"}:
            raise RuntimeError("exclusive fresh host has a non-default network")
    with (root / "pre-child-inventory.json").open("x") as stream:
        json.dump({k: sorted(v) for k, v in baseline.items()}, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return baseline


def supervise(command, admission, plan_paths, out, body_seconds, cleanup_seconds, admission_digest):
    start = time.monotonic()
    deadline = start + body_seconds + cleanup_seconds
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    with (out / "start.json").open("x") as stream:
        json.dump({"kind": "start, never a result", "admission": admission,
                   "containment": "/sys/fs/cgroup/" + admission["fixture_id"],
                   "plans": [str(p) for p in plan_paths], "body_seconds": body_seconds,
                   "cleanup_seconds": cleanup_seconds}, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(descriptor)
    os.close(descriptor)
    result = {"primary": "NOT RUN", "cleanup": {}, "process": {"populated": True}}
    process = containment = None
    baseline = None
    resources = {}
    quota_observations = {}
    next_observation = {}
    def interrupted(signum, _frame):
        raise InterruptedError(f"signal {signum}")
    old = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        containment = Containment(admission["fixture_id"])
        containment.limits(4, 2 * 1024**3, 512)
        baseline = fresh_host_baseline(out, min(start + body_seconds, time.monotonic() + 60))
        result["ingress"] = Ingress(out, admission["fixture_id"], start + body_seconds).install()
        with (out / "child.log").open("xb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                       preexec_fn=containment.enter, pass_fds=(containment.fd,))
            while process.poll() is None:
                if time.monotonic() >= start + body_seconds:
                    raise TimeoutError("whole body deadline reached")
                for plan_path in plan_paths:
                    key = str(plan_path)
                    if key not in resources and plan_path.exists():
                        plan = validate_plan(load_json(plan_path), admission)
                        directory = out / ("resources-" + str(len(resources)))
                        directory.mkdir(mode=0o700)
                        resources[key] = (Resources(directory, plan, start + body_seconds, baseline=baseline),
                                          hashlib.sha256(plan_path.read_bytes()).hexdigest())
                    if key in resources:
                        observer, digest = resources[key]
                        if hashlib.sha256(plan_path.read_bytes()).hexdigest() != digest:
                            raise RuntimeError("immutable resource plan changed")
                        ready = plan_path.parent / "results/quota-observation-ready.json"
                        if ready.exists() and key not in quota_observations:
                            from lab_quota_observer import capture
                            quota_observations[key] = capture(observer, ready, admission, admission_digest)
                        if time.monotonic() >= next_observation.get(key, 0):
                            observer.discover()
                            if key not in quota_observations:
                                from lab_quota_observer import periodic
                                periodic(observer)
                            next_observation[key] = time.monotonic() + 3
                time.sleep(min(0.25, max(0.01, start + body_seconds - time.monotonic())))
            result["child_exit"] = process.returncode
            result["primary"] = "PASS" if process.returncode == 0 else "FAIL"
            result["quota_observations"] = quota_observations
    except BaseException as error:
        result.update(primary="INTERRUPTED" if isinstance(error, (TimeoutError, InterruptedError)) else "FAIL",
                      error=type(error).__name__)
    finally:
        deadline = min(deadline, time.monotonic() + cleanup_seconds)
        for sig in old:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if containment is not None:
                result["process"] = containment.stop(process, min(deadline, time.monotonic() + 45))
        except BaseException as error:
            result["process_error"] = type(error).__name__
        producers_closed = not result["process"]["populated"] and result["process"].get("all_children_reaped")
        try:
            # Resolve plans after producer closure. Each plan has independent
            # error handling so one unreadable plan cannot skip the other.
            for plan_path in plan_paths:
                key = str(plan_path)
                try:
                    if key not in resources and plan_path.exists():
                        directory = out / ("resources-" + str(len(resources)))
                        directory.mkdir(mode=0o700)
                        resources[key] = (Resources(directory, validate_plan(load_json(plan_path), admission), deadline,
                                                    baseline=baseline),
                                          hashlib.sha256(plan_path.read_bytes()).hexdigest())
                    if key in resources:
                        observer, digest = resources[key]
                        observer.deadline = deadline
                        if hashlib.sha256(plan_path.read_bytes()).hexdigest() != digest:
                            raise RuntimeError("immutable resource plan changed during finalization")
                        if producers_closed:
                            result["cleanup"][key] = {"plan_sha256": digest, **observer.reconcile()}
                        else:
                            # Read-only discovery may help recovery; live or
                            # unaccounted producers prohibit deletion/CLEAN.
                            observer.discover()
                            result["cleanup"][key] = {"verdict": "UNKNOWN", "error": "producer closure unknown",
                                                       "observed": list(observer.observed.values())}
                        if result["primary"] != "PASS":
                            result["cleanup"][key]["possible_unanswered_child_mutation"] = True
                            result["cleanup"][key]["verdict"] = "UNKNOWN"
                    else:
                        result["cleanup"][key] = {"verdict": "UNKNOWN", "error": "required resource plan absent"}
                except BaseException as error:
                    result["cleanup"][key] = {"verdict": "UNKNOWN", "error": type(error).__name__}
        finally:
            for observed in quota_observations.values():
                try:
                    shared, private = Path(observed["shared_ack"]), Path(observed["private_ack"])
                    if (shared.is_symlink() or shared.read_bytes() != private.read_bytes()
                            or hashlib.sha256(Path(observed["private_artifact"]).read_bytes()).hexdigest() != observed["sha256"]):
                        raise ValueError("shared acknowledgment differs from root-private observation")
                    observed["binding_verified_after_body"] = True
                except BaseException as error:
                    observed["binding_verified_after_body"] = False
                    observed["binding_error"] = type(error).__name__
            result["quota_observations"] = quota_observations
            result["final"] = "PASS" if (result["primary"] == "PASS" and not result["process"]["populated"]
                and result["process"].get("verdict") == "CLEAN"
                and not result.get("cleanup_error") and len(result["cleanup"]) == len(plan_paths)
                and any(q.get("enforcement", {}).get("verdict") == "PASS" and q.get("binding_verified_after_body")
                        for q in quota_observations.values())
                and all(r.get("verdict") == "CLEAN" and r.get("public_listener_seen")
                        for r in result["cleanup"].values())) else "FAIL"
            with (out / "supervisor.json").open("x") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            for sig, handler in old.items():
                signal.signal(sig, handler)
    return result
