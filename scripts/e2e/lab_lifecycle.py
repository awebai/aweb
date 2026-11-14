#!/usr/bin/env python3
"""Bound a lab child and independently reconcile its declared Docker resources.

The plan is written before mutations by the reviewed child. The caller supplies
the admitted fixture/run/source/IP separately. Raw observations stay private.
Provider teardown is outside this program and has its own result.
"""
import argparse
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
from lab_process import Containment
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
    if not isinstance(plan["created_unix_seconds"], (int, float)):
        raise ValueError("missing plan creation time")
    return plan


class Resources:
    def __init__(self, root, plan, deadline):
        self.root, self.plan, self.deadline = root, plan, deadline
        self.observed = {}
        self.errors = []
        self.uncertain = []
        self.listener_seen = False
        self.publications = {}

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
        return result["stdout"].split()

    def inspect(self, kind, reference):
        result = self.call([kind, "inspect", reference])
        if result["rc"] != 0:
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
        stamp = value.get("CreatedAt" if kind == "volume" else "Created")
        if not belongs or created_epoch(stamp) < self.plan["created_unix_seconds"]:
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
            if len(refs) > 128:
                raise RuntimeError("unexpectedly large lab resource set")
            for ref in sorted(refs):
                if (kind, ref) in self.observed and (kind != "container" or self.listener_seen):
                    continue
                value = self.inspect(kind, ref)
                labels, stamp = self.ownership(kind, value)
                exact = value["Name"] if kind == "volume" else value["Id"]
                identity = {"kind": kind, "id": exact, "name": value.get("Name"),
                            "created": stamp, "labels": labels}
                self.observed[(kind, exact)] = identity
                if kind == "container":
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
            for (item_kind, ref), identity in list(self.observed.items()):
                if item_kind != kind:
                    continue
                try:
                    # A successful complete inventory can establish that an
                    # already-removed object is gone; no guessed error text.
                    current = self.all_objects(kind)
                    if ref not in current:
                        continue
                    value = self.inspect(kind, ref)
                    _, stamp = self.ownership(kind, value)
                    if stamp != identity["created"]:
                        raise RuntimeError("resource identity changed before cleanup")
                    args = [kind, "rm", *( ["-f"] if kind == "container" else []), ref]
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
        return {"verdict": "CLEAN" if clean and not self.errors and not self.uncertain else "UNKNOWN",
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
        return set(result["stdout"].split())




def supervise(command, admission, plan_paths, out, body_seconds, cleanup_seconds):
    start = time.monotonic()
    deadline = start + body_seconds + cleanup_seconds
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    result = {"primary": "NOT RUN", "cleanup": {}, "process": {"populated": True}}
    process = containment = None
    resources = {}
    def interrupted(signum, _frame):
        raise InterruptedError(f"signal {signum}")
    old = {s: signal.signal(s, interrupted) for s in (signal.SIGTERM, signal.SIGINT)}
    try:
        containment = Containment(admission["fixture_id"])
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
                        resources[key] = (Resources(directory, plan, start + body_seconds),
                                          hashlib.sha256(plan_path.read_bytes()).hexdigest())
                    if key in resources:
                        observer, digest = resources[key]
                        if hashlib.sha256(plan_path.read_bytes()).hexdigest() != digest:
                            raise RuntimeError("immutable resource plan changed")
                        observer.discover()
                time.sleep(min(5, max(0.01, start + body_seconds - time.monotonic())))
            result["child_exit"] = process.returncode
            result["primary"] = "PASS" if process.returncode == 0 else "FAIL"
    except BaseException as error:
        result.update(primary="INTERRUPTED" if isinstance(error, (TimeoutError, InterruptedError)) else "FAIL",
                      error=type(error).__name__)
    finally:
        for sig in old:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if process is not None:
                result["process"] = containment.stop(process, min(deadline, time.monotonic() + 15))
            # Only after all contained producers are stopped, read every plan
            # again and reconcile daemon resources. New sessions cannot escape
            # the kernel cgroup. Timed-out Docker operations remain uncertain.
            for plan_path in plan_paths:
                key = str(plan_path)
                if key not in resources and plan_path.exists():
                    directory = out / ("resources-" + str(len(resources)))
                    directory.mkdir(mode=0o700)
                    resources[key] = (Resources(directory, validate_plan(load_json(plan_path), admission), deadline),
                                      hashlib.sha256(plan_path.read_bytes()).hexdigest())
                if key in resources:
                    observer, digest = resources[key]
                    observer.deadline = deadline
                    result["cleanup"][key] = {"plan_sha256": digest, **observer.reconcile()}
                    if result["primary"] != "PASS":
                        # A killed/failed child can have an unanswered daemon
                        # mutation. Terminal absence is retained, but no CLEAN
                        # completion is inferred from one later empty read.
                        result["cleanup"][key]["possible_unanswered_child_mutation"] = True
                        result["cleanup"][key]["verdict"] = "UNKNOWN"
                else:
                    result["cleanup"][key] = {"verdict": "UNKNOWN", "error": "required resource plan absent"}
        except BaseException as error:
            result["cleanup_error"] = type(error).__name__
        finally:
            result["final"] = "PASS" if (result["primary"] == "PASS" and not result["process"]["populated"]
                and result["process"].get("all_children_reaped")
                and not result.get("cleanup_error") and len(result["cleanup"]) == len(plan_paths)
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


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--plan", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--body-seconds", type=int, required=True)
    parser.add_argument("--cleanup-seconds", type=int, default=300)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or args.body_seconds <= 0 or args.cleanup_seconds < 30:
        parser.error("positive body, cleanup >=30 seconds and a child command are required")
    result = supervise(args.command, load_json(args.admission), args.plan, args.out,
                       args.body_seconds, args.cleanup_seconds)
    return 0 if result["final"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
