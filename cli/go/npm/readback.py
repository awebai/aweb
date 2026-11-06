#!/usr/bin/env python3
"""Bounded, exact-byte npm readback shared by the OSS and aw publishers."""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import time
import urllib.parse

# Observed propagation on 2026-11-04 took about 19 minutes. Allow six more
# minutes, bounded across the entire package set rather than per package.
DEFAULT_DEADLINE_SECONDS = 25 * 60


class ReadbackRefusal(RuntimeError):
    pass


class Pending(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifact:
    package: str
    path: Path


def verify(artifacts, version, *, dist_tag=None, git_head=None, registry="https://registry.npmjs.org",
           deadline_seconds=DEFAULT_DEADLINE_SECONDS, backoff_seconds=5,
           clock=time.monotonic, sleep=time.sleep):
    if deadline_seconds <= 0 or backoff_seconds < 0:
        raise ValueError("readback deadline must be positive and backoff non-negative")
    if not artifacts or len({a.package for a in artifacts}) != len(artifacts):
        raise ValueError("readback requires a nonempty, unique package set")
    expected = {a.package: a.path.read_bytes() for a in artifacts}
    deadline = clock() + deadline_seconds
    pending = dict(expected)
    observations = {}
    attempts = 0

    def fetch(url):
        remaining = deadline - clock()
        if remaining <= 0:
            raise Pending("deadline reached")
        try:
            # curl's total transfer deadline plus subprocess timeout bounds
            # slow headers and slow bodies, not merely idle socket intervals.
            result = subprocess.run(
                ["curl", "-sS", "-L", "--connect-timeout", str(min(30, remaining)),
                 "--max-time", str(remaining), "-H", "Cache-Control: no-cache",
                 "-w", "\\n%{http_code}", url], capture_output=True, timeout=remaining,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Pending("registry request unavailable") from exc
        body, separator, status = result.stdout.rpartition(b"\n")
        if result.returncode or not separator:
            raise Pending("registry request unavailable")
        if status != b"200":
            code = status.decode("ascii", errors="replace")
            raise Pending(f"HTTP {code} ({'not yet visible' if code == '404' else 'registry unavailable'})")
        return body

    def document(url):
        try:
            value = json.loads(fetch(url))
            if not isinstance(value, dict):
                raise ValueError("not an object")
            return value
        except (ValueError, UnicodeDecodeError) as exc:
            raise Pending("registry metadata unavailable") from exc

    while pending and clock() < deadline:
        attempts += 1
        for package, staged in list(pending.items()):
            url = registry.rstrip("/") + "/" + urllib.parse.quote(package, safe="")
            try:
                metadata = document(url + "/" + urllib.parse.quote(version, safe=""))
                if metadata.get("name") != package or metadata.get("version") != version:
                    raise ReadbackRefusal(f"permanent package identity mismatch: {package}@{version}")
                # The registry records gitHead with the version; it never changes afterwards.
                if git_head and metadata.get("gitHead") != git_head:
                    raise ReadbackRefusal(f"permanent source gitHead mismatch: {package}@{version} has "
                                          f"{metadata.get('gitHead') or 'none'}, expected {git_head}")
                dist = metadata.get("dist") or {}
                if not isinstance(dist, dict):
                    raise Pending("registry distribution metadata unavailable")
                tarball, integrity = dist.get("tarball"), dist.get("integrity")
                if not isinstance(tarball, str) or not isinstance(integrity, str):
                    raise Pending("tarball or integrity not yet visible")
                expected_integrity = "sha512-" + base64.b64encode(hashlib.sha512(staged).digest()).decode()
                if integrity != expected_integrity:
                    raise ReadbackRefusal(f"permanent integrity mismatch: {package}@{version}")
                observed = fetch(tarball)
                if observed != staged:
                    raise ReadbackRefusal(f"permanent tarball mismatch: {package}@{version}")
                if dist_tag:
                    tags = document(url).get("dist-tags")
                    if not isinstance(tags, dict) or tags.get(dist_tag) != version:
                        raise Pending(f"dist-tag {dist_tag} has not converged to {version}")
                if clock() >= deadline:
                    raise Pending("deadline reached")
                del pending[package]
                print(f"VERIFIED: {package}@{version} {integrity}" +
                      (f" {dist_tag}={version}" if dist_tag else ""), flush=True)
            except Pending as exc:
                observations[package] = str(exc)
        if pending:
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(backoff_seconds, remaining))
    if pending:
        detail = "; ".join(f"{p}: {observations.get(p, 'not observed')}" for p in pending)
        raise ReadbackRefusal(f"registry readback uncertain at deadline after {attempts} attempt(s): {detail}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", action="append", required=True, metavar="PACKAGE=TGZ")
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist-tag")
    parser.add_argument("--git-head", help="source commit every package version must record")
    parser.add_argument("--registry", default="https://registry.npmjs.org")
    parser.add_argument("--deadline-seconds", type=int, default=DEFAULT_DEADLINE_SECONDS)
    parser.add_argument("--backoff-seconds", type=int, default=5)
    args = parser.parse_args()
    try:
        artifacts = []
        for item in args.artifact:
            package, separator, path = item.partition("=")
            if not separator or not package or not path:
                raise ValueError("artifact must be PACKAGE=TGZ")
            artifacts.append(Artifact(package, Path(path)))
        verify(artifacts, args.version, dist_tag=args.dist_tag, git_head=args.git_head, registry=args.registry,
               deadline_seconds=args.deadline_seconds, backoff_seconds=args.backoff_seconds)
    except (OSError, ValueError, ReadbackRefusal) as exc:
        print(f"REFUSE: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
