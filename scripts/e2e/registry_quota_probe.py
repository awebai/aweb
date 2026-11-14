#!/usr/bin/env python3
"""Tokenless real-registry quota exercise, AFTER the complete customer journey.

Public namespace and DID arguments come from already-created fixture bindings.
No key, identity file, Redis mutation, forwarded-source header or retry hook.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import ssl
import time
from urllib.parse import quote, urlsplit


ORIGINS = {"https://api.awid.ai", "https://registry.aweb-docker.test:8010"}
BODY_SECONDS = 180


def exercise(origin, namespace, did_aw, public_ip, out):
    if origin not in ORIGINS:
        raise ValueError("probe origin is not one of the frozen public fixture origins")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", namespace) or not did_aw.startswith("did:aw:"):
        raise ValueError("probe needs existing public namespace/DID bindings")
    if not ipaddress.IPv4Address(public_ip).is_global:
        raise ValueError("probe peer must be the assigned public IPv4")
    target = urlsplit(origin)
    context = ssl.create_default_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    started = time.monotonic()
    result = {"schema_version": 1, "kind": "adaz-registry-quota", "origin": origin,
              "namespace": namespace, "did_aw": did_aw, "public_ipv4": public_ip,
              "requests": [], "verdict": "FAIL", "sent_authority_headers": False,
              "redis_mutations": False, "after_original_journey": True}
    out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    old = {}
    def interrupted(signum, _frame):
        raise InterruptedError(f"probe signal {signum}")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
        old[sig] = signal.signal(sig, interrupted)
    prior_timer = signal.setitimer(signal.ITIMER_REAL, BODY_SECONDS)
    def request(path):
        remaining = BODY_SECONDS - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("fixed probe deadline")
        connection = http.client.HTTPSConnection(target.hostname, target.port or 443,
                                                context=context, timeout=min(5, remaining))
        try:
            connection.connect()
            peer = connection.sock.getpeername()
            local = connection.sock.getsockname()
            if peer[0] != public_ip:
                raise ValueError("actual normal-TLS peer differs from assigned public IPv4")
            certificate = connection.sock.getpeercert(binary_form=True)
            row = {"time": time.time(), "method": "GET", "path": path,
                   "local_socket": list(local), "peer_socket": list(peer),
                   "peer_certificate_sha256": hashlib.sha256(certificate).hexdigest()}
            result["requests"].append(row)
            # No Authorization, service token, X-Forwarded-For or source spoof.
            connection.request("GET", path, headers={"Accept": "application/json"})
            response = connection.getresponse()
            row.update(status=response.status, headers={k: response.getheader(k) for k in
                ("Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")
                if response.getheader(k) is not None})
            response.read(1024 * 1024)
            return row
        finally:
            connection.close()
    try:
        path = "/v1/namespaces/" + quote(namespace, safe="")
        first = request(path)
        assert first["status"] in (200, 429)
        assert int(first["headers"]["X-RateLimit-Limit"]) == 60
        denied = first if first["status"] == 429 else None
        if denied is None and int(first["headers"]["X-RateLimit-Reset"]) - time.time() < 10:
            # Only readiness for this separate post-journey measurement. Never
            # retry or change an original customer failure, clear a Redis key,
            # or discard the already-retained first request/bucket usage.
            delay = max(0, int(first["headers"]["X-RateLimit-Reset"]) - time.time()) + 0.1
            result["natural_window_readiness_seconds"] = delay
            time.sleep(delay)
            first = request(path)
            assert first["status"] == 200
        if denied is None:
            for _ in range(61):
                row = request(path)
                assert row["headers"]["X-RateLimit-Reset"] == first["headers"]["X-RateLimit-Reset"], "measurement crossed a window; no retry"
                assert row["status"] in (200, 429)
                if row["status"] == 429:
                    denied = row
                    break
        assert denied is not None and int(denied["headers"]["Retry-After"]) > 0
        assert int(denied["headers"]["X-RateLimit-Remaining"]) == 0
        neighbor = request("/v1/did/" + quote(did_aw, safe=":") + "/head")
        assert neighbor["status"] == 200
        result["verdict"] = "PASS"
    except BaseException as error:
        result["error"] = type(error).__name__
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        for sig in old:
            signal.signal(sig, signal.SIG_IGN)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        for sig, handler in old.items():
            signal.signal(sig, handler)
        if prior_timer != (0.0, 0.0):
            signal.setitimer(signal.ITIMER_REAL, *prior_timer)
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--did-aw", required=True)
    parser.add_argument("--public-ip", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    return 0 if exercise(args.origin, args.namespace, args.did_aw, args.public_ip, args.out)["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
