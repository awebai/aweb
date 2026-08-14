"""A local registry stand-in speaking the real wire protocols.

Serves the four registry surfaces the normalizer's discovery reads -
PyPI package JSON, npm package documents, the OCI distribution v2 API
(tags list, manifests, config blobs with image labels), and GitHub
releases - from one in-memory world, so end-to-end tests can drive the
canonical entry points over HTTP instead of substituting fakes below
the protocol. The world shape:

    {
      "pypi":   {package: [version, ...]},
      "npm":    {package: [version, ...]},
      "ghcr":   {image: {tag: revision_sha_or_None}},
      "github": {repository: [version, ...]},   # served as tag v<version>
    }

A ghcr tag mapped to None serves a config blob without the revision
label - an identityless image, which is a legitimate observation, not
an error.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _config_digest(image: str, tag: str) -> str:
    return "sha256:cfg-" + urllib.parse.quote(f"{image}:{tag}", safe="")


class _Handler(BaseHTTPRequestHandler):
    world: dict

    def log_message(self, *args) -> None:  # quiet server
        pass

    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server contract
        path = urllib.parse.unquote(self.path.split("?", 1)[0])
        world = self.world

        if path.startswith("/pypi/") and path.endswith("/json"):
            middle = path[len("/pypi/") : -len("/json")].strip("/")
            parts = middle.split("/")
            if len(parts) == 2:
                package, version = parts
                files = world.get("pypi_files", {}).get(package, {}).get(version)
                if files is None:
                    return self._json({}, status=404)
                return self._json(
                    {
                        "urls": [
                            {"filename": name, "digests": {"sha256": sha}}
                            for name, sha in files.items()
                        ]
                    }
                )
            package = middle
            versions = world.get("pypi", {}).get(package)
            if versions is None:
                return self._json({}, status=404)
            return self._json({"releases": {v: [] for v in versions}})

        if path.startswith("/v2/"):
            expected_bearer = world.get("require_bearer")
            if expected_bearer and self.headers.get("Authorization") != (
                f"Bearer {expected_bearer}"
            ):
                return self._json({"errors": ["unauthorized"]}, status=401)
            rest = path[len("/v2/") :]
            if rest.endswith("/tags/list"):
                image = rest[: -len("/tags/list")]
                tags = world.get("ghcr", {}).get(image)
                if tags is None:
                    return self._json({}, status=404)
                return self._json({"name": image, "tags": sorted(tags)})
            if "/manifests/" in rest:
                image, tag = rest.split("/manifests/", 1)
                index = world.get("ghcr_index", {}).get(image, {}).get(tag)
                if index is not None:
                    body = json.dumps(
                        {
                            "manifests": [
                                {
                                    "platform": {
                                        "os": os_name,
                                        "architecture": arch,
                                    },
                                    "digest": f"sha256:{'c' * 63}{i}",
                                }
                                for i, (os_name, arch) in enumerate(
                                    index["platforms"]
                                )
                            ]
                        }
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Docker-Content-Digest", index["digest"])
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return None
                tags = world.get("ghcr", {}).get(image, {})
                if tag not in tags:
                    return self._json({}, status=404)
                return self._json({"config": {"digest": _config_digest(image, tag)}})
            if "/blobs/" in rest:
                image, digest = rest.split("/blobs/", 1)
                prefix = "sha256:cfg-"
                if not digest.startswith(prefix):
                    return self._json({}, status=404)
                image_tag = urllib.parse.unquote(digest[len(prefix) :])
                _, tag = image_tag.rsplit(":", 1)
                tags = world.get("ghcr", {}).get(image, {})
                if tag not in tags:
                    return self._json({}, status=404)
                revision = tags[tag]
                labels = (
                    {"org.opencontainers.image.revision": revision}
                    if revision is not None
                    else {}
                )
                return self._json({"config": {"Labels": labels}})
            return self._json({}, status=404)

        if path.startswith("/repos/") and "/releases/tags/" in path:
            repository, tag = path[len("/repos/") :].split("/releases/tags/", 1)
            assets = world.get("github_releases", {}).get(repository, {}).get(tag)
            if assets is None:
                return self._json({}, status=404)
            return self._json(
                {"tag_name": tag, "assets": [{"name": name} for name in assets]}
            )

        if path.startswith("/repos/") and path.endswith("/releases"):
            repository = path[len("/repos/") : -len("/releases")]
            versions = world.get("github", {}).get(repository)
            if versions is None:
                return self._json({}, status=404)
            return self._json([{"tag_name": f"v{v}"} for v in versions])

        if path.startswith("/tarballs/"):
            key = path[len("/tarballs/") :]
            body = world.get("npm_tarballs", {}).get(key)
            if body is None:
                return self._json({}, status=404)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None

        package = path.lstrip("/")
        # Listing first: a scoped package name itself contains a slash,
        # so the version-document branch only takes paths whose prefix
        # is not a known package listing.
        if package not in world.get("npm", {}) and "/" in package:
            name, version = package.rsplit("/", 1)
            tarball = world.get("npm_tarballs", {}).get(f"{name}/{version}.tgz")
            if tarball is None:
                return self._json({}, status=404)
            import base64 as _b64
            import hashlib as _hashlib

            integrity = "sha512-" + _b64.b64encode(
                _hashlib.sha512(tarball).digest()
            ).decode()
            declared = (
                world.get("npm_integrity_override", {}).get(f"{name}/{version}")
                or integrity
            )
            host = self.headers.get("Host", "")
            return self._json(
                {
                    "dist": {
                        "integrity": declared,
                        "tarball": f"http://{host}/tarballs/{name}/{version}.tgz",
                    }
                }
            )
        versions = world.get("npm", {}).get(package)
        if versions is None:
            return self._json({}, status=404)
        return self._json({"versions": {v: {} for v in versions}})


class RegistryStandIn:
    """Context manager owning the server thread and its base URL."""

    def __init__(self, world: dict):
        self.world = world
        handler = type("Handler", (_Handler,), {"world": world})
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "RegistryStandIn":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join()
