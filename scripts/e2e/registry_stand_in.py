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
            package = path[len("/pypi/") : -len("/json")]
            versions = world.get("pypi", {}).get(package)
            if versions is None:
                return self._json({}, status=404)
            return self._json({"releases": {v: [] for v in versions}})

        if path.startswith("/v2/"):
            rest = path[len("/v2/") :]
            if rest.endswith("/tags/list"):
                image = rest[: -len("/tags/list")]
                tags = world.get("ghcr", {}).get(image)
                if tags is None:
                    return self._json({}, status=404)
                return self._json({"name": image, "tags": sorted(tags)})
            if "/manifests/" in rest:
                image, tag = rest.split("/manifests/", 1)
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

        if path.startswith("/repos/") and path.endswith("/releases"):
            repository = path[len("/repos/") : -len("/releases")]
            versions = world.get("github", {}).get(repository)
            if versions is None:
                return self._json({}, status=404)
            return self._json([{"tag_name": f"v{v}"} for v in versions])

        package = path.lstrip("/")
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
