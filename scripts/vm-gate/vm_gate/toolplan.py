"""Resolve public checksums locally; download/install bytes only on the VM.

Authorities: go.dev/dl JSON; Node's SHASUMS256.txt; the uv release asset digest
published by GitHub's release-assets API. No GitHub authentication is used.
"""

import json
import re
import urllib.request
from urllib.parse import quote
from .errors import Refused


def one(items, tool):
    if len(items) != 1:
        raise Refused(f"missing or ambiguous {tool} download for source pin")
    item = items[0]
    if not re.fullmatch("[0-9a-f]{64}", str(item.get("sha256"))):
        raise Refused(f"missing or invalid {tool} archive sha256")
    return item


def go_archive(metadata, version):
    name = f"go{version}.linux-amd64.tar.gz"
    items = [
        {
            "tool": "go",
            "version": version,
            "filename": name,
            "url": "https://go.dev/dl/" + name,
            "sha256": f.get("sha256"),
            "top": "go",
        }
        for release in metadata
        if release["version"] == "go" + version
        for f in release["files"]
        if f["filename"] == name
        and f.get("kind") == "archive"
        and f.get("os") == "linux"
        and f.get("arch") == "amd64"
    ]
    return one(items, "Go")


def node_archive(checks, major):
    items = []
    for line in checks.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        match = re.fullmatch(
            r"node-v(" + re.escape(major) + r"\.\d+\.\d+)-linux-x64\.tar\.gz", parts[1]
        )
        if match:
            version = match[1]
            name = parts[1]
            items.append(
                {
                    "tool": "node",
                    "version": version,
                    "filename": name,
                    "sha256": parts[0],
                    "url": f"https://nodejs.org/dist/v{version}/{name}",
                    "top": name.removesuffix(".tar.gz"),
                }
            )
    return one(items, "Node")


def uv_archive(metadata, version):
    name = "uv-x86_64-unknown-linux-gnu.tar.gz"
    prefix = f"https://github.com/astral-sh/uv/releases/download/{version}/"
    items = []
    for asset in metadata.get("assets", []):
        if metadata.get("tag_name") == version and asset.get("name") == name:
            digest = asset.get("digest") or ""
            if asset.get("browser_download_url") != prefix + name:
                raise Refused("uv release download URL differs from the pinned release")
            items.append(
                {
                    "tool": "uv",
                    "version": version,
                    "filename": name,
                    "url": prefix + name,
                    "sha256": digest.removeprefix("sha256:"),
                    "top": name.removesuffix(".tar.gz"),
                }
            )
    return one(items, "uv")


def read(url):
    try:
        request = urllib.request.Request(
            url, headers={"User-Agent": "aweb-vm-gate", "Accept": "application/json"}
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(16 * 1024 * 1024 + 1)
        if len(data) > 16 * 1024 * 1024:
            raise Refused("tool release metadata exceeds bound")
        return data
    except (OSError, ValueError):
        raise Refused(
            "public tool release metadata unavailable before allocation"
        ) from None


def resolve(required):
    return {
        "go": go_archive(
            json.loads(read("https://go.dev/dl/?mode=json&include=all")), required["go"]
        ),
        "uv": uv_archive(
            json.loads(
                read(
                    "https://api.github.com/repos/astral-sh/uv/releases/tags/"
                    + quote(required["uv"], safe="")
                )
            ),
            required["uv"],
        ),
        "node": node_archive(
            read(
                "https://nodejs.org/dist/latest-v"
                + required["node"]
                + ".x/SHASUMS256.txt"
            ).decode(),
            required["node"],
        ),
    }
