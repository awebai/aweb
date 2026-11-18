#!/usr/bin/env python3
"""Refuse an aw final whose pinned runtime packages cannot be installed."""

import argparse
from enum import Enum
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from release_manifest import fetch, unique_object

ROOT = Path(__file__).resolve().parent


class MarketplaceSourceKind(str, Enum):
    NPM = "npm"


class ChannelCheck(Enum):
    MAPPING = "mapping"
    PUBLISHED = "published"


def verify_marketplace_source(*, mapping, document):
    """Apply docs/install-integrity.md's runtime compatibility rule to source bytes."""
    if not isinstance(document, dict) or document.get("name") != "awebai-marketplace":
        raise ValueError(
            "Invalid Claude marketplace name. Publish the mapped marketplace before the aw final."
        )
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        raise ValueError(
            "Invalid Claude marketplace plugins. Publish the mapped marketplace before the aw final."
        )
    channels = [
        entry
        for entry in plugins
        if isinstance(entry, dict) and entry.get("name") == "aweb-channel"
    ]
    if len(channels) != 1 or not isinstance(channels[0].get("source"), dict):
        raise ValueError(
            "Claude marketplace must name one aweb-channel npm source. Publish the mapped source before the aw final."
        )
    source = channels[0]["source"]
    version = mapping["claude_channel"]
    package = source.get("package")
    exact_package = package == "@awebai/claude-channel@" + version
    exact_field = (
        package == "@awebai/claude-channel" and source.get("version") == version
    )
    if source.get("source") != MarketplaceSourceKind.NPM or not (
        exact_package or exact_field
    ):
        raise ValueError(
            f"Claude marketplace channel is unpinned or differs from {version}. Publish the exact mapped channel source before the aw final."
        )


def read_marketplace(*, revision, checkout=None):
    if checkout is not None:
        # A staged checkout keeps runnerless publication independent of host
        # availability. git show binds these bytes to the exact supplied commit.
        result = subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "show",
                revision + ":.claude-plugin/marketplace.json",
            ],
            capture_output=True,
            check=True,
        )
        raw = result.stdout
    else:
        raw = fetch(
            "https://raw.githubusercontent.com/awebai/claude-plugins/"
            + revision
            + "/.claude-plugin/marketplace.json"
        )
    return json.loads(raw, object_pairs_hook=unique_object)


def check(mapping, *, mode=ChannelCheck.MAPPING, marketplace_checkout=None):
    packages = {"pi": "@awebai/pi", "claude_channel": "@awebai/claude-channel"}
    for field, package in packages.items():
        version = mapping.get(field, "")
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc\.[1-9]\d*)?", version):
            raise ValueError(
                f"{package}: compatibility mapping requires an exact version"
            )
        if mode is ChannelCheck.PUBLISHED:
            result = subprocess.run(
                ["npm", "view", f"{package}@{version}", "version", "--json"],
                capture_output=True,
                text=True,
            )
            if result.returncode or json.loads(result.stdout) != version:
                raise ValueError(
                    f"{package}@{version} is not published. Publish the mapped package before the aw final."
                )
    revision = mapping.get("claude_marketplace_revision", "")
    if mode is ChannelCheck.PUBLISHED:
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError(
                "Claude marketplace revision is required. Ask the release coordinator to supply its immutable revision before the aw final."
            )
        document = read_marketplace(revision=revision, checkout=marketplace_checkout)
        verify_marketplace_source(mapping=mapping, document=document)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-published", action="store_true")
    parser.add_argument(
        "--marketplace-checkout",
        type=Path,
        default=os.environ.get("AW_RELEASE_MARKETPLACE_CHECKOUT"),
        help="Read pinned marketplace bytes from a staged git checkout instead of contacting its host",
    )
    args = parser.parse_args()
    try:
        mapping = json.loads(
            (ROOT / "internal/releaseverify/channels.json").read_text()
        )
        check(
            mapping,
            mode=ChannelCheck.PUBLISHED
            if args.require_published
            else ChannelCheck.MAPPING,
            marketplace_checkout=args.marketplace_checkout,
        )
        print(
            "PASS: aw channel compatibility mapping"
            + (" is published" if args.require_published else "")
        )
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
