"""Publish-test dependencies served by the real npm client and owned registry."""

import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def prepare_release_compatibility(*, root, registry, marketplace):
    """Stage an actual pinned git object and exact-version registry packuments."""
    cli = root / "cli/go"
    cli.mkdir(parents=True, exist_ok=True)
    for filename in ("check_release_channels.py", "release_manifest.py"):
        shutil.copyfile(ROOT / "cli/go" / filename, cli / filename)
    mapping = json.loads(
        (ROOT / "cli/go/internal/releaseverify/channels.json").read_text()
    )
    marketplace.mkdir(parents=True)
    document = {
        "name": "awebai-marketplace",
        "plugins": [
            {
                "name": "aweb-channel",
                "source": {
                    "source": "npm",
                    "package": "@awebai/claude-channel",
                    "version": mapping["claude_channel"],
                },
            }
        ],
    }
    document_path = marketplace / ".claude-plugin/marketplace.json"
    document_path.parent.mkdir()
    document_path.write_text(json.dumps(document))
    subprocess.run(["git", "init", "-q", "-b", "main", str(marketplace)], check=True)
    subprocess.run(["git", "-C", str(marketplace), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(marketplace),
            "-c",
            "user.name=Release Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Pinned fixture",
        ],
        check=True,
    )
    revision = subprocess.check_output(
        ["git", "-C", str(marketplace), "rev-parse", "HEAD"], text=True
    ).strip()
    mapping["claude_marketplace_revision"] = revision
    mapping_path = cli / "internal/releaseverify/channels.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(json.dumps(mapping))
    for field, name in (
        ("pi", "@awebai/pi"),
        ("claude_channel", "@awebai/claude-channel"),
    ):
        version = mapping[field]
        manifest = json.dumps({"name": name, "version": version}).encode()
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as writer:
            entry = tarfile.TarInfo("package/package.json")
            entry.size = len(manifest)
            writer.addfile(entry, io.BytesIO(manifest))
        registry.packages[name] = archive.getvalue()
        registry.versions[name] = version
        registry.tags[name] = {"latest": version}
    return {
        "AW_RELEASE_MARKETPLACE_CHECKOUT": str(marketplace),
        "NPM_CONFIG_REGISTRY": registry.url,
        "npm_config_registry": registry.url,
    }
