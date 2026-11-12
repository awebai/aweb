"""Operator data is external; subprocess environments are explicitly constructed."""

import json
import math
import os
from pathlib import Path
import re
from .errors import Refused
from .state import money


def child_environment():
    return {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}


def load(path, repo):
    path = Path(path).expanduser().resolve()
    repo = Path(repo).resolve()
    if path.is_relative_to(repo):
        raise Refused("config must be outside the repository")
    try:
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        raise Refused("external config is unreadable or invalid JSON") from None
    native = config.get("host_profile") == "native-arm64-oci-v1"
    if config.get("host_profile") not in {None, "snapshot", "native-arm64-oci-v1"}:
        raise Refused("unknown host profile")
    profile_path = "native_profile" if native else "snapshot_manifest"
    for name in ["state_root", "ledger", profile_path, "token_file"]:
        value = config.get(name)
        if not isinstance(value, str) or not Path(value).is_absolute():
            raise Refused(f"external config requires absolute {name}")
        if Path(value).resolve().is_relative_to(repo):
            raise Refused(f"{name} must remain outside the repository")
    for name in ["owner", "location"]:
        if not isinstance(config.get(name), str) or not re.fullmatch(
            "[a-zA-Z0-9_.-]{1,63}", config[name]
        ):
            raise Refused(f"external config has invalid {name}")
    if not native and (
        type(config.get("snapshot_id")) is not int or config["snapshot_id"] <= 0
    ):
        raise Refused("external config requires a snapshot ID")
    money(config.get("cap_eur", "150"))
    money(config.get("seed_eur", "0"))
    for key in [
        "setup_seconds",
        "pull_seconds",
        "cleanup_seconds",
        "margin_seconds",
        "lint_timeout_seconds",
    ]:
        if key in config and (
            type(config[key]) not in {int, float}
            or not math.isfinite(config[key])
            or config[key] <= 0
        ):
            raise Refused(f"{key} must be positive and finite")
    if "run_ceiling_eur" in config:
        money(config["run_ceiling_eur"])
    if native:
        from .native_host import validate_profile

        if (
            config.get("snapshot_id")
            or config.get("snapshot_manifest")
            or config["location"] != "fsn1"
        ):
            raise Refused(
                "native ARM profile is distinct from snapshots and requires fsn1"
            )
        for key, maximum in [
            ("setup", 900),
            ("pull", 600),
            ("cleanup", 300),
            ("margin", 300),
        ]:
            if config.get(key + "_seconds", maximum) > maximum:
                raise Refused(
                    "native ARM completion budget exceeds reviewed bound: " + key
                )
        try:
            profile = json.loads(Path(config["native_profile"]).read_text())
        except (OSError, ValueError):
            raise Refused("native profile is unavailable") from None
        validate_profile(profile)
        config.update(
            native_profile_path=config["native_profile"],
            native_profile=profile,
            manifest={},
            image_id=161547270,
        )
        config["config_path"] = str(path)
        return config
    try:
        manifest = json.loads(Path(config["snapshot_manifest"]).read_text())
    except (OSError, ValueError):
        raise Refused("snapshot manifest is unavailable") from None
    if (
        not isinstance(manifest.get("observed"), dict)
        or not isinstance(manifest.get("commands"), dict)
        or not isinstance(manifest.get("dpkg"), str)
    ):
        raise Refused(
            "snapshot manifest lacks versions, binary hashes or package manifest"
        )
    commands = manifest["commands"]
    for tool in [
        "go",
        "uv",
        "uvx",
        "node",
        "npm",
        "python3",
        "git",
        "make",
        "bash",
        "docker",
    ]:
        row = commands.get(tool)
        if (
            not isinstance(row, dict)
            or not all(
                isinstance(row.get(k), str) for k in ["path", "target", "sha256"]
            )
            or not re.fullmatch("[0-9a-f]{64}", row["sha256"])
        ):
            raise Refused("snapshot binary manifest is incomplete: " + tool)
    if not manifest["dpkg"].strip():
        raise Refused("snapshot package manifest is empty")
    config["manifest"] = manifest
    config["config_path"] = str(path)
    return config
