"""The team deployment journey's images: everything the journey requires is
something scripts/e2e/team-deployment-images.sh builds."""

import importlib.util
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BUILDER = REPO / "scripts" / "e2e" / "team-deployment-images.sh"


def journey():
    sys.path.insert(0, str(REPO / "naapp" / "secrets" / "e2e"))
    spec = importlib.util.spec_from_file_location("team_deployment_journey", REPO / "scripts" / "e2e" / "team_deployment_journey.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_builder_builds_every_image_the_journey_requires():
    built = set(re.findall(r"^\s*build\s+([a-z-]+)\s", BUILDER.read_text(), re.M))
    assert journey().REQUIRED_IMAGES <= built, journey().REQUIRED_IMAGES - built


def test_the_control_cli_is_built_from_a_pinned_commit_and_recorded_with_it():
    text = BUILDER.read_text()
    pinned = re.search(r'^control="\$\{TEAM_DEPLOYMENT_CONTROL_CLI_COMMIT:-([0-9a-f]{40})\}"$', text, re.M)
    assert pinned, "the control CLI's source must be a full, fixed commit"
    assert "cli-control-source" in text


def test_the_loader_keeps_only_image_references(tmp_path):
    images = tmp_path / "images.txt"
    lines = [f"{name} localhost:5000/{name}@sha256:{'a' * 64}" for name in sorted(journey().REQUIRED_IMAGES)]
    images.write_text("\n".join(lines + ["cli-control-source " + "b" * 40]) + "\n")
    loaded = journey().load_images(images)
    assert set(loaded) == journey().REQUIRED_IMAGES


def test_a_manifest_without_the_control_cli_is_refused(tmp_path):
    import pytest

    images = tmp_path / "images.txt"
    names = sorted(journey().REQUIRED_IMAGES - {"cli-control"})
    images.write_text("".join(f"{name} localhost:5000/{name}@sha256:{'a' * 64}\n" for name in names))
    with pytest.raises(SystemExit, match="cli-control"):
        journey().load_images(images)
