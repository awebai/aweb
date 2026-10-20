"""The agent skills a naapp serves at ``/skills/``.

Each skill is ``<skills dir>/<name>/SKILL.md``. Only names matching the skill
pattern are served, and never through a symlink or from outside the skills
directory.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,80}$")


@dataclass(frozen=True)
class Skills:
    """An app's skills directory.

    ``env_var`` names a configured directory that wins when set; otherwise the
    source checkout's ``source_dir`` is used, then the container image's
    ``container_dir`` (the layout of an installed package).
    """

    app_name: str
    env_var: str
    source_dir: Path
    container_dir: Path = Path("/app/skills")

    def directory(self) -> Path:
        configured = os.environ.get(self.env_var)
        if configured:
            return Path(configured)
        if self.source_dir.is_dir():
            return self.source_dir
        if self.container_dir.is_dir():
            return self.container_dir
        return self.source_dir

    def _path_if_safe(self, skills_dir: Path, name: str) -> Path | None:
        if _SKILL_NAME.fullmatch(name) is None:
            return None
        root = skills_dir.resolve()
        candidate = skills_dir / name / "SKILL.md"
        path = candidate.resolve()
        if (
            candidate.is_symlink()
            or candidate.parent.is_symlink()
            or path.is_symlink()
            or not path.is_relative_to(root)
            or not path.is_file()
        ):
            return None
        return path

    def names(self) -> list[str]:
        skills_dir = self.directory()
        root = skills_dir.resolve()
        if not root.is_dir():
            return []
        names = []
        for entry in root.iterdir():
            if (
                entry.is_symlink()
                or not entry.is_dir()
                or _SKILL_NAME.fullmatch(entry.name) is None
            ):
                continue
            if self._path_if_safe(skills_dir, entry.name) is not None:
                names.append(entry.name)
        return sorted(names)

    def index(self) -> str:
        lines = [
            f"# {self.app_name} agent skills",
            "",
            f"{self.app_name} is a Native Agentic App (naapp) on the aweb.ai hub.",
            f"Agents should fetch the relevant skill before acting so requests match the {self.app_name} API contract.",
            "",
            "- aweb.ai hub: https://aweb.ai",
            "- AWID identity authority: https://awid.ai",
            "",
            "Available skills:",
            "",
        ]
        for name in self.names():
            lines.append(f"- GET /skills/{name}/SKILL.md")
        lines.append("")
        return "\n".join(lines)

    def read(self, name: str) -> str | None:
        if name not in self.names():
            return None
        path = self._path_if_safe(self.directory(), name)
        if path is None:
            return None
        return path.read_text(encoding="utf-8")
