"""Numbered instructions in the shared public-site design system."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from html import escape

from aweb_naapp.chrome import COPY_BTN


@dataclass(frozen=True)
class NumberedStep:
    """One instruction, optionally followed by a copyable command.

    ``description_html`` is trusted, developer-authored inline HTML, like the
    authored HTML slots in SiteConfig. Never pass user content here. Titles and
    commands are plain text and are escaped by the renderer.
    """

    title: str
    description_html: str
    command: str | None = None


def render_numbered_steps(steps: Sequence[NumberedStep]) -> str:
    """Render an ordered list under a section's h2 using the shared CSS bundle.

    The visible numbers are decorative; the ol/li structure carries the order
    for assistive technology. Commands retain the .cmd > pre/copy-button seam
    used by the public chrome's clipboard script.
    """
    items = []
    for number, step in enumerate(steps, 1):
        command = (
            f'<div class="cmd"><pre>{escape(step.command)}</pre>{COPY_BTN}</div>'
            if step.command is not None
            else ""
        )
        items.append(
            f'<li class="gs-step">\n'
            f'  <div class="gs-step__n" aria-hidden="true">{number}</div>\n'
            f'  <div class="gs-step__body">\n'
            f'    <h3 class="gs-step__title">{escape(step.title)}</h3>\n'
            f'    <p class="gs-step__what">{step.description_html}</p>\n'
            f"    {command}\n"
            f"  </div>\n"
            f"</li>"
        )
    return '<ol class="gs-steps" role="list">\n' + "\n".join(items) + "\n</ol>"
