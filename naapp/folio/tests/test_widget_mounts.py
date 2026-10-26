"""Real Markdown rendering exposes trusted mount points, never widget JSON."""

import json
from html.parser import HTMLParser

from folio.presentation import render_presented_markdown


class View(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.mounts = []
        self.text = []
        self.tags = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        attrs = dict(attrs)
        if "data-folio-widget" in attrs:
            self.mounts.append(attrs["data-folio-widget"])

    def handle_data(self, value):
        self.text.append(value)


def table(identifier="research", label="Finding"):
    return (
        ":::widget\n"
        + json.dumps(
            {
                "id": identifier,
                "type": "table",
                "props": {"columns": [{"field": "finding", "label": label, "format": "text"}]},
                "bind": {"collection": "discoveries"},
            }
        )
        + "\n:::\n"
    )


def test_mixed_prose_has_atomic_mounts_and_no_raw_definition():
    view = View(render_presented_markdown("# Before\n\n" + table() + "\n**After**"))
    assert view.mounts == ["research"]
    assert "Before" in view.text and "After" in view.text
    assert "strong" in view.tags
    visible = "".join(view.text)
    assert ":::widget" not in visible and '"collection"' not in visible


def test_untrusted_html_cannot_forge_widget_mounts():
    view = View(
        render_presented_markdown(
            '<div data-folio-widget="private" onclick="steal()">Fake table</div>\n\n' + table()
        )
    )
    assert view.mounts == ["research"]
    assert "script" not in view.tags


def test_widget_inside_a_code_example_stays_inert_and_visible():
    view = View(render_presented_markdown("```\n" + table() + "```\n"))
    assert view.mounts == []
    assert ":::widget" in "".join(view.text)
    assert "code" in view.tags


def test_hostile_label_is_never_executed_or_rendered_as_agent_markup():
    source = table(label='</script><img src=x onerror="steal()">')
    view = View(render_presented_markdown(source))
    assert view.mounts == ["research"]
    assert "script" not in view.tags and "img" not in view.tags


def test_invalid_block_refuses_inertly_without_disclosing_raw_json():
    view = View(render_presented_markdown(':::widget\n{"id":"secret-source"}\n:::\n'))
    assert view.mounts == []
    assert "secret-source" not in "".join(view.text)
    assert '"id"' not in "".join(view.text)
