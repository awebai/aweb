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


def test_readonly_widgets_bootstrap_uses_fixed_nonce_module_without_inline_token():
    from folio.presentation import render_presented_page

    html = render_presented_page(body=table(), nonce="host-nonce", widget_token="checked-token")
    view = View(html)
    assert view.mounts == ["research"]
    assert 'src="/present/widgets/assets/folio-widget-host.mjs"' in html
    assert 'nonce="host-nonce"' in html
    assert 'data-widget-token="checked-token"' in html
    assert "renderer.css" in html


def test_widget_module_csp_uses_nonce_and_fixed_origin_fetches():
    from folio.presentation import content_security_policy

    csp = content_security_policy(mode="document", nonce="host-nonce", stream_host="", widgets=True)
    assert "script-src 'nonce-host-nonce' 'strict-dynamic'" in csp
    assert "connect-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "'unsafe-eval'" not in csp and "script-src 'self'" not in csp


def test_initial_editor_never_displays_raw_widget_source_while_session_is_loading():
    from folio.presentation import render_editor_page

    html = render_editor_page(
        body=table(), token="checked-token", version_number=1, nonce="host-nonce"
    )
    import re

    textarea = re.search(r'<textarea id="body"[^>]*>', html).group(0)
    assert "hidden" in textarea
    assert "atomic-editor.mjs" in html
