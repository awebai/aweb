"""The public steps component preserves list semantics and the copy-button seam."""

from xml.etree import ElementTree as ET

import aweb_naapp as naapp


def test_steps_keep_order_and_accessible_list_structure() -> None:
    root = ET.fromstring(
        naapp.render_numbered_steps(
            [
                naapp.NumberedStep("First", "Read the guide."),
                naapp.NumberedStep("Second", "Choose a task."),
            ]
        )
    )
    assert root.tag == "ol"
    assert root.get("role") == "list"
    items = root.findall("li")
    assert len(items) == 2
    assert [item.find(".//h3").text for item in items] == ["First", "Second"]
    for number, item in enumerate(items, 1):
        marker = item.find("div")
        assert marker.text == str(number)
        assert marker.get("aria-hidden") == "true"


def test_text_is_escaped_but_authored_description_html_is_preserved() -> None:
    title = '<script>alert("title")</script> & next'
    command = 'printf "%s" "<tag> & value"\nnext-command'
    description = 'Read <a href="/guide"><code>the guide</code></a>.'
    html = naapp.render_numbered_steps([naapp.NumberedStep(title, description, command)])
    root = ET.fromstring(html)
    assert root.find(".//h3").text == title
    assert root.find(".//pre").text == command
    assert root.find(".//script") is None
    assert root.find('.//a[@href="/guide"]/code').text == "the guide"
    command_box = root.find('.//div[@class="cmd"]')
    assert command_box.find("pre") is not None
    button = command_box.find("button")
    assert button.get("type") == "button"
    assert button.get("aria-label") == "Copy command"
    assert naapp.COPY_BTN in html


def test_steps_without_commands_do_not_offer_copy_buttons() -> None:
    root = ET.fromstring(naapp.render_numbered_steps([naapp.NumberedStep("Choose", "A task.")]))
    assert root.find(".//pre") is None
    assert root.find(".//button") is None
    assert ET.fromstring(naapp.render_numbered_steps([])).findall("li") == []
