"""Document widgets remain data and cannot be altered through prose saves."""

import json

import pytest

from folio.document_widgets import (
    WidgetDocumentError,
    document_segments,
    merge_document_prose,
    parse_widget_blocks,
    require_same_widgets,
    table_widgets,
)


def widget(identifier="research", **changes):
    definition = {
        "id": identifier,
        "type": "table",
        "props": {"columns": [{"field": "finding", "label": "Finding", "format": "text"}]},
        "bind": {"collection": "discoveries", "limit": 20},
    }
    return definition | changes


def block(definition=None, newline="\n"):
    return newline.join((":::widget", json.dumps(definition or widget()), ":::")) + newline


def test_mixed_document_keeps_widget_spans_and_normal_table_definition():
    raw = block()
    body = "# Research\n\n" + raw + "\nDiscuss this next.\n"
    parsed = parse_widget_blocks(body)
    assert len(parsed) == 1
    # The closing line ending belongs to the following prose segment; adding
    # prose after a widget at EOF must not change the widget's own bytes.
    assert parsed[0].raw == raw.removesuffix("\n")
    assert body[parsed[0].start : parsed[0].end] == raw.removesuffix("\n")
    assert table_widgets(body) == {"research": widget()}
    assert [part["kind"] for part in document_segments(body)] == ["prose", "widget", "prose"]
    assert all(
        ":::widget" not in part["text"]
        for part in document_segments(body)
        if part["kind"] == "prose"
    )


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_prose_edits_and_deletion_preserve_raw_blocks_exactly(newline):
    raw = block(newline=newline)
    body = "A café" + newline + raw + "After" + newline + block(widget("other"), newline)
    merged = merge_document_prose(body, ["Changed\n", "", "The end"])
    assert merged == "Changed\n" + raw + block(widget("other"), newline) + "The end"
    assert [p.raw for p in parse_widget_blocks(merged)] == [
        p.raw for p in parse_widget_blocks(body)
    ]
    require_same_widgets(body, merged)


def test_no_widget_document_is_one_unmodified_prose_segment():
    body = "# Ordinary\r\n\r\nText without a table."
    assert table_widgets(body) == {}
    assert document_segments(body) == [{"kind": "prose", "text": body}]
    assert merge_document_prose(body, ["Edited text"]) == "Edited text"


def test_typing_prose_at_widget_boundaries_never_requires_editing_delimiters():
    raw = block().removesuffix("\n")
    body = merge_document_prose(raw, ["Before", "After"])
    assert body == "Before\n" + raw + "\nAfter"
    require_same_widgets(raw, body)


def test_initial_serialization_preserves_entire_original_document():
    original = "Before\r\n" + block(newline="\r\n") + "After\r\n"
    prose = [p["text"] for p in document_segments(original) if p["kind"] == "prose"]
    assert merge_document_prose(original, prose) == original


@pytest.mark.parametrize("fence", ["```", "````", "~~~"])
def test_documentation_examples_inside_code_fences_are_not_live_widgets(fence):
    example = fence + "json\n" + block() + fence + "\n"
    body = example + block(widget("actual"))
    assert list(table_widgets(body)) == ["actual"]
    assert document_segments(body)[0] == {"kind": "prose", "text": example}


@pytest.mark.parametrize(
    "change",
    [
        lambda raw: "",
        lambda raw: raw.replace('"research"', '"renamed"'),
        lambda raw: raw.replace('"discoveries"', '"private"'),
        lambda raw: raw.replace('"limit": 20', '"limit": 10'),
        lambda raw: raw + block(widget("new")),
        lambda raw: "```\n" + raw,
        lambda raw: "~~~\n" + raw,
    ],
)
def test_prose_save_refuses_removed_changed_added_or_hidden_widgets(change):
    raw = block()
    with pytest.raises(WidgetDocumentError):
        require_same_widgets(raw, change(raw))


def test_prose_cannot_hide_widget_by_opening_a_code_fence():
    with pytest.raises(WidgetDocumentError):
        merge_document_prose("Before\n" + block() + "After", ["```\n", "After"])


def test_prose_cannot_add_a_new_widget_or_wrong_number_of_segments():
    for prose in ([block()], ["before", "extra"], []):
        with pytest.raises(WidgetDocumentError):
            merge_document_prose("Ordinary text", prose)


@pytest.mark.parametrize(
    "body",
    [
        block() + block(),
        block(widget("bad id")),
        block(widget(type="text")),
        block(widget(bind={"collection": "discoveries", "limit": 201})),
        block(
            widget(props={"columns": [{"field": "finding", "label": "Finding", "format": "html"}]})
        ),
        block(widget(endpoint="https://attacker.invalid")),
        ':::widget\n{"id":"a","id":"b","type":"table"}\n:::\n',
        ':::widget\n{"id":"a","type":"table","props":{"columns":NaN}}\n:::\n',
        ":::widget\nnot json\n:::\n",
        ":::widget\n{}",
    ],
)
def test_invalid_or_ambiguous_blocks_fail_closed(body):
    with pytest.raises(WidgetDocumentError):
        table_widgets(body)


def test_widget_order_is_part_of_prose_save_invariant():
    first, second = block(), block(widget("second"))
    with pytest.raises(WidgetDocumentError):
        require_same_widgets(first + second, second + first)
