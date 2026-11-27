"""Vocabulary measurement never narrows accepted input or records its contents."""

import logging

import pytest
from aweb.message_vocabulary import (
    MessageInputSource,
    UNNAMED_MESSAGE_VOCABULARY,
    observe_message_vocabulary,
)
from aweb.messaging.kinds import ContentMode, MessagePriority


def _count(source, field):
    return UNNAMED_MESSAGE_VOCABULARY.labels(
        source=source.value, field=field
    )._value.get()


@pytest.mark.parametrize("source", list(MessageInputSource))
def test_unnamed_metadata_counts_fields_once_and_logs_no_values(source, caplog):
    before = {field: _count(source, field) for field in ("content_mode", "priority")}
    with caplog.at_level(logging.INFO, logger="aweb.message_vocabulary"):
        observe_message_vocabulary(
            source=source,
            content_mode="private arbitrary mode",
            priority="private priority",
        )
    assert {
        field: _count(source, field) - count for field, count in before.items()
    } == {
        "content_mode": 1,
        "priority": 1,
    }
    assert len(caplog.records) == 1
    assert caplog.messages == [
        f"message_vocabulary_unnamed source={source.value} fields=content_mode,priority"
    ]
    assert "private" not in caplog.text


@pytest.mark.parametrize(
    "mode,priority",
    [
        (None, None),
        ("", None),
        (None, ""),
        ("", ""),
        (ContentMode.PLAINTEXT, MessagePriority.NORMAL),
        ("encrypted_v2", "urgent"),
    ],
)
def test_named_or_absent_metadata_is_not_measured(mode, priority, caplog):
    source = MessageInputSource.MAIL_SEND
    before = (_count(source, "content_mode"), _count(source, "priority"))
    with caplog.at_level(logging.INFO):
        observe_message_vocabulary(source=source, content_mode=mode, priority=priority)
    assert before == (_count(source, "content_mode"), _count(source, "priority"))
    assert not caplog.records


@pytest.mark.parametrize("mode", [" legacy_plaintext_v1", "LEGACY_PLAINTEXT_V1"])
def test_nonempty_equivalent_looking_strings_are_measured_without_normalization(
    mode, caplog
):
    source = MessageInputSource.MAIL_SEND
    before = _count(source, "content_mode")
    with caplog.at_level(logging.INFO):
        observe_message_vocabulary(source=source, content_mode=mode)
    assert _count(source, "content_mode") == before + 1
    assert len(caplog.records) == 1


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyError])
def test_counter_failure_does_not_refuse_accepted_input(
    monkeypatch, caplog, failure_type
):
    def unavailable(**labels):
        raise failure_type("private dependency contents")

    monkeypatch.setattr(UNNAMED_MESSAGE_VOCABULARY, "labels", unavailable)
    with caplog.at_level(logging.INFO):
        observe_message_vocabulary(
            source=MessageInputSource.MAIL_SEND, content_mode="opaque"
        )
    assert (
        caplog.messages[0]
        == f"message_vocabulary_counter_unavailable failure_type={failure_type.__name__}"
    )
    assert "private dependency contents" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)
    assert any("message_vocabulary_unnamed" in message for message in caplog.messages)
