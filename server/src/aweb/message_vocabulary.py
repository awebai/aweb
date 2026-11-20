"""Measure unnamed accepted metadata without changing delivery admission.

The embedding host exposes its Prometheus registry. Only bounded source and
field labels are recorded; signed strings and message content never enter logs.
"""

import logging
from enum import StrEnum

from prometheus_client import Counter

from aweb.messaging.kinds import (
    ContentMode,
    ContentModeValue,
    MessagePriority,
    MessagePriorityValue,
    accepted_content_mode,
    accepted_message_priority,
)

logger = logging.getLogger(__name__)


class MessageInputSource(StrEnum):
    MAIL_SEND = "mail_send"
    CHAT_SEND = "chat_send"
    FEDERATION_INGRESS = "federation_ingress"
    NATIVE_PREPARATION = "native_preparation"


class _VocabularyField(StrEnum):
    CONTENT_MODE = "content_mode"
    PRIORITY = "priority"


UNNAMED_MESSAGE_VOCABULARY = Counter(
    "aweb_unnamed_message_vocabulary_total",
    "Accepted message metadata outside the named vocabulary, by entry and field.",
    ("source", "field"),
)


def observe_message_vocabulary(
    *,
    source: MessageInputSource,
    content_mode: ContentModeValue | None,
    priority: MessagePriorityValue | None = None,
) -> None:
    """Count unnamed fields once per invocation; never reject accepted values.

    docs/aw-hooks-sot.md:92 keeps received metadata open. Observation belongs
    at a logical send or verified ingress entry, before replay exits, rather
    than in callback constructors that may never be reached on exact retries.
    """
    unnamed: list[_VocabularyField] = []
    if accepted_content_mode(content_mode) not in frozenset(ContentMode):
        unnamed.append(_VocabularyField.CONTENT_MODE)
    if accepted_message_priority(priority) not in frozenset(MessagePriority):
        unnamed.append(_VocabularyField.PRIORITY)
    if not unnamed:
        return
    try:
        for field in unnamed:
            UNNAMED_MESSAGE_VOCABULARY.labels(
                source=source.value, field=field.value
            ).inc()
    except Exception as exc:
        # Measurement cannot refuse accepted input or expose a dependency's
        # exception contents in the request's logging context.
        logger.error(
            "message_vocabulary_counter_unavailable failure_type=%s", type(exc).__name__
        )
    logger.info(
        "message_vocabulary_unnamed source=%s fields=%s",
        source.value,
        ",".join(field.value for field in unnamed),
    )
