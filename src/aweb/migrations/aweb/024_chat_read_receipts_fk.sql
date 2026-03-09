ALTER TABLE {{tables.chat_read_receipts}}
    ADD CONSTRAINT fk_chat_read_receipts_last_read_message
    FOREIGN KEY (last_read_message_id)
    REFERENCES {{tables.chat_messages}}(message_id)
    ON DELETE SET NULL;
