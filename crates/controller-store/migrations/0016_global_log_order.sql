ALTER TABLE attempt_log_chunks
    ADD COLUMN cursor_id bigint GENERATED ALWAYS AS IDENTITY;

ALTER TABLE attempt_log_chunks
    ADD CONSTRAINT attempt_log_chunks_cursor_id_unique UNIQUE (cursor_id);

CREATE INDEX attempt_log_chunks_tenant_cursor_idx
    ON attempt_log_chunks (organization_id, cursor_id);
