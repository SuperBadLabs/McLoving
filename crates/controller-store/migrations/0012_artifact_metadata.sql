ALTER TABLE attempt_objects
    ADD COLUMN media_type text NOT NULL DEFAULT 'application/octet-stream'
    CHECK (
        length(media_type) BETWEEN 1 AND 255
        AND media_type = btrim(media_type)
    );

CREATE INDEX attempt_objects_artifact_name_idx
    ON attempt_objects (organization_id, attempt_id, name)
    WHERE kind = 'artifact';
