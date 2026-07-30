ALTER TABLE attempt_objects
    ADD COLUMN media_type text NOT NULL DEFAULT 'application/octet-stream'
    CHECK (
        length(media_type) BETWEEN 1 AND 255
        AND media_type = btrim(media_type)
    );

ALTER TABLE attempt_objects DROP CONSTRAINT attempt_objects_status_check;
ALTER TABLE attempt_objects ADD CONSTRAINT attempt_objects_status_check CHECK (
    status IN ('pending', 'available', 'missing', 'corrupt')
);

CREATE INDEX attempt_objects_artifact_name_idx
    ON attempt_objects (organization_id, attempt_id, name)
    WHERE kind = 'artifact';
