-- AGENT-012: 0045 is reserved for CTRL-007. Durable reservations replace the
-- anonymous process-local stream ledger; member row locks serialize retries.
CREATE TABLE artifact_sets (
 organization_id uuid NOT NULL,
 attempt_id uuid NOT NULL,
 fence bigint NOT NULL CHECK (fence >= 0),
 restore_epoch bigint NOT NULL,
 set_id bytea NOT NULL CHECK (octet_length(set_id) = 32),
 state text NOT NULL CHECK (state IN ('staging','available','aborted')),
 bytes bigint NOT NULL CHECK (bytes BETWEEN 0 AND 268435456),
 objects bigint NOT NULL CHECK (objects BETWEEN 0 AND 1024),
 PRIMARY KEY (organization_id,attempt_id,fence),
 UNIQUE (organization_id,attempt_id,fence,set_id),
 FOREIGN KEY (attempt_id,organization_id) REFERENCES attempts(id,organization_id)
);
CREATE TABLE artifact_set_members (
 organization_id uuid NOT NULL,
 attempt_id uuid NOT NULL,
 fence bigint NOT NULL,
 set_id bytea NOT NULL,
 name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 512),
 bytes bigint NOT NULL CHECK (bytes >= 0),
 media_type text NOT NULL CHECK (media_type = 'application/octet-stream'),
 object_digest bytea CHECK (octet_length(object_digest) = 32),
 pending_token text CHECK (octet_length(pending_token) BETWEEN 1 AND 255),
 PRIMARY KEY (organization_id,attempt_id,fence,name),
 FOREIGN KEY (organization_id,attempt_id,fence,set_id)
 REFERENCES artifact_sets(organization_id,attempt_id,fence,set_id),
 CHECK ((object_digest IS NULL) = (pending_token IS NULL))
);
ALTER TABLE attempt_objects ADD COLUMN artifact_set_id bytea;
ALTER TABLE attempt_objects ADD CONSTRAINT attempt_objects_artifact_set_fk
 FOREIGN KEY (organization_id,attempt_id,fence,artifact_set_id)
 REFERENCES artifact_sets(organization_id,attempt_id,fence,set_id);
ALTER TABLE artifact_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_sets FORCE ROW LEVEL SECURITY;
CREATE POLICY artifact_sets_tenant_policy ON artifact_sets
 USING (organization_id = NULLIF(current_setting('mcloving.organization_id',true),'')::uuid)
 WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id',true),'')::uuid);
ALTER TABLE artifact_set_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_set_members FORCE ROW LEVEL SECURITY;
CREATE POLICY artifact_set_members_tenant_policy ON artifact_set_members
 USING (organization_id = NULLIF(current_setting('mcloving.organization_id',true),'')::uuid)
 WITH CHECK (organization_id = NULLIF(current_setting('mcloving.organization_id',true),'')::uuid);
GRANT SELECT,INSERT,UPDATE ON artifact_sets,artifact_set_members TO mcloving_tenant;
