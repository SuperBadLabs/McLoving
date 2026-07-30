CREATE FUNCTION mcloving_owned_object_publication_allowed(
    candidate_organization uuid,
    candidate_attempt uuid,
    candidate_fence bigint,
    candidate_kind text,
    candidate_name text,
    candidate_digest bytea
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT
      current_setting('mcloving.organization_id', true)
        = candidate_organization::text
      AND EXISTS (
        SELECT 1
        FROM attempt_objects AS owned
        WHERE owned.organization_id = candidate_organization
          AND owned.attempt_id = candidate_attempt
          AND owned.fence = candidate_fence
          AND owned.kind = candidate_kind
          AND owned.name = candidate_name
          AND owned.object_digest = candidate_digest
          AND NOT EXISTS (
              SELECT 1
              FROM object_deletion_claims AS deletion
              WHERE deletion.object_digest = candidate_digest
          )
      )
$$;

REVOKE ALL ON FUNCTION mcloving_owned_object_publication_allowed(
    uuid, uuid, bigint, text, text, bytea
) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mcloving_owned_object_publication_allowed(
    uuid, uuid, bigint, text, text, bytea
)
TO mcloving_tenant;
