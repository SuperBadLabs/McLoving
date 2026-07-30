CREATE FUNCTION mcloving_object_deletion_claim_exists(candidate_digest bytea)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM object_deletion_claims
        WHERE object_digest = candidate_digest
    )
$$;

REVOKE ALL ON FUNCTION mcloving_object_deletion_claim_exists(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mcloving_object_deletion_claim_exists(bytea)
TO mcloving_tenant;
