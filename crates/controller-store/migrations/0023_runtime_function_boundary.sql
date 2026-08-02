-- Runtime sessions must not inherit PostgreSQL's default PUBLIC EXECUTE grant.
-- The six functions that form the runtime API already have explicit grants to
-- mcloving_tenant in their owning migrations; every other function is reached
-- only through a trigger or the separately privileged migration connection.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;

-- Keep future migrations fail-closed as they add functions. A new callable
-- runtime function must carry an explicit, reviewable mcloving_tenant grant.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
