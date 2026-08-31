-- A reconciliation-only controller can be waiting before another worker
-- establishes a lease.  Wake it when an attempt first becomes active so it
-- can recompute the authoritative nearest-expiry deadline.  Renewals only
-- move that deadline later; an early timer wake is safe and avoids emitting a
-- notification for every heartbeat.
CREATE FUNCTION mcloving_notify_active_lease() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('mcloving_work_ready_v1', NEW.organization_id::text);
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION mcloving_notify_active_lease() FROM PUBLIC;

CREATE TRIGGER attempts_notify_active_lease
AFTER UPDATE OF status, lease_expires_at ON attempts
FOR EACH ROW
WHEN (
    NEW.status IN ('offered', 'accepted', 'running', 'finalizing', 'cancelling')
    AND NEW.lease_expires_at IS NOT NULL
    AND (
        OLD.status NOT IN ('offered', 'accepted', 'running', 'finalizing', 'cancelling')
        OR OLD.lease_expires_at IS NULL
    )
)
EXECUTE FUNCTION mcloving_notify_active_lease();
