-- Notifications are deliberately hints, not scheduling authority. Consumers
-- always re-run the fenced claim query after a notification and on a bounded
-- fallback deadline, so coalesced or lost PostgreSQL notifications are safe.
CREATE FUNCTION mcloving_notify_work_ready() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('mcloving_work_ready_v1', NEW.organization_id::text);
    RETURN NEW;
END;
$$;

-- PostgreSQL grants EXECUTE to PUBLIC for newly created functions by default.
-- The runtime role reaches this function only through the table triggers, so
-- keep the existing closed function boundary intact.
REVOKE ALL ON FUNCTION mcloving_notify_work_ready() FROM PUBLIC;

CREATE TRIGGER nodes_notify_work_ready_after_insert
AFTER INSERT ON nodes
FOR EACH ROW
WHEN (NEW.status = 'queued')
EXECUTE FUNCTION mcloving_notify_work_ready();

CREATE TRIGGER nodes_notify_work_ready_after_transition
AFTER UPDATE OF status ON nodes
FOR EACH ROW
WHEN (
    NEW.status = 'queued'
    AND OLD.status IS DISTINCT FROM NEW.status
)
EXECUTE FUNCTION mcloving_notify_work_ready();

-- DAG successors are already stored as queued while their dependencies are
-- incomplete. A terminal attempt can therefore make work claimable without a
-- queued-state transition on the successor node.
CREATE TRIGGER attempts_notify_dag_progress
AFTER UPDATE OF status ON attempts
FOR EACH ROW
WHEN (
    NEW.status IN ('succeeded', 'failed', 'aborted')
    AND OLD.status IS DISTINCT FROM NEW.status
)
EXECUTE FUNCTION mcloving_notify_work_ready();
