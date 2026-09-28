-- PAR-002: mutable, generation-bound schedule slots. Trigger version rows stay
-- immutable; the native calendar materializes upcoming fire times here, extends
-- the horizon without a generation bump, and the watermark check reads membership
-- from this table. Controllers claim due slots with SKIP LOCKED so two processes
-- on one database fire each slot once. After downtime, older missed open slots
-- are marked skipped and only the latest missed slot is fired.
CREATE TABLE trigger_schedule_slots (
    organization_id uuid NOT NULL,
    project_id uuid NOT NULL,
    pipeline_id uuid NOT NULL,
    trigger_id uuid NOT NULL,
    trigger_generation bigint NOT NULL CHECK (trigger_generation > 0),
    resolved_slot_unix_ms bigint NOT NULL CHECK (resolved_slot_unix_ms >= 0),
    outcome text NOT NULL DEFAULT 'open' CHECK (
        outcome IN ('open', 'claimed', 'fired', 'skipped')
    ),
    delivery_id text CHECK (
        delivery_id IS NULL OR (
            delivery_id = btrim(delivery_id)
            AND length(delivery_id) BETWEEN 1 AND 512
        )
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (
        organization_id, trigger_id, trigger_generation, resolved_slot_unix_ms
    ),
    FOREIGN KEY (organization_id, project_id, pipeline_id, trigger_id)
        REFERENCES pipeline_trigger_definitions(
            organization_id, project_id, pipeline_id, trigger_id
        ),
    FOREIGN KEY (organization_id, trigger_id, trigger_generation)
        REFERENCES pipeline_trigger_versions(
            organization_id, trigger_id, generation
        ),
    CHECK (
        (outcome = 'fired' AND delivery_id IS NOT NULL)
        OR (outcome <> 'fired' AND (delivery_id IS NULL OR outcome = 'claimed'))
    )
);

CREATE INDEX trigger_schedule_slots_due_idx
    ON trigger_schedule_slots (
        organization_id, outcome, resolved_slot_unix_ms
    )
    WHERE outcome = 'open';

CREATE FUNCTION mcloving_guard_trigger_schedule_slot()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
       OR NEW.project_id IS DISTINCT FROM OLD.project_id
       OR NEW.pipeline_id IS DISTINCT FROM OLD.pipeline_id
       OR NEW.trigger_id IS DISTINCT FROM OLD.trigger_id
       OR NEW.trigger_generation IS DISTINCT FROM OLD.trigger_generation
       OR NEW.resolved_slot_unix_ms IS DISTINCT FROM OLD.resolved_slot_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'trigger schedule slot identity is immutable';
    END IF;
    IF OLD.outcome = 'fired' OR OLD.outcome = 'skipped' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'trigger schedule slot outcome is terminal';
    END IF;
    IF OLD.outcome = 'open' AND NEW.outcome NOT IN ('claimed', 'skipped', 'fired') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'open schedule slot may only claim, skip, or fire';
    END IF;
    IF OLD.outcome = 'claimed' AND NEW.outcome NOT IN ('open', 'fired', 'skipped') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'claimed schedule slot may only reopen, fire, or skip';
    END IF;
    IF NEW.outcome = 'fired' AND (
           NEW.delivery_id IS NULL
           OR NEW.delivery_id IS NOT DISTINCT FROM OLD.delivery_id
       )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'fired schedule slot requires a new delivery id';
    END IF;
    RETURN NEW;
END
$$;

REVOKE ALL ON FUNCTION mcloving_guard_trigger_schedule_slot() FROM PUBLIC;

CREATE TRIGGER trigger_schedule_slots_transition_guard
BEFORE UPDATE ON trigger_schedule_slots
FOR EACH ROW
EXECUTE FUNCTION mcloving_guard_trigger_schedule_slot();

ALTER TABLE trigger_schedule_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE trigger_schedule_slots FORCE ROW LEVEL SECURITY;
CREATE POLICY trigger_schedule_slots_tenant_policy
    ON trigger_schedule_slots
    USING (
        organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    )
    WITH CHECK (
        organization_id = NULLIF(current_setting('mcloving.organization_id', true), '')::uuid
    );

GRANT SELECT, INSERT, UPDATE ON trigger_schedule_slots TO mcloving_tenant;
