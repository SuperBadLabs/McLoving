-- PAR-010: a stage may run several ordered steps inside one attempt. Their
-- output is distinguished by a step ordinal rather than by stream name, so
-- the stream check from 0003 stays exactly as it is and every existing row
-- is step zero.
ALTER TABLE attempt_log_chunks
    ADD COLUMN step_ordinal integer NOT NULL DEFAULT 0
        CHECK (step_ordinal >= 0 AND step_ordinal < 65536);
