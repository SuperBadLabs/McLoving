CREATE TABLE agent_sessions (
    agent_id text PRIMARY KEY,
    trust_pool text NOT NULL,
    session_epoch bigint NOT NULL CHECK (session_epoch > 0),
    protocol_minor integer NOT NULL CHECK (protocol_minor >= 0),
    features text[] NOT NULL,
    capabilities text[] NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

GRANT SELECT, INSERT, UPDATE ON agent_sessions TO mcloving_tenant;
