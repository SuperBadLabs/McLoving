-- PAR-015: pin a multi-stage build to the agent that ran its first stage so
-- later stages reuse that agent's on-disk workspace. NULL until the first
-- stage succeeds; then later stages are offered only to this agent. A queued
-- successor whose affinity agent has no live session fails the build by name
-- rather than being offered to a different agent blind.
ALTER TABLE builds
    ADD COLUMN workspace_affinity_agent_id text
    CHECK (
        workspace_affinity_agent_id IS NULL
        OR (
            length(workspace_affinity_agent_id) BETWEEN 1 AND 512
            AND btrim(workspace_affinity_agent_id) = workspace_affinity_agent_id
        )
    );
