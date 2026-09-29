# Build workspace affinity v1

Status: PAR-015 implementation. Product multi-stage builds pin later stages to
the agent that ran the first stage and reuse that build's on-disk workspace so
a checkout in stage one is visible in stage two without re-acquiring it.

## Scope

- Applies to product DAG builds whose nodes require `workspace-affinity-v1`
  (admission adds that capability on every stage of a multi-stage product
  pipeline), with more than one `work` node and without the bounded checkpoint
  transfer namespace (`workspace_namespace` null). Multi-node DAGs that do not
  carry the capability are unchanged: they may still run parent and child on
  different agents.
- The small checkpoint snapshot mechanism (`BUILD_WORKSPACE_TRANSFER_V1`) keeps
  its caps for the contained sequential path; affinity and transfer are
  mutually exclusive on one assignment.
- Linux only in version 1. Windows multi-stage submissions are refused at
  admission.

## Behaviour

1. Admission adds the opaque capability `workspace-affinity-v1` to every stage
   of a multi-stage product pipeline. Agents advertise it with the negotiated
   feature `build-workspace-affinity-v1`.
2. The first stage is claimed by any eligible agent. On successful finalize the
   controller stores that agent id on `builds.workspace_affinity_agent_id`.
3. Later stages are offered only to that agent. The work assignment carries a
   `WorkspaceAffinityGrant` (`create` then `reuse`, with `retain_on_success`
   while further stages remain).
4. The agent materializes the workspace at
   `{organization_id}/{build_id}/workspace`. On reuse it opens that directory,
   strips the prior stage's `spool/`, and runs. Before publishing a successful
   non-final stage it writes marker `.mcloving-affinity-retain` so a crash after
   `complete_work` still retains the tree on recovery; reclaim honors the marker
   only when the journaled phase is `succeeded`, and otherwise clears it and
   removes the workspace. On reuse the next stage strips spool only.
5. If a later stage is ready and the pinned agent has no live
   `agent_sessions` row, the controller fails the build with
   `workspace_affinity_agent_gone` rather than offering it to another agent.

## Proof

`examples/parity/two-stage-checkout.pipeline.yaml`: submit, wait for success,
`mcloving graph` shows both attempts with the same `lease_owner`.
