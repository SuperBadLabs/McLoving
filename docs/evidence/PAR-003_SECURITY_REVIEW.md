# PAR-003 closure receipt: human project role grants

Ticket: `PAR-003`. Merged as PR #153, squash commit
`ea20d437fd9c3e36c70e61bdafe0865a9012b601` on 2026-09-28.

## What merged

- Runtime human project role grants and revocations through
  `mcloving-identity-admin` (`grant-role` / `revoke-role`) and
  `PUT`/`DELETE /projects/{project_id}/memberships/{identity_id}` under
  `ProjectConfigure`.
- First Owner is admin-tool only; Owner manages Owner; last usable Owner
  cannot be revoked or demoted; revocation and demotion fence live sessions
  by bumping `identities.lifecycle_generation` in the same transaction.
- Migration 0041 records grant authority and time, membership revisions for
  `If-Match`, and the runtime-role write grants on memberships and lifecycle
  generation.
- Membership writes revalidate the caller's identity, session or credential,
  and mapped-policy generation under ordered locks so a concurrent demotion,
  revocation, fence or policy install cannot race the write.

## Review

Sixteen review rounds on PR #153; every finding fixed in the pull request
before merge. Residual: a mapped-policy `ProjectConfigure` grant is decided at
authorization time and rechecked under the policy lock inside the write; the
identity, session and credential are held for the write.

## Verification

| Check | Result |
|---|---|
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 36446151459, success |
| Exact-main Windows Agent | run 36446151406, success |
| Store and API membership suites | green on the merged head |

## Threat model

Boundaries reviewed: identity lifecycle fencing, membership authority lattice,
mapped-policy reauthorization and session/credential revalidation. Closure
attribution is recorded in `docs/threat-model/README.md`. No production
authority beyond the reviewed role-grant surface is granted.
