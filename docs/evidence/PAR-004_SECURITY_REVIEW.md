# PAR-004 closure receipt: build notifications

Ticket: `PAR-004`. Merged as PR #151, squash commit
`bf47e75129e1b846e32adede1cf0fccf1ab62896` on 2026-09-12.

## What merged

- Pipeline IR v1.9: a root `notify` list of at most eight targets, each
  exactly one of `github_status: {mapping_id, commit, context?, repository?}`
  or `webhook: {mapping_id}`, naming a deployment-owned mapping and never a
  destination; the commit is the one field a parameter may supply. The
  domain crate owns the type and validators; the canonical bytes carry the
  targets after the stages under the new minor; a pipeline that names none
  keeps its earlier schema and bytes. Versioned components and the
  sequential planner refuse targets rather than dropping them.
- Notification mapping catalog: `MCLOVING_NOTIFICATION_MAPPING_CATALOG`
  (digest-pinned, trust-class nofollow) binds each mapping to one repository
  or one `https` destination and to one organization and project. Every
  target is resolved against it at save, validate, plan and submission;
  unknown, foreign, mismatched or uncredentialed mappings answer 422
  `notification_mapping_denied`. The resolved targets (repository
  lowercased) are recorded on the build and bound into its replay contract,
  and the DAG contract validates their complete shape.
- Credentials: `MCLOVING_GITHUB_TOKEN_FILE` and
  `MCLOVING_NOTIFICATION_KEY_FILE`, owner-private secret-class files;
  `MCLOVING_PUBLIC_BASE_URL` (an origin) for the link a notification
  carries, which the UI follows to the build once the token is supplied.
- Ledger (migration 0040): `notification_deliveries` written in the
  transaction that makes a build terminal (the dead-letter path included)
  with one `dag.build_terminal` event; rows claimed `FOR UPDATE SKIP LOCKED`
  under a 90 s lease for the kinds the controller holds a credential for,
  delivered concurrently under a 30 s deadline, settled by terminal
  generation and attempt count, backoff scheduled at settlement, twelve
  attempts then abandoned.
- Ordering of writes at an external key: every attempt is marked in flight
  under the status key's advisory lock before its request and the mark
  stands through failure and reclaim; a build that becomes terminal again,
  or a later build for the same repository, commit and context, takes the
  same lock and delays its first post past the in-flight attempt's
  deadline; an older attempt that finds a later build recorded is
  superseded and sends nothing; a stale settlement re-queues or marks the
  newer generation for one more post.
- Delivery: destination resolved (injectable resolver) and every address
  checked (IPv4 special-purpose ranges; IPv6 by allowlist inside `2000::/3`
  with embedded IPv4 forms decided by the embedded address and local-use
  NAT64 refused), the client pinned to the checked addresses, no redirects,
  no proxy, `https_only`, bounded timeouts and answer. GitHub commit status
  `POST /repos/{owner}/{name}/statuses/{commit}`; webhook as a signed JSON
  record (`X-McLoving-Signature-256`, delivery id with terminal
  generation).
- Docs: `PIPELINE_IR_V1.md` (v1.9), `PUBLIC_API_V1.md`,
  `controller.env.example`, deploy-lib classification; threat-model section
  (TM-054 added, TM-039, TM-013); `scm_webhook` and `notifications` join
  the controller-postgres lane.

## Review

Twenty-one Codex rounds; clean on the twenty-second. Rounds one to ten
each hardened the same family, the ordering of writes at an external key:
claim lease past the deadline, concurrent delivery inside the lease, the
terminal generation fence, an IPv6 allowlist, claiming only deliverable
kinds, the replay contract carrying the resolved targets, re-posting after
a stale settlement, supersession by the latest build, the in-flight mark
before any request, and the status key's lock serializing the mark against
the terminal record. Past the cap, rounds eleven to twenty-one fixed small
ones in place (the mark kept through failed settlement and reclaim,
abandonment dropping it, full validation of resolved targets with a URL
parse and a lowercase repository, the dead-letter terminal path notifying
once, lock order, components and sequential admission refusing targets,
the notification link opening its build) and filed `CTRL-007` for what the
local deadline cannot bound: a request the target applies after the quiet
interval (reconciliation by read-back) and network-specific NAT64 prefixes
(operator-named). One residual is stated without a ticket: the status-key
fence is tenant-partitioned, so two organizations mapping one repository,
commit and context race at GitHub.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-pipeline-ir` | all suites incl. `tests/notify.rs` and the component refusal |
| `cargo test -p mcloving-controller-api --lib` | catalog validation, address policy (52 refused, 11 allowed), destination shape, sanitized errors |
| `cargo test -p mcloving-controller-api --test notifications` (fresh PostgreSQL, local sink) | admission refusals, ledger at terminal, retry with the error kept, signed webhook, two workers claiming one row once, credential-scoped claims, private-resolving destination refused, supersession by a later build, base URL shape |
| `cargo test -p mcloving-controller-store --test postgres_truth` (fresh PostgreSQL) | 59 incl. the terminal ledger, generations, leases, in-flight marks, supersession, the dead-letter path |
| `cargo test -p mcloving-controller-store --test dag_contract` | resolved target shapes refused by field |
| `cargo test -p mcloving-controller --test deployable_runtime -- --ignored` | grant matrix and forced-RLS pins with the new table |
| Proof (HeMan): shipped controller, embedded worker, PostgreSQL 17 | two builds of a pipeline naming the `SuperBadLabs/cljest` mapping wrote `success` and `failure` statuses on the real head commit with a target URL answering the controller UI |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34666100980, success |
| Exact-main Windows Agent | run 34666100983, success |

## Threat model

Boundaries reviewed: TM-054 (new), TM-039 and TM-013; the closure section
in `docs/threat-model/README.md` records the review and its residuals (the
items carried by `CTRL-007`, the system roots, the tenant-partitioned
status key). No production authority is granted.
