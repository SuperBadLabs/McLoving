# PAR-014 closure receipt: artifacts from the agent

Ticket: `PAR-014`. Merged as PR #150, squash commit
`9208e4e287dddfae6ce85f719fb211bbedafc18a` on 2026-09-11.

## What merged

- Pipeline IR v1.8: a stage may declare `artifacts: [{name, paths}]`, up to
  sixteen names per stage with one to thirty-two literal workspace-relative
  patterns each (`/`-separated segments; `**` alone matches any depth, `*`
  and `?` within a segment; never absolute, never `.` or `..`). The dialect,
  its bounds and the table-driven matchers live in the domain crate; the
  compiler refuses a bad declaration by field, the canonical bytes carry
  the declarations after the stage's steps under the new minor, the reader
  re-validates them, and a pipeline that declares none keeps its earlier
  schema and bytes.
- Routing: a stage with declarations rides the version-5 envelope and its
  node requires `artifact-upload-v1` beside `multi-step-v1`; the agent
  advertises the capability on Unix and offers the wire feature, the
  controller keeps the capability for scheduling only when the feature was
  negotiated, a Windows submission of such a stage is refused at admission,
  and an artifact node that reaches a session without the feature in a
  mixed rollout is declined before a step runs.
- Collection (agent): after the steps of an attempt that was not cancelled
  and before the terminal is made durable, a descriptor-relative walk from
  the agent-owned root resolved one component at a time without following
  a link, every directory and file opened `O_NOFOLLOW` and re-identified,
  the agent's own spool never visited, a directory entered only when a
  pattern can match below it, one object per matching declaration each
  with its own file description, bounded at depth 32, 65 536 entries, 1 024
  objects and 256 MiB. Refusals by name, recorded as the attempt's reason
  with nothing of the set uploaded: a link where a declaration would
  collect or descend (including the workspace or an ancestor of the root
  swapped for one), a non-regular match, an entry the walk cannot stat,
  open or read, a workspace the step made unreadable, a non-UTF-8 or
  control-character name, an object name past 512 bytes, a file that runs
  short, grows or is rewritten under either read, a bound, and a
  cancellation before or during collection.
- Upload: a new `UploadArtifact` client stream on `AgentControl` (header
  with work authority, name, length and SHA-256, then one-MiB data frames)
  under the shared upload budget (thirty seconds plus one second per MiB,
  at most fifteen minutes). The controller reads the header and the whole
  receive phase under that budget, charges each stream's declared bytes and
  one object against the attempt's quotas in an in-process ledger of
  streams in flight before staging (an exact retry of an available object
  is answered without receiving a byte; a pending one is charged once),
  stages through a streaming stager that reserves the declared length
  against the store quota and discards a short or mismatching upload,
  registers through the same fenced predicate the public commit route uses
  with the session epoch re-checked inside the registration and
  availability transactions, under an attempt-scoped artifact lock and
  then the per-name lock, refuses past 256 MiB or 1 024 objects, commits
  into the immutable digest namespace and marks the object available.
- Docs: `AGENT_RUNTIME.md`, `PIPELINE_IR_V1.md` (v1.8 section),
  `PUBLIC_API_V1.md`; threat-model section (TM-003, TM-006, TM-013, TM-018,
  TM-052).

## Review

Forty-two findings across eighteen Codex rounds
(5,3,3,3,4,4,2,2,1,2,2,2,1,1,4,1,1,1), clean on the nineteenth review.
Twenty-nine fixed in the pull request through round ten; from round eleven,
past the ten-round cap, thirteen filed: twelve as `AGENT-012` (a per-attempt
matching-work budget over precompiled patterns, a growth probe for
zero-length files, collected files reopened at upload time instead of
pinned, the controller's per-frame writes and finalization off the runtime's
workers, atomic publication of a declared set, cancellation inside the
digest pass, client-deadline headroom over the receive budget, a bounded
reader join, the in-flight ledger reconciled with registered rows, the
per-object quota answer as a named refusal, and a pending object's copy
resumed on retry) and one as `CTRL-006` (the sequential planner refusing
artifact-bearing stages rather than dropping their declarations; latent, no
pipeline reaches it). Rounds one to ten were each one narrow case of the
same three families: the walk's no-follow and identity discipline, the
upload's fencing and quotas, and refusals recorded as durable reasons rather
than session errors.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-domain` | 28 incl. pattern dialect, descent pruning, declaration bounds, matching bounded for 170 globstars |
| `cargo test -p mcloving-pipeline-ir` | all suites incl. `tests/artifacts.rs` (typed, versioned, canonical roundtrip, refusals by field, no version drift) |
| `cargo test -p mcloving-object-store` | 17 incl. the streamed stager |
| `cargo test -p mcloving-controller-store --test postgres_truth` (fresh PostgreSQL) | 58 incl. per-attempt byte and object quotas, scope, idempotent re-registration |
| `cargo test -p mcloving-controller-api` | all suites incl. the version-5 envelope with declarations, required capabilities, Windows admission refusal |
| `cargo test -p mcloving-agent --lib` | 108 incl. the assignment guard and the collector's refusals by name |
| `cargo test -p mcloving-agent --test remote_work` (pin 7 → 9) | 9: `declared_artifacts_are_uploaded_and_downloadable`, `a_planted_link_refuses_the_artifact_set_by_name` |
| `cargo test -p mcloving-agent --test long_step_lease` | 8, unchanged |
| Proof (HeMan): shipped controller and agent over mTLS, PostgreSQL 17 | `mcloving artifacts` listed both declared objects and `mcloving artifact-download` returned bytes whose digests matched the listing and the step's own `sha256sum`; a step planting `out/planted.txt -> /etc/hostname` failed with `artifact_refused:link:out/planted.txt` and listed nothing |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34652565336, success |
| Exact-main Windows Agent | run 34652565410, success |

## Threat model

Boundaries reviewed: TM-003, TM-006, TM-013, TM-018 and TM-052; the closure
section in `docs/threat-model/README.md` records the review and its
residuals (the in-flight ledger is per controller process; the items carried
by `AGENT-012` and `CTRL-006`). No production authority is granted.
