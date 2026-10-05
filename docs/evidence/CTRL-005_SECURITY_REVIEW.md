# CTRL-005 local implementation and validation receipt

Observed on 2026-10-05 in isolated worktree `codex/ctrl-005-log-accounting-20261005`,
allocated from `8f2b625b7623aae7734576b85fa15424b86a7170`. This records local
implementation and independently executed observations. It does not close the
ticket or supply reviewed publication, protected merge, exact-main Foundation,
native Windows, or subsequent closure receipts. No production authority is granted.

## Result

Migration 0044 backfills durable committed bytes keyed by organization, attempt
and fence, and the last committed log position per build. Successful ledger
mutation maintains both in the same transaction under attempt-before-build
advisory locks. Modern quota reads the exact counter and modern position
allocation updates the durable build counter instead of reading prior chunks.
Identical retry charges neither bytes nor position; quota/authority refusal
leaves both unchanged. Accounting charges persisted redacted bytes.

Shared invoker triggers support current writers, pre-v39 column-list inserts,
and v39–43 full-column inserts. Older binaries retain their original SUM/MAX
query cost until upgraded. The new relation has forced tenant RLS, exact
runtime grants and startup inventory coverage; trigger functions expose no
PUBLIC execution. Startup cardinalities derive from the expected-table CTE,
with strict policy expressions, roles, ownership and FORCE checks preserved.
Unexplained missing accounting fails closed. Existing restrictive chunk foreign
keys remain; supported chunks-first cleanup removes zero accounting when its
parent is deleted, and deleted positions are never reused.

The original primary key and all other indexes remain unchanged. The modern
duplicate query keeps every original key/owner/restore-epoch/current-metadata
predicate and omits `FOR UPDATE`. Direct UPDATE/DELETE lock their tuple before
the BEFORE trigger waits on the attempt advisory lock. A duplicate lookup that
owns the advisory lock and then requests that tuple can close a deadlock cycle.
The actual overlap control and `FOR UPDATE` mutation below prove this reason
independently of speculative index-performance work.

## Exact acceptance scope and remaining cost

The ticket's explicit proof requires no prior-chunk read **“beyond its own
conflict check.”** Initial root validation imposed the stronger condition that
even own-conflict checks always be bounded point reads. After retained real
counterexamples, root explicitly corrected that added scope to the original
exception. This change is recorded; it is not a universal zero-cost claim.

The classifier permits only the two complete extracted conflict statements:
modern organization/attempt/fence/sequence lookup with all owner/epoch/current
metadata predicates, and the trigger's exact four-key duplicate-position lookup.
It compares complete whitespace-normalized SQL. Relation names or labels alone
cannot exempt a scan; missing fence/sequence/owner/current-epoch predicates,
wrapped queries, SUM and MAX receive no exception. Source controls exercise
these refusals. Raw returned, filtered and rechecked rows times loops remain
counted and reported; ModifyTable INSERT RETURNING is excluded from prior reads.
Every nonconflict quota, allocation and nested counter statement remains subject
to zero prior-chunk reads.

**Known residual:** an original-index stale-stat fixture reads 3,000 prior rows
in each exact conflict statement, while quota and INSERT read zero. An earlier
grown lookup touched 2,076 blocks. Those real conflict-check costs can still
make whole append quadratic. Incremental accounting is achieved; universally
constant-cost append is not claimed. The speculative covering-primary-key
rebuild passed a fresh fixture but failed on a grown fixture and was removed.

## Actual current verification

All runs below were independently scheduled/executed by root against pinned
PostgreSQL 17.6 in an owned container with no network/published ports, private
Unix socket and disposable data. The original deployment database was untouched.

| Actual check | Observed result | Elapsed seconds |
|---|---|---:|
| Nine `ctrl005_` PostgreSQL controls, fresh current schema | 9 passed | 11.896 |
| Full `postgres_truth`, separate fresh current schema | 68 passed, 2 ignored | 10.838 |
| Store + controller Clippy, all targets, `-D warnings` | passed | 11.816 |
| Both ignored `deployable_runtime` tests, fresh schema | 2 passed | 9.663 |
| Actual seed → custom pg_dump → pg_restore → verify | both exact ignored canaries passed; owned DBs removed | 1.393 |
| Final byte-restored nine-control run after mutations | 9 passed | 9.864 |

The controls cover exact 64 MiB plus next-byte refusal and unchanged counters;
identical/conflicting/concurrent retries; stale fences/sessions; tenant isolation;
redacted stored-byte charges; both legacy writer shapes; legacy quota rollback;
mixed-writer lock order; multi-tenant/historical-fence migration backfill and
reentry; monotonic cursors; restrictive parent deletion and supported cleanup;
actual pg_locks-observed UPDATE/DELETE waits; and the real duplicate query during
that overlap. Startup tests remove the accounting policy and separately disable
FORCE, require the precise inventory refusal, restore both, and retain existing
credential-preservation and valid-startup/submission checks.

Actual backup verification restores historical/current byte counts and build
position, then appends under the current restore epoch through restored triggers.
The current custom dump is 458,059 bytes, SHA-256
`766888efb0753063b75a30d9255de1a6068d3fdc23531bb21761dc0dce0371fe`.

## Complete append and nested plans

After 3,000 real unprivileged runtime commits, a measured complete production
append used backend 1578. The capture has 17 emitted plans, including its fixture
backend-ID probe and actual nested trigger SQL. Exactly two full-key conflict
statements match extracted source/migration identities; every nonconflict
statement visits zero prior chunk rows. Fresh measured own checks each visit
zero rows and touch two blocks. The separately controlled stale-stat case
reports existing=3,000, trigger=3,000, quota=0, INSERT=0; no costs are hidden.

Ordinary INSERT EXPLAIN does not expose nested trigger statements. This proof
uses retained actual `auto_explain.log_nested_statements` output, enabled only
on the measured fixture connection through fixture-only parameter grants.
Production grants have no tracing privileges. Raw trace SHA-256:
`d607fef332068fa3a139a682cd35f4fcd6eeb43d770b8ac13ca97ca94b8eff6b`.

## Actual mutation controls and restoration

Each control first passed its exact unmodified baseline, then failed for its
named behavior. Root restored source bytes after every mutation and passed the
final nine-control run. Compile/setup failure, timeout or a different earlier
assertion is not recorded as a meaningful kill.

| Mutation | Actual specific failure |
|---|---|
| Omit filtered visits | filtered oracle 0 versus 6,000 |
| Omit index rechecks | recheck oracle 2 versus 8 |
| Restore original quota SUM | quota gate 3,000 versus 0 prior rows |
| Restore original INSERT position MAX | allocation gate 1 versus 0 prior rows |
| Restore only duplicate `FOR UPDATE OF l` | PostgreSQL `40P01` deadlock |

The MAX trigger still overrides a supplied position: its meaningful failure is
forbidden prior-row allocation work, not cursor regression. The deadlock mutant
runs the actual duplicate query directly, without a classifier shortcut. Process
1957 waits on the attempt advisory held by 1958; 1958 waits on transaction 74318
held by 1957. The actual UPDATE reports `40P01` in the trigger's attempt-lock
PERFORM (line 26), rather than timing out. Both UPDATE and DELETE overlap pass
on restored source.

## Historical observations retained without promotion

- Tests-first RED on unchanged production compiled and executed: quota SUM read
  3,000 rows and MAX read one. An earlier HRTB compilation failure was not RED.
- A first counter-only nested trace filtered 3,000 in each conflict statement;
  counting only returned rows hid 6,000 visits, motivating the corrected oracle.
- Cloned-table comparisons made even the original bounded, so they earned no
  comparative repair proof. A covering-key fresh experiment passed eight tests
  (9.48 s) and full-key Index Only probes, then grown restored source failed
  7/8 at a 3,000-row conflict scan. That failure and its 2,076-block work remain.
- Later actual grown comparisons after statistics evolved chose read_idx with
  zero visits and 2–4 blocks for all candidates. Equivalence/refusal controls
  passed; no comparative failure or cause of the previous planner choice was
  established. No query-range, initplan, index-reordering or planner flag was
  adopted from those comparisons.
- The earlier covering-key stale-stat case analyzed an earlier 3,000-chunk
  tenant, grew a new tenant by 3,000 without refreshing stats and passed (5.194 s).
  It did not reproduce the grown failure. Autovacuum was disabled only on that
  owned scratch table. On the final original-index candidate the same pattern
  reports both 3,000-row conflict costs and strict zero nonconflict work.
- Actual startup found stale literal 64 checks after adding the 65th expected
  table: both binaries refused valid startup. Deriving both counts earned fresh
  67 passed/2 ignored (10.631 s), Clippy (3.069 s), startup 2 (6.675 s). Parent's
  missed cardinality finding and correction are recorded in review history.
- Earlier actual full coverage passed 67/2 ignored (9.50 s), store unit tests
  passed 23 (5.59 s), and actual dump/restore passed (1.742 s). These bind their
  historical source; the current-schema restore above supplies the final binding.
- The first MAX mutant failed earlier at an unchanged conflict scan, so its kill
  was explicitly unearned. Only three specific controls were earned then.
  The five v2 baseline→specific-red controls above supersede that unearned claim
  without rewriting the original failed records.

## Source and evidence custody

The following five candidate-phase file SHA-256 values were restored byte-exact
after all mutations and bind the recorded native, plan and final-restoration
receipts. The later base-composition observation below distinguishes the merged
threat document from those measured-phase bytes:

| File | SHA-256 |
|---|---|
| `crates/controller-store/src/lib.rs` | `496796d94e04941dd710abc1973356c7a2c56e36baebe6d724d32c555df99fb3` |
| `crates/controller-store/tests/postgres_truth.rs` | `71c6adf34247c6c91017469b084c195fb329b73bbedc66d15e0cd6c396388cfd` |
| `crates/controller-store/migrations/0044_log_accounting.sql` | `62f9915cbc4bdd51883ddcbf8782936b4bfd4ae5ad18004b4967e336f5f0bdb9` |
| `docs/threat-model/README.md` | `094b0ffbca2bcd3bbcb8fda50db052ea3ae1b2329440689f3263f29133744122` |
| `bins/controller/tests/deployable_runtime.rs` | `18d40380e87d10c18330bab94c205cc523e501f6e21e42b2c1fc748dc8ed423a` |

Historical binding groups (unchanged values explicitly shared across phases):

| Phase/file | SHA-256 |
|---|---|
| Tests-first RED lib | `427ffb405bba40ecb1249ca208d6a2bb2ef00a79fd351db479b01be67add51b9` |
| Tests-first RED test | `db3f5e5e5bb69c4be3f2726bd1c3b1509049d1fc95ba34a8824c2dbddcb64466` |
| Covering fresh8 lib; earlier full67/lib23/restore; pre-inventory helper-fix phases | `558080d0dbf9bd061fcff28fdeaf5bf1835f6000466f302621cbf54577fe0403` |
| Covering fresh8/earlier full67/lib23/restore test | `255479d22fca5eba63de7d8f307002d94648ae9f0b6116d758709357c69261f1` |
| Option-helper fix/inventory-fix test | `03bd4d5b5b29e33d7eaf686828eaa24952b5b0a06991fc20e009ab311eb21fc0` |
| Inventory fix/stale baseline lib | `542d0ef212e30e398c7c7ef7f68efe058a2d0f80efca8e8c0639d6050eadc594` |
| Covering/inventory/stale baseline migration | `2decb2d286242a19acbbbe3cf132ac8ca348c3533d23a16406c8617312c12600` |
| Covering/inventory/stale baseline threat document | `a3a709c080c7af534efe1fb0446121e0eafa2ef9235b689fe03a801b739e3250` |
| Inventory/stale baseline startup test (also current) | `18d40380e87d10c18330bab94c205cc523e501f6e21e42b2c1fc748dc8ed423a` |
| Covering stale baseline test | `f2e1a6cb72bba0be5195ee418c49b5871d5a67b80b6db4520e598c2d99de42af` |

Local retained artifacts are under `/tmp/mcloving-milestones/M2/CTRL-005/`:
`qualified-final-native-custody.json`, `qualified-native-verification.json`,
`qualified-plan-custody.json`, `qualified-backup-restore.json`, `mutations-v2.json`,
and companion exact baseline/red/restored logs. Historical bindings are in
`red-custody.json`, `root-green-custody.json`, `inventory-correction-native-verification.json`,
`stale-stats-baseline.json`, `mutations.json` and original raw logs. These are
local observational artifacts; this receipt does not fabricate hosted CI or
publication links.

## Review and remaining obligations

Parent `/root/milestone_m2` independently inspected source/schema/classifier,
legacy compatibility, retry/quota/lock behavior and affected threat boundaries.
Root separately reviewed the qualified source, formatted/froze its bytes and
executed native/plan/restore/mutation validation. Final receipt and changed-file
review precede publication; protected merge and exact-main Foundation/native
Windows precede earned closure. The ticket remains open through this handoff.

TM-018 quota/database CPU, TM-003/TM-011 fenced/session authority, TM-013
redaction and TM-005/TM-017 durability/restore are affected. No capability or
protocol change is introduced for authentication, external authorization,
secrets, agent execution, compiler, connectors, pool enrollment, supply-chain,
deployment contracts, migration or decommission authority. The conflict-scan
residual is explicit; privileged operator corruption/storage/kernel/database
risks remain existing operational boundaries.

## Subsequent base-composition observation

At 2026-10-05T19:43:38.352573+00:00, the candidate was rebased onto protected base
`4bdcbcf78cd040390a6f1afb689f8535fb415b60`. Its four runtime source/test/migration
files remained byte-identical to the measured values above. The complete
seven-file topic delta retained every reviewed added/removed line and path.
The board retained the published PAR-005 closure plus the single CTRL-005
ACTIVE substitution. The threat document retained all protected-base PAR-005
and CTRL-006 evidence plus the identical reviewed TM-018 replacement and
CTRL-005 section; its composed SHA-256 is
`1cb11409a46c4d986419edd8b999796d6105b92c3c8c194bb3744c9a3fc433d7`. The earlier threat hash in the
table binds the measured candidate phase, rather than this composed document.
This follow-up qualifies custody only; it changes no executable, schema or
test bytes and supplies no hosted-check, merge, native-Windows or closure result.
