# Related work: Fogell

Updated: 2026-08-05

Status: informational. This document grants no authority, transfers no
evidence, and changes no ticket. It exists so that McLoving work can consult
Fogell's measurements instead of rediscovering them, under the boundary rules
below.

## What Fogell is

Fogell is an end-to-end F# CI engine pursuing the same charter as McLoving —
a better and faster Jenkins, with compatibility claimed only where
differential evidence proves it — from the opposite architectural end. It is
owned by the same owner, developed privately, and named for the character
whose real identity sits behind the McLovin fake ID; the naming is not a
coincidence and neither is the relationship.

- Checkouts: local on the owner's development machine; board records HeMan as the canonical private repository.
- (Intentionally location-agnostic: do not record hostnames or filesystem paths here.)
- Command center: `docs/EXECUTION_BOARD.md` (waves 0–8, `FG-xxx` tickets),
  `docs/adr/` for decisions, `evidence/` for sealed receipts.
- As of 2026-08-05: 44 of 100 live board tickets DONE, 4 PARTIAL. The durable
  spine (PostgreSQL, exactly-once resume proven under a real SIGKILL), both
  pipeline front ends, and 63/63 tier-1 differential cases are complete;
  operations and release waves are untouched. Linux only; no agent fleet.

## The architectural disagreement, stated plainly

Fogell exists partly as a critique of ADR 0006. Its founding measurement is a
74.3% lowering tax observed when a Groovy front end is split from the engine
by compiling the pipeline AST to a static IR — the shape of McLoving's
compatibility plane. Fogell's answer (`fogell:docs/adr/0002`) is to interpret
the pipeline AST directly in a bounded, capability-limited, structurally
sandboxed interpreter, so the tax is never paid.

McLoving's answer is that an isolated, pinned, deterministic compiler with
sealed provenance is worth the tax. Both positions are defensible; only
differential receipts and the performance contract (ADR 0011) can arbitrate.
When McLoving's migration campaign produces per-file compile results, the
per-file comparison against Fogell's interpreter results on the same corpus is
the cheapest available cross-check either project will ever get.

## Shared substrate

Both projects measure against the same oracle lineage:

- The same hash-pinned 228-file Jenkinsfile corpus. Fogell's baseline
  scorecard and McLoving's `MIG-002` corpus report identical oracle signals:
  80 Declarative-valid, 199 compile/CPS entry, 119 reached agent scheduling
  (the only scoring denominator both boards accept).
- A pinned Jenkins 2.568.1 oracle. Fogell measured on luigi; McLoving's
  sealed inventory came from the Mario `jenkins-oracle-228` population.
  Same version, different hosts and plugin provenance — receipts are
  therefore comparable in SHAPE but never interchangeable.

## What Fogell has that McLoving can use

1. **Measured Jenkins semantics, with receipts.** Fogell has ~49 sealed
   differential receipts and its ADR 0005 records oracle behaviors that
   McLoving's migration and differential tickets will otherwise re-measure
   from scratch, including: `post` arm selection and ORDER (always → changed →
   fixed → regression → result-arm → cleanup, with `changed` firing on a
   first build); `timeout` defaulting to MINUTES and also arriving as a
   pipeline/stage OPTION that aborts the build; `failFast` being stage-level
   (rejected inside `parallel {}`) and producing `failure`, not `aborted`;
   `retry(N)` meaning N total attempts with no backoff; `input` timeout
   aborting with the following step never running; credential masking
   behavior including the three-line GString interpolation warning; UNSTABLE
   (not FAILURE) on failing `junit` reports; skipped stages leaving the build
   SUCCESS with their `post` not running. Every claim names its receipt.
   Use these to design tickets and predict oracle behavior; re-measure before
   claiming.
2. **Demand counts, counted not recalled.** Fogell re-measured corpus demand
   per construct and found the board's recalled numbers wrong up to 3x:
   `checkout scm` 49 files (not 15), `options` 33, `git` step 30, `agent
   { label }` 26, `parameters` 18, `agent { docker }` 13 (of 70 raw `docker`
   hits). These rank McLoving's remaining compatibility work by set-cover.
3. **A defect taxonomy paid for in review rounds.** 117 review findings
   across seven Fogell PRs clustered into five cross-cutting classes:
   cancellation ordering (54), string/GString/quoting provenance (52),
   abort-cause misattribution (40), fail-closed gaps (19), output-narration
   suppression (17). Fogell's measured lesson: each new step rediscovers
   these invariants one at a time unless they are swept once, centrally, with
   a test. Any McLoving component that walks pipeline steps should expect the
   same five classes, and the cancellation lesson transfers verbatim — the
   right question is not "does every site check?" but "does every site check
   in the right ORDER, and record which event actually happened?"
4. **Process findings that generalize.** Seal evidence LAST (a bundle sealed
   mid-review attests to a snapshot never merged); a claim-audit script that
   fails the build when a comment asserts measured behavior without naming an
   existing receipt; read every review round and diff the finding list.

## What McLoving has that Fogell lacks

For symmetry, and because the owner intends the investigation to run both
ways: Windows execution with atomic kill-on-close Job membership (`WIN-004`,
`AGENT-006`'s boot-ID-bound cancellation identity), a TLC-checked formal
model, a production mTLS agent fleet with journal-before-ack durability,
object storage with PITR and legal holds, RLS tenancy, and the sealed
migration inventory discipline. Fogell's open `FG-038a` (Windows executor)
and `FG-062` (agent protocol) are the tickets most directly informed by
McLoving's completed work.

## Boundary rules (non-negotiable)

1. **Receipts do not transfer.** A Fogell receipt proves Fogell-vs-Jenkins.
   It licenses no McLoving claim, no tier assignment under ADR 0001, and no
   board status. The reverse holds equally.
2. **Oracle measurements inform, re-measurement claims.** Fogell's
   measurements of JENKINS behavior may shape a ticket's design and its
   expected outcome, but the McLoving receipt must be produced by McLoving's
   own harness against McLoving's own pinned oracle before anything is
   recorded as proven.
3. **No scalar compatibility percentage**, here or anywhere. Both boards
   carry this rule independently; citing Fogell's acceptance numbers does not
   relax it.
4. **Read-only.** McLoving work may read Fogell's docs, receipts, and source
   for insight. Code that crosses over must carry provenance in the commit
   message and pass this project's own review, threat-model, and evidence
   gates as if written fresh.
