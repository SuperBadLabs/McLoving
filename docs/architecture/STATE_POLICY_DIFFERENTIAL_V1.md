# State and policy differential v1

Status: `DIFF-002` verified implementation; independent exact-head review,
protected checks, and merge remain required before closure.

## Certified boundary

`mcloving.jenkins.state-policy-differential/v1` is a fail-closed certificate for
the identity, authorization, operational-state, and persistent-history semantics
needed by the admitted `MIG-005A` stateful fixture. It is deliberately separate
from the native execution differential: `DIFF-001` compares one compiled build,
while this ticket compares the state and policy that surround build admission,
history consumption, restart, and reverse reconciliation.

The repository bundle is
`migration/state-policy-differential-v1`. Its exact two-file tree contains a
canonical JSON observation and a canonical self-excluding manifest. The JSON
SHA-256 is compiled into the independent Rust verifier, so rewriting the
observation and resealing its adjacent manifest cannot grant authority.
The contained runtime comparison loads that same exact observation and binds
its active, deleted-predecessor, replacement, authorization, operational-state,
disabled-ingress, and zero-build fields to the live Jenkins and McLoving
observations. This prevents substitution within that live-compared slice.
Alias history, membership and ACL metadata, issuer/subject metadata, lifecycle
and group generations, provenance, enabled-ingress counts, and persistent
history remain protected by the compiled digest and strict static verifier but
are not all independently live-derived by this receipt. Accordingly,
`certificate_binding_equal` is a scoped runtime join, not a claim that every
static certificate field was re-observed live.

This boundary binds the already accepted exact-profile `MIG-005A` receipts:

- Jenkins image SHA-256
  `f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`;
- PostgreSQL image SHA-256
  `ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`;
- forward bundle SHA-256
  `af172be8893e282b72fc20b820382c8236e18c7b981bc3b4acbf57884ead55e4`;
- reverse bundle SHA-256
  `1a66f2c6354011abd23f45671674291e0b22faeea1043791920fc5ee0123ef52`;
- sealed transform-evidence manifest SHA-256
  `e28b47d2aa70ec2ad8cdaa2c48e1100c8862c9a47765d22a355c1660e96cafe7`.

It also binds the reviewed `IDP-001`, `AUTHZ-001`, and `JOBSTATE-001`
implementation identities and a detached SHA-256 of the audit implementation
used by the fixture. Those substrate identities are prerequisites, not
substitutes for the DIFF-002 comparisons.

## Compared semantics

The v1 denominator contains two immutable principal cases and eight explicit
authorization decisions. The active renamed human retains its immutable source
ID, ordered alias history, source membership and ACL generations, exact target
issuer/subject/principal, lifecycle and group generations, and provenance
digest. The deleted-name-reuse case uses a distinct immutable source and target
identity and has no authority. Both cases compare source and target decisions
for view, trigger, cancel, and configure; inactive identities must deny all four.

Operational state compares three monotonic generations: initial enabled,
disabled, and rollback-as-new-enabled-generation. Each generation contains an
exact manual, API, upstream, webhook, and schedule ingress matrix. Disabled
observations must reject before queue materialization and must report zero
builds, credential grants, approvals, and effects. Source and target
observations must be byte-semantically equal. Rollback never rewinds the
generation counter.

Persistent history compares:

- unique builds 1 through 4, next build number 5, and previous successful result;
- four exact SCM revision observations and the false/true/true/false
  changeset/changelog selection sequence;
- one cross-build artifact digest per build, retained workspace digest, and
  persistent-state digest;
- the strengthened retention deadline and all three strictly ordered active
  holds with positive generations and release authorities;
- approval identity, submitted-value digest, expiry, and expired-submission
  denial;
- checkout `failed -> succeeded` retry lineage and three
  `fail_fast_skipped -> succeeded` descendant lineages;
- effect-free first authoritative build 3; and
- restart and rollback observation digests plus exact forward/reverse binding.

The complete adversarial denominator covers approval identity/value/expiry,
deleted-name reuse, same-name collision, rename, group-generation fencing,
every disabled ingress, the disable race, history gaps, hold omission and
release, restart, rollback, reverse reconciliation, and the effect-free first
authoritative run. A denied case that reports any queued build, grant, approval,
or effect is rejected even when both sides make the same unsafe mistake.

## Independent verifier

`mcloving-state-policy-differential` rejects symlinked, special, extra, missing,
oversized, or non-canonical bundle content before parsing semantics. Serde
rejects unknown fields. The verifier then checks the frozen substrate hashes,
positive identity and operational generations, unique identities, strictly
ordered aliases and holds, the complete action/ingress/scenario denominators,
source/target equality, zero authority on denied and disabled cases, contiguous
history, exact approval expiry behavior, exact retry pairs, and the effect-free
first authoritative run.

Mutation tests prove failure on dependency substitution, principal collision,
alias reorder, lifecycle or decision divergence, authority after disable or a
stale group generation, history/hold/retry omission, approval-expiry broadening,
first-run effect authority, restart/rollback substitution, scenario omission,
extra files, and symlinks.

Run the repository verifier with:

```text
cargo run --locked -p mcloving-state-policy-differential -- \
  migration/state-policy-differential-v1
```

## Contained exact-profile gate

`scripts/test-state-policy-differential.sh` refuses a dirty source tree, creates
a new immutable evidence directory and an internal-only Podman network, and
starts the pinned Jenkins and PostgreSQL images plus a pinned Rust runner.
Jenkins boots with a private synthetic realm and a built-in persisted
authorization strategy for authenticated administration. The fixture password
is generated per run, mounted from a mode-restricted read-only file rather than
an environment variable, used through a temporary netrc file, checked absent
from retained evidence, and deleted with the temporary home. The Jenkins
controller is destroyed before the longer target phase, and that boundary is
recorded in the sealed evidence.

An authenticated, crumb-protected runtime probe installs the fixture strategy
into the running Jenkins instance without persisting its script class. Every
decision is then evaluated through the real freestyle job's `getACL()` result,
not by calling a detached fixture ACL. The ACL keys view grants to Jenkins
core's stable per-user session seed rather than an `Authentication` object
reference, and the probe proves two distinct authentications for the active
account receive the same decisions. For the predecessor, the probe captures
the view grant, deletes the account, revokes the retained authentication inside
the installed ACL, and records four post-delete denies. It then recreates the
exact same Jenkins login, proves the stable user seed changed, and proves the
replacement inherited no action. The PostgreSQL-backed target test performs
the corresponding explicit imported grant, lifecycle deletion/session
revocation, same-alias replacement with a distinct immutable identity, four
authenticated post-delete predecessor denies, and four replacement denies. The
probe also drives the job through enabled, disabled, and
rollback-as-new-enabled generations and proves disabled pre-queue denial and
post-rollback admission. All Jenkins HTTP
calls have finite connect and total timeouts. A negative socket probe proves the
Jenkins container cannot reach a public address.

The Rust runner has all default capabilities dropped, no-new-privileges, and
finite CPU, memory, and PID ceilings. With Cargo network access disabled it
reads only the host's prefetched Cargo registry through a read-only mount, runs
the sealed differential mutations and the real-PostgreSQL identity,
authorization-mapping, operational-state, and typed-trigger-ingress suites,
then runs the independent bundle verifier. These suites export observations
from the authentication, decisions, transitions, and admission paths they
actually exercise. The gate compares their immutable identity, four-decision
matrix, three state/generation pairs, five-ingress disabled matrix, zero-build
result, disabled pre-queue result, and rollback admission directly with the
live Jenkins observation and fails unless every field matches. The evidence
includes the runtime observations, the comparison verdict, initially pinned
and post-run-rechecked source commit/tree/status, image, container and network
inspections, source-file hashes, the full test transcript, and a self-excluding
manifest.

The protected Foundation workflow also runs authorization-mapping tests against
its pinned PostgreSQL service; previously that suite was present in the local
PostgreSQL harness but absent from the hosted protected job.

The accepted contained implementation run used clean pushed head
`cfe82a9870c04f06173d3bc5ab52ea005d653800`, tree
`7006406b033ea3d62520209fa126ec85f7829689`. It passed eight sealed-bundle and
mutation tests, three ordinary identity-lifecycle tests, four ordinary
authorization-mapping tests, four operational-state/race tests, five typed
trigger-ingress tests, and the final independent bundle verification. The two
ignored identity and two ignored authorization cases are the deliberately
separate source/restore halves driven only by `scripts/test-backup-restore.sh`;
they were not silently counted as executed. The protected recovery job remains
the required multi-database proof.

The live Jenkins and PostgreSQL-backed target observations matched the immutable
active identity `jenkins-user-immutable-1042`; allow/deny decisions for project
view, build trigger, build cancel, and project configure; the reused login
`alice-reused`; predecessor identity `jenkins-user-deleted-2041`, its view-only
decisions, deletion, and four post-delete denies; replacement identity
`jenkins-user-deleted-reuse-2042`, its changed authentication, and its four deny
decisions; enabled generation 1, disabled generation 2, and enabled generation
3; manual, API, upstream, webhook, and schedule disabled-ingress denial with
zero queued builds; disabled pre-queue denial; and rollback admission. The
target predecessor and replacement results come from real authenticated
PostgreSQL-backed principals, their returned immutable identity IDs, an actual
lifecycle transition, and calls to the product authorization engine, not
prefilled expected values. The five ingress results come from the distinct
product admission paths. The resulting
`mcloving.diff002.runtime-comparison/v1` verdict reports all seventeen
comparison dimensions, including stable source authentication and the sealed
certificate binding, and aggregate parity as true.

The runner exited zero with empty source status on an internal Podman network,
the exact Jenkins, Rust, and PostgreSQL image digests above, no added
capabilities, all default capabilities dropped, no-new-privileges, a read-only
Cargo registry mount, and finite per-container CPU, memory, and PID ceilings.
The repository mount was read-only; Cargo used a fresh writable target directory
inside the mode-restricted temporary runtime, which cleanup removed after the
run. No production credential or endpoint was present. The sealed external
evidence is
`/sn8100/runs/mcloving/diff002-state-policy-20260814T100550Z`; its
self-excluding 19-file manifest SHA-256 is
`710817c5f0571f9f20a128c35705cfbf8159bd42aad064a3230bb0cdab171e94`.
Independent re-verification of every manifest entry passed.

Twenty preserved predecessors contribute no authority. The first,
`diff002-state-policy-20260814T081748Z`, failed before test execution when the
Rust shim attempted a forbidden channel refresh. The second,
`diff002-state-policy-20260814T081844Z`, failed before compilation because the
offline runner had no dependency registry. The successful
`diff002-state-policy-20260814T081946Z` receipt was superseded by the verifier's
detached prerequisite-head bindings, exact positive/negative decision matrix,
state/generation pairing, exact artifact/hold/retry denominators, and universal
zero-authority adversarial fence. The accepted run explicitly selects the
already installed 1.97.1 toolchain and mounts the prefetched registry read-only
while keeping the evidence network internal. The successful
`diff002-state-policy-20260814T082540Z` receipt was then superseded by exact
per-case lifecycle and external-subject collision checks, unique artifact
digests, exact adversarial outcomes, and full untracked-source status capture.
The successful `diff002-state-policy-20260814T083055Z` receipt was superseded
because it verified the sealed model and target suites but did not derive and
compare a live pinned-Jenkins runtime observation.
The successful `diff002-state-policy-20260814T084604Z` live receipt was
superseded because its runtime join omitted the target deleted-name-reuse
decision matrix and its clean-tree requirement was enforced only before, not
after, test execution. The accepted runner also rejects evidence output inside
the source repository before creating it and refuses to seal if the source tree
changes during execution.
The successful `diff002-state-policy-20260814T085011Z` receipt was superseded
because its Jenkins authentication used a static synthetic credential that
failed the protected secret scan and its probe did not assert the installed
realm and strategy classes. `diff002-state-policy-20260814T085550Z` was
interrupted and preserved without authority after the pinned Jenkins log
exposed an invalid strategy constructor and the HTTP probe stalled. The
accepted run uses a per-run credential, the pinned-version constructor/setter
API, exact class assertions, and finite HTTP timeouts; its Jenkins log contains
no bootstrap-script or boot-failure error.
The successful `diff002-state-policy-20260814T090010Z` receipt was superseded
because its decisions called a detached ACL, it did not execute a real
delete/recreate lifecycle, its generated credential appeared in container
inspection, and it recorded rather than pinned the initial source identity.
The `091408Z`, `091519Z`, and `091635Z` attempts failed safely while the private
realm user lifecycle and secret-file UID mapping were corrected. The `091747Z`
and `091921Z` attempts proved the Jenkins half but stopped before a target
receipt while immediate secret cleanup and the predecessor's explicit imported
grant were corrected. None has a sealed manifest. The accepted run evaluates
the installed job ACL, performs the lifecycle on both sides, retains no secret
value, destroys Jenkins before target execution, and rejects any commit, tree,
or status change both after execution and immediately before sealing.
The successful `diff002-state-policy-20260814T092206Z` receipt was superseded
because the installed ACL retained view authority for the predecessor
authentication after account deletion. The
`diff002-state-policy-20260814T092907Z` run proved corrected Jenkins
post-delete denies but ended transiently before target startup and has no
sealed manifest. The accepted run compares four post-delete denies derived
through retained Jenkins authentication with four fresh McLoving token
authentication-plus-authorization attempts.
The `diff002-state-policy-20260814T093916Z` run proved the expanded Jenkins
five-ingress matrix but ended transiently before PostgreSQL startup and has no
sealed manifest. The subsequent successful run derived the target identity
change from the two authenticated identity IDs and drove each typed target
ingress through its production admission path while proving zero builds were
created.
The successful `diff002-state-policy-20260814T093947Z` receipt was superseded
because its live runtime comparison and sealed certificate described different
fixture identity labels and were only independently verified. The accepted run
binds the exact compiled-digest certificate to the active, predecessor, and
replacement runtime IDs and decisions, all three state generations, all five
disabled ingress outcomes, and both zero-build counts; its
`certificate_binding_equal` result is true.
The successful `diff002-state-policy-20260814T094859Z` receipt was superseded
because its writable whole-repository mount exposed ignored host Cargo output
to the contained runner. The accepted run mounts source and the dependency
registry read-only, compiles into a new temporary writable target directory,
records those mount modes in sealed inspection, and deletes the target during
cleanup.
The successful `diff002-state-policy-20260814T095456Z` receipt was superseded
because its Jenkins ACL keyed grants to saved `Authentication` object
references. The accepted run keys grants to the stable Jenkins `UserSeedProperty`
identity, proves a fresh active authentication retains the same view-only
decisions, and proves same-login recreation changes the seed and inherits no
authority. No seed value enters retained evidence.

## Non-authority and limitations

This certificate grants no production identity-provider, principal, job,
trigger, credential, approval, scheduler, external-effect, canary, cutover,
rollback, or decommission authority. Its synthetic identity and policy cases
exercise the frozen product contracts; they do not claim that a production
Jenkins realm or ACL population has been migrated. The persistent-history side
is limited to the accepted `MIG-005A` stateful fixture and its exact four-build
reconciliation.

Any new principal class, action, ingress, operational-state rule, state record,
approval behavior, retry shape, source/target implementation identity, or
`MIG-005A` evidence digest changes this denominator and requires a new
versioned two-sided differential.
