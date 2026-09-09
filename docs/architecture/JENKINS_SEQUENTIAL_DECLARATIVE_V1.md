# Jenkins sequential Declarative contract v1

Status: preregistered contract for JCOMP-001. No new compiler admission,
execution equivalence, migration eligibility, or operational authority is
claimed. JCOMP-002 implements compilation; JCOMP-003 earns paired execution
receipts only after the necessary runtime work closes. ADR 0006 remains a
compile-only architecture: Groovy source is never evaluated by the compiler.

## Capability and admission boundary

The target is Linux sequential Declarative pipelines using these unqualified
call forms only: `pipeline { ... }`, `agent any`, `stages { ... }`,
`stage(STRING) { ... }`, `steps { ... }`, and either `sh STRING` or
`sh(STRING)`. The root contains `agent any` followed by `stages`; directive
reordering is not part of v1. Each stage has one `steps` block, containing only
its ordered literal-shell calls. Braced blocks have no explicit closure
parameters, arrows, labels, declarations, or extra statements. Explicit `this.`
or other receivers, safe-navigation, method pointers, and alternative invocation
forms are unsupported even if a Groovy AST could hide their lexical difference.

Source is strict UTF-8 without a BOM, uses LF line endings (no raw CR), and has
no NUL. Outside strings, allow whitespace, `//` line comments, non-nesting
`/* ... */` comments, optional statement semicolons, and an optional first-line
Groovy shebang starting at byte zero. That source shebang is a comment, never an
interpreter selection. Reject imports, package declarations, annotations, or
any other preamble. Ordinary formatting is accepted only where the pinned
Groovy parser produces precisely the permitted DSL AST; lexical recognition
and that AST must agree. Neither a standalone lexical recognizer nor stripped
AST metadata may broaden the source grammar.

STRING means a Groovy single-, double-, triple-single-, or triple-double-quoted
constant. Slashy and dollar-slashy strings, concatenation, arbitrary expressions,
and GStrings are unsupported. In double-quoted forms every dollar sign must
be escaped as `\$`; single-quoted forms may contain literal dollars. The only
backslash escapes are `\\`, `\'`, `\"`, `\$`, `\n`, `\r`, `\t`, `\b`, `\f`. Reject Unicode escapes, octal escapes, unknown escapes, and escaped
physical-line continuation. Raw LF is permitted inside triple-quoted forms
only. Escapes are decoded before byte limits and shell checks; decoded NUL is
unsupported. UTF-8 literal payloads receive no Unicode normalization.

Stage labels retain their original UTF-8 spelling. Derive identifiers by
folding ASCII `A` through `Z` to `a` through `z` only, replacing each maximal run
matching `[^a-z0-9._-]+` with one `-`, and trimming leading/trailing `-` characters.
Periods, underscores, and internal hyphens are preserved. Do not perform Unicode
casefolding, Unicode normalization, or locale-dependent lowercasing. Require
distinct nonempty normalized identifiers of at most 96 characters. For example,
a Kelvin-sign-only label is unsupported rather than silently becoming `k`.
This v1 sequential policy preserves historical `Build` -> `build`; it does not
change the legacy compiler's normalization behavior or receipts.

Bounds are checked on UTF-8 bytes: source 16,384; stage name 96; decoded shell
literal 4,096; all decoded shell literals together 4,096. There are at most 32
stages and 64 steps across the whole pipeline, and at least one stage and one
step per stage. Empty shell literals are unsupported. These are proposed v1
contract bounds, not a description of the broader existing parser constants.
The canonical worker response remains bounded at 65,536 bytes; response-capacity
failure must produce a bounded named rejection, never truncated success. Rust
admission independently checks the bounds and source/profile/output bindings.

Dynamic expressions/GStrings, Scripted Pipeline, plugin steps (including
Jenkins `echo`), wrappers, environment/parameters/options/tools/post/when,
parallel/matrix, shared libraries, Windows/bat translation, and additional
syntax are outside the subset. No construct is silently stripped or executed
during compilation. Malformed syntax is `rejected`; valid syntax outside the
subset is `unsupported`. Both return no admitted executable and schedule zero
work. The manifest preregisters exact diagnostics for its negative fixtures;
those names are requirements for future implementation, not current observed
results. Source-byte limits take precedence over parsing; otherwise fixtures
isolate one primary rejection reason. Other inputs need a stable diagnostic,
not an exhaustive cross-error precedence rule in this contract.

The compiler produces canonical strict YAML, independently validated Rust IR,
and a separate disabled imported-job record. `agent any` is resolved explicitly
to the contained Linux worker/platform and deny-production trust pool, not an
abstract scheduler capability token. Source content hashes and provenance stay
bound to every result; authored test provenance must not pretend to be a new
Mario inventory epoch. Supporting new sources must not depend on adding their
hashes to a hello-world allowlist. No new public production API is specified.

## Shell meaning and comparison

The declared shell is the pinned Linux `/bin/sh`, with Jenkins default `-xe`
behavior and no production endpoints or credentials. A decoded shell literal
beginning with `#!` is explicitly unsupported (`E_SHELL_SHEBANG_UNSUPPORTED`):
Jenkins's alternate-interpreter behavior is not the existing `sh -c` lowering.
The manifest tests that rejection. Shell script path/identity dependence
(including `$0`), Jenkins-specific environment variables and temporary paths,
agent-local tools/content not in the fixture, live SCM, external reads/writes,
secrets, time/randomness-dependent output, and deployment effects are excluded
from the execution-equivalence claim. An arbitrary shell program can disguise
such dependencies, so v1 does not claim to detect them statically. Syntactic
compilation support is not certification of every accepted shell program.
Only exact cases with paired contained execution receipts earn equivalence.

For each supported fixture, the manifest specifies decoded script bytes,
stage/step order, per-step succeeded/failed/skipped disposition and exit code,
semantic stdout, stage/build result, and final workspace file contents by
relative path, size, and SHA-256. First/middle/last-step failures are supported
inputs: expected failure is positive evidence of compatibility. A failed step
prevents every later step/stage from executing; skipped steps have no shell
exit code or output. Earlier output and files remain observable. S03 sets an
exported variable and changes directory in its first shell, then
requires the variable to be absent and the original directory restored in the
next shell. The contained fixture environment initially omits
`JCOMP_STEP_SENTINEL`. Separate `sh` steps use fresh shell processes; shell variables and `cd` do not persist across
steps, while workspace files do. Empty stages/steps are never synthesized to
represent skipped work.

The successor differential must carry ordered per-step records, not v1's one
`process` field and workspace-entry count. Preserve raw evidence. Compare exact
decoded scripts, effective interpreter/flags, exit codes, semantic stdout bytes,
workspace regular-file paths/content, stage and build outcomes, and actual
execution/skipping order. Record physical argv on both sides, but do not require
literal equality between Jenkins's temporary script-file argv and McLoving's
current `-c` argv. Any lowering difference must retain equivalent shell behavior
for the certified inputs.

The fixture scripts emit no intentional stderr. Jenkins console merges streams,
so these fixtures certify combined semantic console output, not universal
stdout/stderr interleaving parity. Normalize only runner-owned protocol banners,
Jenkins `[Pipeline]` markers, shell xtrace records independently attributed to
these exact commands, and the known shell nonzero-exit wrapper record. Retain
raw xtrace and independently verify it agrees with executed script/step order;
never discard an arbitrary workload line because it starts with `+`. For these
fixtures, literal expected output has no such ambiguity. Do not trim whitespace,
normalize arbitrary paths, drop unexpected lines, mask exit codes, or sort
execution order. Timestamps/build IDs/PIDs are receipt metadata excluded from
semantic equality, but their raw provenance and chronology remain verified.

Workspace comparison covers the fixture's relative regular files after the
last executed step and before build cleanup. Directory ancestors are derived
from those paths; symlinks and extra workload files are differences. Runtime
spools and Jenkins control files are separately inventoried control material,
not workload outputs; broad filename-pattern exclusion is forbidden. Final
cleanup is verified after collecting that observation. No artifact publication,
test-report, credential, approval, or effect count is earned by a workspace file.

## Fixtures, provenance, and claims

`compat/jenkins-worker/fixtures/sequential-v1/manifest.json` is the executable
expectation inventory. S01–S10 are original project-authored inputs covering
hello-world, three stages, three steps, quoting, multiline shell, same-stage and
cross-stage workspace continuity, and first/middle/last-step failures. They
contain no imported third-party source and make no new license grant. N01–N12
are separate negative inputs for syntax/subset/bounds, never execution jobs.
C052 references the unchanged original source in the historical corpus, with
its MIT provenance and source commit retained; it is not an eleventh authored
fixture. Existing historical attribution remains in the corpus index.

The target profile is the unchanged `compat/jenkins-worker/profile-v1.properties`,
SHA-256 `feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271`:
Jenkins 2.568.1, Groovy 2.4.21, Temurin 21.0.11+10-LTS, Clojure 1.12.1, and
90 exact plugin files. That file pins the image, WAR/core/Groovy JAR digests,
plugin-manifest digest, and historical source epoch. The manifest references it
by exact bytes rather than copying a floating dependency list. A compiler build
and execution runtime do not yet exist for this contract; JCOMP-002/003 must
add their exact identities to new evidence, never invent placeholder evidence.

Publish separately: 10 authored supported-input expectations, 12 authored
negative expectations, one historical regression, and 228 original sources to
reclassify later. No expectation is a measured result. Reclassification may
leave corpus coverage at 1/228: nearest other sources contain excluded `echo`,
`junit`, wrappers, or directives. Do not rewrite them into the subset and count
the rewrites as original-corpus compatibility. Keep parse reach, compile support,
executed fixtures, certified equivalence, and production eligibility separate.
NOASSERTION corpus sources remain evidence-only under their existing policy.
Historical receipts are immutable; this contract does not reseal them.

## Implementation prerequisites and acceptance

Current product admission rejects stages with more than one step; workers run
one process per attempt. Current workspaces are attempt/fence scoped and removed
after finalization. Therefore neither multi-step sequencing nor cross-stage
workspace continuity can be claimed by implementing the compiler alone.

Before final JCOMP-003 evidence, separate bounded ownership must deliver:

- **Step execution:** actual sequential per-step execution, preserved stage and
  step identities/results, failed-step downstream skipping, and terminal truth.
  Removing the admission guard or concatenating commands into one opaque shell
  is insufficient. Preserve fresh-shell semantics and validate-accepted implies
  runnable. JCOMP-002A owns this work after JCOMP-002 compiler/admission work.
- **Workspace continuity:** a build-workspace lifecycle or verified state
  transfer in dedicated disposable fixtures, with agent placement/transfer,
  namespace non-collision, fence/lease loss, cancellation/recovery, and whole-build
  cleanup ownership explicit. Controller/agent assignment must never give two
  builds the same workspace or deliver another build's state. Stale ownership
  and fence-bound lifecycle operations must be refused. Observe final outputs
  before cleanup. Reusing an attempt path or disabling cleanup is insufficient.
  JCOMP-002B owns this work after JCOMP-002A fixes step-execution ownership.
  This proves lifecycle continuity and non-collision, not denial of direct
  filesystem access by hostile same-UID workloads. Sibling-workspace read/write
  isolation and general hostile workload containment remain SEC-005.

The chosen order is JCOMP-002 -> JCOMP-002A -> JCOMP-002B -> JCOMP-003. The
chief-owned board must encode that order before JCOMP-001 closes; this document
authorizes no runtime changes. Preserve runtime admission guards until runnable
support lands: generalized compile-only output must not bypass product admission.
JCOMP-003 must wait for both runtime prerequisites. Workspace-dependent cases
remain execution-ineligible until JCOMP-002B lands. Any campaign finding that
requires a runtime change returns to a separate bounded implementation ticket;
its reviewed correction and regenerated affected evidence must precede the final
exact-runtime differential seal. JCOMP-003 is the evidence ticket, not a shared
implementation bucket.

JCOMP-001 acceptance is reviewed contract/fixture integrity: verify source and
profile hashes, closed populations, unique IDs, complete authored-file membership,
expected outcome consistency, explicit licensing/provenance and zero observed
execution claims. The companion validator is read-only and never executes a
Jenkinsfile or shell script. Mutation tests must expose source/profile drift,
omitted/extra files, duplicate identities, borrowed denominators, and inconsistent
failure/skip expectations. Local checks of the authored shell snippets may
validate their intended outputs; they are not Jenkins or product receipts.

The M1 execution boundary is a dedicated disposable Jenkins environment and a
separate dedicated disposable McLoving controller/agent/database environment,
using only reviewed fixed fixture scripts. The campaign must pin their exact
images, binaries, toolchain, resource limits, mount inventory, input snapshots,
and internal-only connectivity before execution. No production endpoint,
credential, service home, or shared production workspace may be reachable or
mounted. Capture bounded raw results and inspect the build workspace before
cleanup, then verify teardown. This fixture boundary cannot be promoted into a
claim that the shipped runtime isolates mutually hostile same-UID jobs or
protects production services; SEC-005 owns that boundary. If the disposable
boundary cannot be demonstrated for an exact run, that run yields no evidence.

JCOMP-002 must prove isolated deterministic compilation and independently
admitted lowering, including adversarial worker substitutions and rejected
lexical forms named above. Its tests must distinguish parenthesized `sh` from
unsupported receivers/preamble/closure parameters/alternate string syntax,
exercise every declared quote/escape form and source-text constraint, and
verify ASCII-only normalization with UTF-8 labels. These are implementation
test obligations; the fixed 23-fixture preregistration population is unchanged. JCOMP-003 must
execute every supported fixture on pinned disposable Jenkins and the shipped
McLoving controller/agent through explicit contained submissions while the
imported job remains disabled. Require zero unexplained differences, zero work
for negative inputs, workspace observations/cleanup, and separate 228-source
classification. No production authority, performance claim, live campaign,
history migration expansion, or deployment/cutover eligibility follows.

Reproduce contract checks from the repository root:

```sh
python3 compat/jenkins-worker/fixtures/sequential-v1/validate.py
python3 compat/jenkins-worker/fixtures/sequential-v1/test_manifest.py
(cd compat/jenkins-worker && clojure -M:foundation fixtures/sequential-v1/check_literals.clj ../..)
```

The final check independently decodes fixture literals with Groovy 2.4.21 at
CONVERSION, compares exact stage names/script bytes with the manifest, and
rejects the malformed-quoting input. It does not invoke the existing compiler,
evaluate Groovy, validate a Jenkins Declarative model, or execute a shell. Its
Groovy JAR must match the profile's pinned digest; the normal foundation alias
selects that version.
