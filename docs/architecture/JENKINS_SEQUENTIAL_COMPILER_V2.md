# Sequential Jenkins compiler protocol v2

JCOMP-002 implements compilation and independent admission for the
[JCOMP-001 syntax contract](JENKINS_SEQUENTIAL_DECLARATIVE_V1.md). It does not
make the resulting pipeline runnable: sequential execution and workspace
continuity remain JCOMP-002A and JCOMP-002B, followed by paired evidence in
JCOMP-003. Existing imported jobs remain disabled.

## Version and authority

The new internal operation is `compile-sequential`, under protocol
`mcloving.jenkins.compiler/2` and compiler identity
`mcloving-jenkins-compiler-worker/2`. Protocol v1, its exact-source admission,
public Rust functions, CLI shapes, golden receipts, and default local image
remain unchanged. Neither validator accepts the other protocol's response.
There is no new production endpoint or execution authority.

The contract SHA-256 is
`ae47b3f3cc58d6a66cec6d73832a189417864df74110c83bf1f656840c5d5dfe`.
The unchanged target profile SHA-256 is
`feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271`.
The target profile describes the pinned Jenkins/Groovy/plugin environment;
its historical Mario inventory fields do not describe a newly supplied source.

## Document attribution

The caller supplies a bounded canonical EDN document context with exactly these
fields. The context identifies a logical source document, not an observed
Jenkins job or a new inventory epoch.

| Field | Meaning and bound |
|---|---|
| `:schema` | `mcloving.jenkins.source-document/1` |
| `:document-id` | 1–128 ASCII bytes; initial alphanumeric, then alphanumeric, dot, underscore or hyphen |
| `:origin-kind` | `:authored-document` or `:corpus-reference` |
| `:origin` | Nonempty printable ASCII, at most 512 bytes; attribution only, never dereferenced |
| `:source-sha256` | SHA-256 of the exact source snapshot, lowercase hexadecimal |

The context is at most 2,048 bytes. Unknown or duplicate fields, invalid types,
noncanonical encoding and source-digest substitution fail. Its digest covers
canonical EDN plus one LF. Equality to caller attribution is verified; the
compiler does not authenticate publication, ownership or upstream provenance.
No actor, generation, effective time or controller epoch is fabricated.

Canonical EDN uses the existing sorted-map formatter, including comma and space
between fields, and exactly one final LF. Original request bytes are retained
for v2 canonical validation. Legacy input decoding and error behavior remain
unchanged. Request IDs retain the existing 1–96 ASCII-byte syntax: initial
alphanumeric, then alphanumeric, dot, underscore, colon or hyphen.

## Request and response

A request contains exactly `:operation`, `:protocol`, `:request-id`,
`:source-context`, `:source-path`, `:target-contract-sha256`, and
`:target-profile-sha256`. The operation is `:compile-sequential`; the source
path is always `/input/Jenkinsfile`. Rust constructs the request from validated
caller snapshots; the launcher does not interpolate EDN from shell arguments.

A compiled response contains exactly `:authority`, `:compiler`,
`:contract-sha256`, `:protocol`, `:request-id`, `:result`, `:source`,
`:source-context`, `:status`, and `:target-profile`.

The source receipt contains exact byte count, source SHA-256 and context SHA-256.
The result contains canonical pipeline YAML and its digest, canonical disabled
definition YAML and its digest, stage/step counts, and an explicit mapping:
Jenkins selector `any`, McLoving platform `linux`, trust pool
`migration-deny-authority`, and effect authority false. This mapping is metadata
for a later contained submission; it does not add scheduler fields to IR.

All eight authority fields remain false: agent protocol, controller filesystem,
controller store, credentials, effects, network, scheduler and workload execution.
The complete encoded response, including LF, is at most 65,536 bytes. Capacity
failure produces a bounded named rejection, never truncated success.

An attributed unsupported response has the same common bindings, a diagnostic
and status `:unsupported`, and no result. A boundary rejection has only authority,
compiler, diagnostic, protocol and status `:rejected`; it cannot invent a request
identity. Fixed diagnostic messages contain no source excerpts.

## Independent parsing and admission

The worker checks source byte/text constraints, performs Groovy PARSING only,
then recognizes the original source's lexical and structural subset. It invokes
CONVERSION only after that recognition, and compares the actual AST's stage
names and literal values with the recognized source. It never evaluates a
Jenkinsfile. Excluded annotations, imports, declarations and receiver forms
cannot reach conversion. Groovy parsing success alone is not Jenkins validity.

Rust independently derives names, ASCII-normalized stage IDs, exact decoded
scripts and order from the original source bytes. Admission compares the
complete expected YAML lowering, reparses strict YAML, validates typed IR and
canonical IR, and checks every source/context/profile/contract binding. It
requires no parameters or expressions, no injected environment, direct process
mode, `/bin/sh`, exactly `[-xe, -c, script]`, no timeout injection, and exact
stage/step counts. Worker-computed hashes cannot substitute for this comparison.

The independent source outcomes are Supported, Unsupported(code), Rejected(code)
and Unclassified. A successful classification requires the worker's status and
code to agree exactly. Supported source may not be downgraded. Disagreements,
unknown outside-subset grammar, internal/profile failures, response-capacity
failures and timeouts are failed or unverified compilation evidence; they are
not counted as unsupported coverage. The twelve fixed negative fixtures retain
their preregistered status/code pairs.

Source limits apply to UTF-8 bytes. The grammar cap is 16,384 bytes and takes
precedence over parsing. The launcher retains the 262,144-byte outer snapshot
cap so a bounded oversized contract fixture can receive an independently
verified `E_SOURCE_TOO_LARGE` response. Larger transport inputs fail preparation.
Strict UTF-8, no BOM, no raw CR and no NUL are checked before grammar. Other
literal, stage, step and aggregate bounds come from the unchanged contract.

For v2 canonical YAML, non-ASCII Unicode scalars and unsafe controls use YAML
Unicode escapes, with lowercase four- or eight-digit hexadecimal values.
Common controls, quote and backslash use standard short escapes. Actual YAML
has one backslash before `u` or `U`; the enclosing EDN string escapes it again.
Java iterates scalar code points, not UTF-16 code units. This preserves exact
payloads without broadening the legacy EDN parser. Stage normalization folds
ASCII letters only and preserves existing internal hyphens.

## Disabled artifact

The separate artifact uses schema `mcloving.jenkins.disabled-document`, version
1, and literal state `disabled`. Canonical fields are ordered as follows:

- `version`, `schema`, `definition_id`, `state`.
- `source`: `context_sha256`, `origin_kind`, `origin`, `sha256`.
- `compilation`: `compiler`, `contract_sha256`, `target_profile_sha256`,
  `pipeline_yaml_sha256`.

Every field is mandatory and independently bound to caller expectations or the
validated pipeline. No other field is admitted. This is a disabled logical
source definition, not an exported-job observation, and it is not the legacy
`mcloving.jenkins.jobstate-import` schema. Importing an actual Jenkins job still
requires its real inventory/state evidence. Existing historical imports remain
unchanged and disabled.

## Contained launch and evidence

`run-worker.sh compile-sequential SOURCE REQUEST_ID DOCUMENT_CONTEXT` snapshots
source and context once through bounded regular-file readers. Only the private
source snapshot is mounted read-only into the worker. Context travels in the
bounded request. Independent Rust validation must succeed before output is
released. Existing rootless containment, resource limits, deadline, output
sentinels and cleanup remain in force.

The v2 lane requires an explicit immutable image digest through
`MCLOVING_JENKINS_SEQUENTIAL_WORKER_IMAGE_SHA256`. It verifies the selected local
image and target profile, then launches by immutable ID. A separate local image
tag preserves the existing v1 image. Trusted contained-test receipts record the
selected image ID and actual admission executable digest outside the worker;
worker echoes are not evidence of implementation identity.

The fixture campaign covers 23 frozen records: ten authored supported inputs,
twelve authored negatives, and one historical C052 regression. Two identical
isolated compilations establish deterministic compiler output for those inputs.
They do not execute shell scripts or establish controller/agent compatibility.
The 228-source corpus requires a separate future classification receipt that
preserves historical source representations and all prior receipts.
