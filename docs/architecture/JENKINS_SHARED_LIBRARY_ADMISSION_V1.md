# Jenkins shared-library admission v1

Status: `MIG-005` verified implementation

## Boundary

McLoving does not fetch or execute Jenkins shared libraries. The admission
tool verifies an owner-approved strict-YAML ledger and optionally verifies
prefetched source trees. It has no SCM network authority, no SCM credential,
no controller credential, and no Groovy evaluation path. A verified source
tree remains unsupported for execution until a separate differential gate
earns that claim.

Only the standard Jenkins shared-library namespaces are admitted:
`vars`, `src`, and `resources`. Prefetched source is normalized into one
directory per resolution and sealed read-only. `.git`, build files, tests,
root-level scripts, and every other namespace are absent from the worker input.

## Exact oracle reconciliation

The v1 ledger is bound to:

- frozen inventory manifest
  `8cf682d06522b050c97c504c1a516f33463bd906e4ee10c3d6a1c38c03c6ec07`;
- job graph
  `76ae2e85d7d8a5a1410826b7b4556a36407bba726ac2baf6efe67062888b99ab`;
- runtime dependency inventory
  `238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4`;
- exact corpus manifest
  `a28283de801854836887e9bc6cffd43c10bb078dbeff343fdf92d19b470a74c2`.

The frozen scanner recorded 18 occurrences / 17 distinct reference strings.
Source reconciliation classifies two of those occurrences as comment-only
false positives and finds four additional live runtime calls. The resulting
denominator is 20 live observations plus two comment-only observations across
19 source files and 21 distinct reference strings.

Seven distinct public references, covering eight live observations, resolve
to exact commits. Every observation records source file, source byte digest,
line, syntax, load phase, sandbox and CPS dependency, plugin dependencies,
credential dependency, resolution, disposition, and reason. Unresolved and
source-verified observations are both unsupported; executable cases are zero.

## Fail-closed verification

The verifier rejects:

- schema extensions, duplicate keys, YAML aliases, anchors, tags, directives,
  or other non-strict YAML;
- substituted corpus bytes, lines, bindings, ledger bytes, or semantic model;
- duplicate observations or resolutions and inexact coverage denominators;
- floating or non-HTTPS resolution provenance;
- writable source roots, symlinks, hard links, special files, unexpected
  resolution IDs or namespaces, path traversal, non-UTF-8 paths, excessive
  files or bytes, and content-digest substitution;
- any policy that grants SCM network, SCM credential, Groovy evaluation, or
  controller execution authority; and
- any nonzero executable-case claim.

The repository bundle is
`migration/mario-jenkins-oracle-228/corpus-v1/shared-libraries-v1`.
The sealed source root is
`/sn8100/runs/mcloving/mig005-shared-libraries-20260801T103457Z/sources`.
It contains 518 files / 1,400,368 bytes. The ledger raw SHA-256 is
`3c9d79f73524d50ab62abb617d9863e0e897f1c6dd16c438e0f05d82f05cd4a5`;
its canonical semantic SHA-256 is
`e9ba69753ac9507f0d459edae012f9d537576e45ffa8806dead1a20b02db69c6`.
The authoritative README-locked external evidence is
`/sn8100/runs/mcloving/mig005-shared-libraries-20260801T104859Z-v2`. Its
self-excluding manifest covers 522 files and has SHA-256
`ec598cbc26a39d8f2d69ebd3d8298f89dc5728dd5b91c5f8ea7215b4fd57b9cf`.
The pre-README-lock predecessor remains immutable at manifest
`a6671f966e3738e25135b33fc397b5fb21666ac60edb931b49e3b35672f5123b`.

## Deliberate limits

This ticket does not implement Groovy, Jenkins CPS, sandbox approvals, plugin
steps, global-library configuration, credential mapping, controller-side SCM,
or shared-library execution. A future bounded evaluator requires fresh owner
approval and must remain isolated behind the compiler deny-authority boundary.
