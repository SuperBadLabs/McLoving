# DIFF-003 external-boundary security review

Reviewed: 2026-08-15

## Accepted scope

DIFF-003 certifies the contained, zero-production-authority external-boundary
denominator. It does not certify a production endpoint, credential, mapping,
effect, deployment, client cutover, canary, rollback, or Jenkins decommission.
The real owner/operator client remains `jenkins_source`, and the Mario
inventories retain zero admitted production boundary mappings.

The accepted implementation is exact head
`01d548c510dc84b10576c0fd0c9a4524a18835e4`, tree
`d5ef1ce12f152a48ffc683537978f4549756693d`. HeMan sealed
`/sn8100/runs/mcloving/diff003-boundary-20260815T060147Z`; the independently
rechecked self-excluding evidence-manifest SHA-256 is
`cd8a43e08b7e2a3c3e1ed0a2cbc961818c27b3daa5e2eba0f23b1a140521dff7`.

## Evidence result

The exact ledger contains 15 passing suite entries:

1. PostgreSQL trigger, discovery, external-read-consumer, and external-admin
   contracts;
2. source-acquirer, secret-broker, input-adapter, provisioner, and ordinary plus
   exact-capacity dependency-resolver contracts;
3. cache, release-provenance, and independent boundary-verifier contracts;
4. physically separated no-network connector and observer contracts; and
5. the rootless isolated dependency authority-alias negative contract.

All 13 named boundaries exported the actual public receipt produced by the
focused positive implementation test. The independent runtime verifier checks
each boundary-specific contract, binds every one of the 48 certified scenarios
to an exact test that executed successfully, and applies explicit compatibility
rules to both validated live receipts in every join. A nonempty object, stale
receipt, substituted boundary receipt, or arbitrary pair of hashes cannot
satisfy the gate.

The retained comparison reports 13 validated live receipts, 12 validated live
joins, 48 executed adversarial scenarios, zero production mappings, zero
production effects, zero duplicate effects, zero production cutover claims, and
zero secret-marker disclosures. Runner, connector, and observer identities and
permissions remain distinct. Jenkins and target fixtures used different
internal-only networks; Jenkins was destroyed before the target network existed.

The main target runner is rootless, no-new-privileges, read-only for source and
Cargo registry, resource-bounded, and drops the default capability set. It restores
only rootless `SETUID`, `SETGID`, and `SETFCAP` so the source-acquirer can create
its single-identity inner user namespace. Focused and complete runs prove the
namespace deadline kills the whole transport PID namespace and credentialed
smart HTTP completes without disclosing its credential. The runner retains no
host-root mapping, `SYS_ADMIN`, mount, public-network, or production authority.
Connector and observer tests run later in distinct no-network containers with
distinct writable receipt and Cargo-target mounts; neither can access the
other's state. A separate rootless no-network container receives only
user-namespace `SYS_ADMIN` to execute the two bind-mount authority-alias
negatives. It has no host-root mapping, production mount, writable source, or
production authority.

## Failed-attempt disposition

Seven earlier attempts grant no closure authority:

- `20260815T041624Z`: PostgreSQL startup was incompatible with an all-capability
  drop and the harness stopped before target execution.
- `20260815T041817Z`: PostgreSQL became ready, but Podman `exec` could not serve
  as the engine-portable readiness probe.
- `20260815T041916Z`: the rootless runner denied the inner UID map; 17 of 19
  source integration cases passed and the two affected cases failed closed.
- `20260815T043555Z`: all 15 suites passed, but the host rejected sealing because
  the observer loopback feature was not enabled and `OBS-001.json` was absent.
- `20260815T045125Z`: the implementation receipt initially sealed, but exact-head
  review found that runtime receipts, joins, scenario outcomes, execution
  separation, encoded markers, and resolver aliases were not independently
  enforced. It is superseded and retained only as diagnostic history.
- `20260815T053113Z`: the hardened suites passed, but the host rejected sealing
  because the resolver source-manifest binding still named the pre-review tree.
- `20260815T054726Z`: the refreshed detached certificate passed its source check,
  but the separately compiled verifier retained the old resolver binding and
  failed closed before the isolated lanes.

The accepted attempt fixes each harness defect without borrowing evidence from
an earlier run. Its exact head reruns the complete denominator and produces the
complete receipt set before sealing.

## Residual risk

The certificate is a contained contract, not live production observation.
Compromise shared by a prerequisite implementation and its focused test can
still produce a coherent bad receipt; the independent verifier limits schema,
identity, authority, count, and digest substitution but is not an alternative
implementation of every product boundary. Live inventory reconciliation,
migration packaging, shadow replay, per-job canary, cutover, rollback, and
decommission remain mandatory later tickets.
