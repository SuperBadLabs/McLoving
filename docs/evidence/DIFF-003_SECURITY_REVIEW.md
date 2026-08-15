# DIFF-003 external-boundary security review

Reviewed: 2026-08-15

## Accepted scope

DIFF-003 certifies the contained, zero-production-authority external-boundary
denominator. It does not certify a production endpoint, credential, mapping,
effect, deployment, client cutover, canary, rollback, or Jenkins decommission.
The real owner/operator client remains `jenkins_source`, and the Mario
inventories retain zero admitted production boundary mappings.

The accepted implementation is exact head
`061fb8d324f7cd4cc29a41d2672363776ffacab6`, tree
`e23c3bf02fb71ab7e18d5d37aca5c5910a9f6155`. HeMan sealed
`/sn8100/runs/mcloving/diff003-boundary-20260815T045125Z`; the independently
rechecked self-excluding evidence-manifest SHA-256 is
`9a403938462b163b4693940b81cddc2c2c36c4a6a7267ccdea431e389eece009`.

## Evidence result

The exact ledger contains 15 passing suite entries:

1. PostgreSQL trigger, discovery, external-read-consumer, and external-admin
   contracts;
2. source-acquirer, secret-broker, input-adapter, provisioner,
   external-connector, and destination-observer contracts;
3. ordinary and exact-capacity contained dependency-resolver contracts;
4. cache, release-provenance, and independent boundary-verifier contracts; and
5. the target public-network denial.

All 13 named boundaries exported the actual public receipt produced by the
focused positive implementation test. The host hashes those receipts and
derives all 12 live join identities from the observed source and target receipt
digests plus the certified contract input. A static certificate without those
outputs cannot satisfy the gate.

The retained comparison reports 13 live receipts, 12 live joins, 48 certified
adversarial scenarios, zero production mappings, zero production effects, zero
duplicate effects, zero production cutover claims, and zero secret-marker
disclosures. Runner, connector, and observer identities and permissions remain
distinct. Jenkins and target fixtures used different internal-only networks;
Jenkins was destroyed before the target network existed.

The target runner is rootless, no-new-privileges, read-only for source and Cargo
registry, resource-bounded, and drops the default capability set. It restores
only rootless `SETUID`, `SETGID`, and `SETFCAP` so the source-acquirer can create
its single-identity inner user namespace. Focused and complete runs prove the
namespace deadline kills the whole transport PID namespace and credentialed
smart HTTP completes without disclosing its credential. The runner retains no
host-root mapping, `SYS_ADMIN`, mount, public-network, or production authority.

## Failed-attempt disposition

Four diagnostic attempts remain unsealed and grant no authority:

- `20260815T041624Z`: PostgreSQL startup was incompatible with an all-capability
  drop and the harness stopped before target execution.
- `20260815T041817Z`: PostgreSQL became ready, but Podman `exec` could not serve
  as the engine-portable readiness probe.
- `20260815T041916Z`: the rootless runner denied the inner UID map; 17 of 19
  source integration cases passed and the two affected cases failed closed.
- `20260815T043555Z`: all 15 suites passed, but the host rejected sealing because
  the observer loopback feature was not enabled and `OBS-001.json` was absent.

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
