# DIFF-003 external-boundary security review

Reviewed: 2026-08-15

## Accepted scope

DIFF-003 certifies the contained, zero-production-authority external-boundary
denominator. It does not certify a production endpoint, credential, mapping,
effect, deployment, client cutover, canary, rollback, or Jenkins decommission.
The real owner/operator client remains `jenkins_source`, and the Mario
inventories retain zero admitted production boundary mappings.

The accepted unchanged HeMan run binds exact reviewed head
`296238dfb7aefaef1518a72c2398848f7b5fd2ec`, tree
`7020c99d334089e7c7862e87ce430790cce47491`, and independently rechecked
self-excluding 175-file evidence-manifest SHA-256
`40ff90e57bd29b16044706b8cd6686211527131a6459a0eea8cf85c024074fd5`.
The exact receipt-authentication public key's canonical DER SHA-256 is
`47bd4c993a30cf5a048b5590c09f0c00712649580902f9dfc1ecc9bf044cc23b`.
The retained HeMan path stays in the private owner-controlled execution record.
No repository change followed that accepted run before PR #59 squash-merged as
protected-main commit `6156e70fa2b869b2f2b3097e65a618e8e741936e`.

## Evidence result

The exact ledger contains 15 passing suite entries:

1. PostgreSQL trigger, discovery, external-read-consumer, and external-admin
   contracts;
2. source-acquirer, secret-broker, input-adapter, provisioner, and ordinary plus
   exact-capacity dependency-resolver contracts;
3. cache, release-provenance, and independent boundary-verifier contracts;
4. physically separated no-network connector and observer contracts; and
5. the rootless isolated dependency authority-alias negative contract.

All 13 named boundaries export the actual public receipt produced by the
focused positive implementation test. A fresh ceremony-only Ed25519 key signs
each exact receipt file after collection; the verifier retains the public key,
requires the exact 13 detached signatures, and rejects any changed, stale, or
fabricated file. The private key is destroyed before verification and sealing.
Each of the 48 certified scenarios requires one runtime outcome emitted from a
scenario-specific predicate over the owning test's actual observed error,
status, counter, digest, generation, or rollback state. Each create-new,
synchronized outcome retains a nonempty structured observation; test completion
alone cannot emit it. Every join then compares all
declared compatibility dimensions from both authenticated receipt files. A
nonempty object, plausible-looking signature text, test name alone, static
certificate outcome, or arbitrary pair of hashes cannot satisfy the gate.

The retained comparison reports 13 validated live receipts, 11 validated live
joins, 48 executed adversarial scenarios, zero production mappings, zero
production effects, zero duplicate effects, zero production cutover claims, and
zero secret-marker disclosures. Runner, connector, and observer identities and
permissions remain distinct. Jenkins and target fixtures used different
internal-only networks; Jenkins was destroyed before the target network existed.

The main target runner is rootless, no-new-privileges, read-only for source and
Cargo registry, resource-bounded, and has only three disjoint writable mounts:
public component receipts, scenario observations, and runner-only outputs. It
cannot preseed or modify the host-retained evidence root, authentication files,
logs, inspections, merged receipt set, verifier output, or manifest. It drops
the default capability set and restores
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

Before the self-excluding manifest is written, the host scans raw, Base64,
Base64URL, nested, hexadecimal, and percent marker forms; the hexadecimal and
percent checks are case-insensitive. It also rejects every retained filesystem
entry that is neither a regular file nor a directory, and every regular file
whose link count is not one. These checks prevent case-varied marker bypass,
special-file omission, and hard-link aliasing outside the sealed tree.

## Failed-attempt disposition

Eight earlier attempts grant no closure authority:

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
- `20260815T060147Z`: all hardened suites sealed, but final exact-head review
  found that receipt authentication, assertion-derived scenario outcomes,
  two-receipt join projections, and final reviewed-head binding remained
  incomplete. The receipt is superseded and diagnostic only.

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
