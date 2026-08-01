# Jenkins native differential v1

This bundle certifies the complete **currently admitted** Jenkins compiler
surface: one exact declarative pipeline from the immutable 228-file Mario
corpus. It does not claim broad Jenkins compatibility.

The source was run in a fresh, disposable Jenkins 2.568.1 controller from the
exact pinned image, with the exact 90-plugin SHA-256 manifest and plugin files
predating execution, later independently reverified without mismatch, and the
oracle directory mounted from the pinned source path read-only. The container
had no network, a read-only root filesystem, the exact
dropped-capability set, synthetic local
initialization, and bounded CPU, memory, PIDs, file descriptors, and time. The
live Mario oracle was not mutated. The compiled strict-YAML pipeline was run
through the shipped McLoving controller and embedded Linux worker against a
fresh PostgreSQL database on an internal-only Podman network with no
production credential or effect authority. The non-root McLoving runner had a
read-only root filesystem, no effective capabilities, no-new-privileges, no
published ports, bounded resources, and a read-only source mount. The database
published no ports and retained only its five required startup capabilities.
Both disposable stacks were torn down after collection.

The independent `mcloving-jenkins-differential` verifier checks the manifest,
source, pipeline, image, and plugin-profile identities, the two raw receipts,
the exact Jenkins console transcript and containment (including mount sources,
tmpfs policy, dropped capabilities, memory/swap, and ulimits),
McLoving runner/database/network containment and integrity,
coverage/authority declarations, and the canonical trace. It compares stage
order, literal process arguments, terminal outcome, attempt ordinal, semantic
stdout, workspace entries, artifacts, tests, approvals, credential grants, and
external effects. Mutation tests reseal altered bundles and prove semantic,
containment, output, and coverage substitutions fail closed; exact-tree tests
also reject extra files and symlinks.

All other corpus cases and behavior families remain outside compiled
admission. They receive no McLoving work, credential, approval, or effect
authority from this evidence. Expanding compiler admission invalidates this
coverage denominator and requires a new differential version.

The first Jenkins attempt was safely discarded before execution because a
256 MiB `/tmp` caused Jenkins' disk monitor to take the built-in node offline.
The successful run used a bounded 2 GiB `/tmp`. McLoving's first isolated
launch was denied when the Rust shim attempted a network toolchain check, and
the next launch correctly exposed the invalid abstract `any` scheduler token.
The final run used the already pinned/prebuilt test binary and the concrete
Linux platform. Later containment-tightening attempts that failed before
execution are also excluded. No failed or superseded predecessor contributes
semantic evidence.
