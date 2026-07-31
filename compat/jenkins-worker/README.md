# Isolated Jenkins compiler worker

This directory owns the deny-authority JVM/Clojure boundary used to import
Jenkins configuration. It is not a pipeline runner. The worker cannot schedule
work, contact agents, access the controller store, receive credentials, or
produce effects.

The v1 target profile is byte-bound to Mario's owner-designated
`jenkins-oracle-228` snapshot:

- Jenkins image
  `sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`;
- Jenkins core 2.568.1 and its exact WAR/core JAR;
- Temurin Java `21.0.11+10-LTS`;
- Groovy 2.4.21 and its exact JAR;
- all 90 plugin files and their sealed manifest; and
- inventory fingerprint
  `b1c2f81c74ec0ffc36971f358f920b2d0775c6009f474bea924448cd2a1915c1`.

`build-image.sh` accepts only the frozen snapshot root, verifies every plugin,
constructs the image without network access, and labels it with the exact
profile digest. The runtime re-verifies the profile, Groovy/core JARs, and all
plugins before processing a request.

`run-worker.sh` is the only supported launcher. It uses rootless Podman with no
network, a read-only root filesystem and source mount, all capabilities
dropped, `no-new-privileges`, one CPU, 512 MiB memory, 64 PIDs, bounded file
descriptors, a 16 MiB no-exec tmpfs, a cleared and allowlisted environment, a
five-second deadline, and a 64 KiB single-response limit. Inherited image
volumes are ignored, preventing Jenkins' base-image declaration from silently
creating a writable home volume. No `compile` response is returned by the
launcher until the independent Rust validator has parsed and accepted its
exact status-specific envelope.

The protocol is one bounded EDN request and one canonical EDN response.
Protocol v1 supports `probe` and `compile`. MIG-003 admits exactly the
Mario-oracle case `corpus-052-cinqict_jenkinsdev`: `agent any`, one ordered
stage, and one literal `sh` step. Groovy is parsed only to its CONVERSION-phase
AST and is never evaluated. The output is deterministic strict YAML plus a
separate disabled job-state import record. Every other source receives a
stable fail-closed diagnostic and no authority.

Worker output is not trusted. `mcloving-jenkins-compiler-admission` reparses
the canonical EDN envelope and both strict-YAML documents, validates all
source/profile/compiler hashes and the all-false authority ledger, recompiles
Pipeline IR in Rust, validates its independent canonical bytes, and refuses
noncanonical or substituted output. Before launch, that same binary opens the
source once with no-follow/nonblocking semantics, validates and bounds it on
the opened handle, and creates the private snapshot used for hashing,
container compilation, and independent admission.

```sh
clojure -M:test
./build-image.sh /path/to/frozen/snapshot
./test-boundary.sh
./run-worker.sh probe example-probe
./run-worker.sh compile /path/to/Jenkinsfile example-compile \
  corpus-052-cinqict_jenkinsdev \
  e76362bbc8e899510b8498808ffd0d2f83bb64d3215cf2c5b31690895f251d97
```
