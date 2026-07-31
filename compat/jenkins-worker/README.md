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
creating a writable home volume.

The protocol is one bounded EDN request and one canonical EDN response.
Protocol v1 supports `probe` and `compile`. Until MIG-003 admits a deterministic
Declarative subset, every valid source receives stable
`E_COMPILER_SUBSET_NOT_IMPLEMENTED` and `unsupported`; it never executes.

```sh
clojure -M:test
./build-image.sh /path/to/frozen/snapshot
./test-boundary.sh
./run-worker.sh probe example-probe
./run-worker.sh compile /path/to/Jenkinsfile example-compile
```
