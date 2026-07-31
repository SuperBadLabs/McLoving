# Mario Jenkins mapping catalog v1

This immutable bundle is the first corpus-earned Jenkins-to-McLoving mapping
catalog. It admits exactly one mapping: the literal `sh` step exercised by
`corpus-052-cinqict_jenkinsdev`. The mapping is pinned to Mario's exact Jenkins
plugin, compiler profile, inventory, source, and predecessor corpus manifest.

The catalog is descriptive and deny-authority. It does not grant scheduler,
agent-protocol, credential, connector, workload-execution, external-effect,
canary, or cutover authority. The mapped command may write only inside its
contained workspace. Network, host-filesystem, credential, undeclared-input,
floating-version, and fallback behavior is forbidden. Production external
effects remain connector-only under `EXT-001`.

`mcloving-jenkins-mapping-catalog` independently applies strict-YAML admission,
an exact schema, exact binding checks, and the detached byte and semantic
digests in `catalog.lock.yaml`. Unknown steps or plugins remain explicitly
unsupported. No certified-equivalence claim is made by this bundle.
