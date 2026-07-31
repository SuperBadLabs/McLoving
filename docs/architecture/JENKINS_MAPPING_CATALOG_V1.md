# Jenkins mapping catalog v1

MIG-004 introduces a versioned, independently admitted mapping catalog between
the deny-authority Jenkins compiler and any future execution certification.
The catalog is not code and grants no authority. It converts an exact,
provenance-bound source construct into a typed target description only.

## First earned mapping

Mario's immutable 228-file corpus earns one mapping:

- Jenkins symbol: literal `sh`;
- plugin: `workflow-durable-task-step` `1479.v56e587f413a_7`;
- plugin SHA-256:
  `a0f0f1464ce3592f76d0f0079ce9fc2d4272594f995bf3d1a7ede4cd5031452e`;
- source: `corpus-052-cinqict_jenkinsdev`, SHA-256
  `666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100`;
- target: `/bin/sh -xe -c <literal>` in the contained workspace;
- platform: `any`;
- trust pool: `migration-deny-authority`.

The command may write its contained workspace. Network, credentials, host
filesystem access, and direct production effects are forbidden. Production
effects remain available only through a separately certified `EXT-001`
connector. The mapping has no scheduler, agent-protocol, workload-execution,
credential, connector, or effect authority.

## Admission and locking

`mcloving-jenkins-mapping-catalog` first applies the shared bounded strict-YAML
parser, then a deny-unknown-fields typed schema, then exact binding and policy
checks. The detached lock binds both the exact catalog bytes and a semantic
digest to the compiler profile and predecessor corpus manifest. The bundle
reader requires exactly three regular files and refuses symbolic links,
unexpected files, floating versions, unknown fields, silent fallback,
undeclared host reads, authority substitution, profile/plugin/corpus
substitution, and unearned local-input, shared-resource, or cache semantics.

The v1 catalog byte SHA-256 is
`b53d6a30c7dcbb799e4c6c939e4e267d7935ddb21916878a4c966395c73f3b62`;
its semantic SHA-256 is
`2cda142fab4786e02c854488ab5fcadaf822706e961b7754bff6aa314d96be64`.
It reports one mapping earned by one compiler-admitted case across 228 corpus
sources and zero certified-equivalence cases.
