# MIG-003 first admitted compiler case

This directory records the first deterministic Jenkins-to-McLoving compiler
case. It is bound to Mario's exact `jenkins-oracle-228` population and admits
only `corpus-052-cinqict_jenkinsdev` at source SHA-256
`666ac2275ea75730e27cf7b565d757691b094c508355adc0199d745278a23100`.

Mario's immutable oracle proves Declarative model validation, CPS compilation
entry, and agent scheduling reach. It does not prove successful execution.
The source job and its imported operational-state record are disabled.

The worker image was rebuilt from the sealed 90-plugin profile as image ID
`8459b3b080d4239daffa2d5ba632c707dfbd18657b0176fb0e6340ff5dd45548`.
The profile SHA-256 remains
`feeeb44d32aa10181e572a0dbbf5b2e23895731b1913bd46aba9f38d56172271`;
the image ID is supporting local evidence, not a published release identity.

`worker-response.edn` is byte-for-byte deterministic across two isolated
rootless Podman runs. Rust independently reparses its canonical EDN envelope,
reparses and recompiles `pipeline.yaml`, validates McLoving canonical IR bytes,
reparses `jobstate.yaml`, and checks every source/profile/compiler/authority
binding before issuing `rust-admission.receipt`.

No file in this directory grants trigger, scheduler, agent, credential,
connector, workload, effect, canary, or cutover authority. Certified execution
equivalence remains false.
