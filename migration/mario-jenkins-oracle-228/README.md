# Mario Jenkins oracle inventory receipt — Wave 4A

This directory is the immutable, owner-designated `MIG-000` source inventory
for Wave 4B. It represents the rootless Podman controller
`jenkins-oracle-228` on Mario at the bounded offline epoch
`2026-07-31T06:44:17Z`.

## Source binding

- controller: `mario/jenkins-oracle-228`
- endpoint: `http://100.127.170.90:18080` over Tailscale
- Jenkins core: `2.568.1`
- image:
  `docker.io/jenkins/jenkins@sha256:f4f65e6cd1405cd889b7f5ac33f9d5cdc2a099de6b87fe8a3933b9c5d53d1d02`
- jobs: 230, consisting of 228 corpus jobs and two native-control jobs
- frozen build records: 231
- plugin files: 90
- snapshot generation:
  `2e350d0089c94379eb01124929ccc0f931c8e10f93860bef30be9d300572e556`
- exporter binary:
  `c5a3827ff7814a4b83cad816965440e7258b79c13861c2bf100b2666d12c66e9`
- trusted inventory fingerprint:
  `3473f1528e0fa8b1b856ae4941e5a5169d4c2c46389b813d0dd34935fb505198`

The controller had no running build or queued work before the service was
stopped. Its bind-mounted home, plugins, and corpus were copied while the
service was offline. The generated systemd unit was restored immediately and
HTTP health returned successfully.

## Sealed evidence

| File | SHA-256 |
|---|---|
| `SHA256SUMS` | `bddf7baf53cebcff7b3c6c9e6616640ae906749b8a7f4171734861b03dc11219` |
| `job-graph.yaml` | `e88bbbc9d7c620ab66814689441e03668dd89fa75eba0c1e82b1f35c0b362b51` |
| `identity-clients.yaml` | `09bf99b613a0597f6a27dfcaddc73dc9a203525da6b469ce34ae4e24838c328b` |
| `runtime-dependencies.yaml` | `d3f2e0d0841d20dde2d95f82798507f3f0e6ca809119c1fb0bb8e5f2905b5c2f` |
| `persistent-state.yaml` | `34ebc08ae3df05e011416945877bb2f3b2df07a046e41c524c98e326d41cda34` |
| `eligibility-ledger.yaml` | `72256db0ba06408cf4452baae7ccc284db18dd81e654ce2dbc40b0395818de5f` |

Independent HeMan verification reproduced:

```text
inventory-ok controller=mario/jenkins-oracle-228
epoch=mario-oracle-20260731T064417Z
jobs=230 dependencies=230 state-records=230
```

The digest-pinned gitleaks image scanned 1.49 MB and reported no leaks.

## Conservative eligibility

All 230 jobs are disabled parse-oracle jobs. Each complete inline Jenkinsfile
is bound as one opaque CPS runtime surface with `scripted` disposition. Every
job also has frozen build history whose forward and rollback transformations
remain `unsupported` until `MIG-005A`; consequently all 230 eligibility rows
are `unsupported`.

This is intentional fail-closed truth. The inventory grants no compiler,
scheduler, agent, credential, trigger, connector, effect, canary, or cutover
authority. Wave 4B may now measure and implement translation against the exact
corpus without converting inventory presence into an execution claim.
