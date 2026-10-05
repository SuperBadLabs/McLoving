# PAR-005 candidate review record — ticket ACTIVE

This candidate is not an earned closure receipt. PAR-005 remains ACTIVE.
No protected merge, post-merge verification, or full implementation approval
is asserted by this document.

## Correction and verification scope

The evidence recorder formerly constructed a GNU date epoch fraction from
an unpadded integer millisecond remainder. Controller creation time ending
005 ms became `.500`; 074 ms became `.740`. Besides recording incorrect
times, this could refuse a later 100 ms build as earlier than the previously
recorded distorted 740 ms build. The candidate formats exactly three digits
before converting the epoch to the evidence table's UTC timestamp.

`python3 scripts/test-dogfood-verdicts.py` exercises the complete shipped
`scripts/dogfood/verdicts.sh` in an isolated directory with fake read-only
GitHub/controller programs. It verifies exact timestamps and full matching
rows for seven distinct pushes at 000, 005, 040, 074, 087, 100 and 999 ms in one second,
then verifies a truly older build is refused without modifying the table.
The preceding isolated reproduction established that the uncorrected
recorder distorts 005/074 and wrongly refuses the subsequent 100 ms row.
The fixture neither contacts GitHub nor changes any live deployment.
Foundation's existing architecture job and its dogfood architecture mirror
both invoke this regression. The lane verifier must continue to recognize
their matching command. The workflow/oracle change still requires independent
review and hosted exact-head checks; baseline green runs do not verify it.

Implementation child `/root/milestone_m1/par005` produced the correction.
Independent milestone reviewer `/root/milestone_m1` read the baseline
pipeline, deployment, bridge, recorder, tool pins and lane verifier, inspected
the narrow patch and candidate workflow/test diff, and reran both the isolated
reproduction and shipped-source candidate regression. Root coordinator `/root`
separately reran the initial reproduction. These observations do not establish
independent exact-head approval of the full PAR-005 implementation,
source-acquirer changes, or a final committed candidate head. These observations
record the uncommitted tree as it was reviewed. Review of a subsequently
committed head is recorded separately.

## Credential correction candidate

The subsequent full-scope audit identified credential-bearing process
arguments: the bridge key in `openssl -hmac`, replayable HMAC headers and API
bearer headers passed to `curl`, public-hook secrets passed through
`jq --argjson`, and API/artifact tokens passed to the controller's `env`
launcher. These are TM-013/TM-039 findings rather than changes to the ten-push
denominator. The candidate reads the key inside a Python signer; transmits
credentials through atomically created mode-0600 request files under the
private state directory; and loads controller tokens from its existing private
identities file through shell builtins in the cleared launcher environment.
That shell refuses missing/empty token input before executing the controller.

`/root/milestone_m1` authored the initial signer, bridge and deployment
prototypes. `/root/milestone_m1/par005` authored the persistent full-script
tests, signature-header protection, controller handoff, explicit handled-signal
cleanup and fail-closed improvements. Consequently the milestone coordinator
cannot serve as an independent reviewer of all authored implementation here.
Root must independently inspect the complete committed code/oracle/workflow
candidate. This draft records authorship and evidence without asserting that
the required final independent review has already occurred.

`python3 scripts/test-dogfood-credentials.py` runs the actual scripts with
public toy credentials, real Python/jq operations and isolated dependency
spies. It checks RFC 4231 vectors, exact bridge payload/signature bytes,
absence of keys/tokens/replayable signatures from command and local `/proc`
arguments, header file contents and mode, credential file cleanup, POST/PATCH
payload equivalence, trigger generation reconciliation, missing/empty handoff
refusal, the controller's correct token environment and rejection of inherited
parent secrets. Transport/signer failures and actual SIGINT/SIGTERM during
blocked synthetic requests must leave no tracked request files or bridge
watermark. Both Foundation architecture and its dogfood mirror run this test.
The uncorrected complete bridge/deployment scripts fail the corresponding
credential-concealment tests, providing a negative control of the oracle.

The milestone coordinator separately observed a native foreign-UID probe:
the actual signer waited on a private synthetic FIFO, a different UID could
read its command line without seeing the toy key, and could not read the
owner-private hook file. This is a bounded host observation with synthetic
data, not evidence of general workload isolation. SIGKILL cannot run cleanup;
same-UID process environments/files remain the SEC-005 residual. No real
webhook, deployment, controller or production effect was invoked by the tests.

## Evidence already present and its limits

`PAR-005_DOGFOOD.md` retains ten matching verdict rows ending at main
`9a3468c687fa661654d1241e823da1f2bfb82fb0`. Local first-parent ancestry
confirms those ten recorded commits are consecutive. The deployment notes
retain binaries at `0220759a6669444f15f0807b9b3c6ed9b34a753c` during later
checked-out pushes. Independent milestone coordinator GitHub readbacks on
2026-10-05 confirm all ten run head SHAs and success conclusions, and each
commit has a successful `mcloving/foundation` status targeting the recorded
build UUID. Root independently recovered ten succeeded builds from an isolated
filesystem copy of the stopped original PostgreSQL volume, with no network
and read-only transactions. The API-equivalent rounded epoch-millisecond
conversion confirms two timestamp errors: row 7 `.870` must be `.087` and
row 10 `.400` must be `.040`. Every original timestamp is reproduced by the
uncorrected recorder; every build verdict remains matching. The historical
table bytes are retained with a dated erratum. Selected nonsecret readback
fields and provenance are retained in `PAR-005_VERDICT_READBACK.json`.
Root's further readback reconciles each requested checkout commit, the
`foundation` node, its succeeded attempt and committed log chunks with the
same build. The ten commits form a consecutive first-parent main sequence,
with one Foundation push run per SHA; the published statuses and stored
execution truth agree. The retained JSON includes these execution bindings.
Contemporaneous binary/configuration attestations were not retained; the
accepted owner-user debug deployment and signed-bridge scope remain explicit.

The root coordinator observed successful Foundation run `36652376712`,
attempt 2, and Windows Agent `36652376373`, both for baseline main
`8f2b625b7623aae7734576b85fa15424b86a7170`. These are baseline custody
checks and cannot prove this candidate's exact-head or post-merge gates.
The original canceled browser job is retained in hosted run history.

## Threat boundaries and residuals

The narrow correction touches TM-052, verification integrity and evidence
ordering. The full ticket additionally requires review of TM-013 (tokens,
keys, owner-private deployment files and environment), TM-003 (agent/source
execution and transport bounds), and TM-039 (signed trigger ingress,
idempotency, distinct push identities, pairing and gap handling), as described
in `docs/threat-model/README.md`.

The accepted signed-bridge limitation, owner-user debug deployment, omitted
privileged/browser/deployment/formal lanes, and comparison to Foundation's
whole-run verdict remain explicit. Public-webhook lifecycle and bidirectional
lane comparison belong to DOGFOOD-001; hostile workload isolation belongs
to SEC-005. This change grants no production or credential authority.

## Hosted runner dependency correction

Foundation pull-request run `37348516184` at candidate
`bc37f32557b279bfcb1ba046e308440c4f987153` failed Architecture records
job `111893150176`: the actual verdict regression could not find `rg` on
the runner. The failure is retained. Root added an architecture-only
provisioning step for `jq` and `ripgrep`; the existing lane classifier is
unchanged and both new regression commands remain required. The workflow
aggregate oracle now requires the additional step and its exact body.
Milestone M2 independently reviews this root-authored workflow/oracle
correction. Fresh checks must describe its subsequent committed head.

## Gates still required before closure

- Complete independent exact-head review across PAR-005's affected boundaries
  and resolve every actionable finding, including the final evidence oracle.
- Obtain the required app-bound candidate checks and fresh protection readback,
  then record the actual protected merge SHA.
- Verify successful Foundation and native Windows for that exact resulting
  main commit; baseline runs above are not substitutes.
- Replace this candidate record with factual earned review/merge/run receipts
  and only then perform the subsequent board closure update.
