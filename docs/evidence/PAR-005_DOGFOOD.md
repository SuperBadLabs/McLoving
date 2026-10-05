# PAR-005 dogfood: McLoving runs its own Foundation

McLoving's own repository is the first pipeline McLoving runs for real: on
every push to `main`, the dogfood deployment on the owner's host checks the
pushed commit out through the sealed source acquirer, runs the Foundation
lanes that need no user namespaces or privileged containers, and writes the
outcome back to the commit as the `mcloving/foundation` status beside
GitHub's own Foundation run. The ticket closes when ten consecutive main
pushes have the same verdict from both; a mismatch resets the count.

## What runs

| Piece | Where |
|---|---|
| Pipeline | `.mcloving/pipeline.yaml`: one `foundation` stage, a checkout step and six lane steps, `notify` to the `github.mcloving` mapping |
| Lanes | `scripts/dogfood/{rust-lint,rust-tests,dependencies,secrets,architecture,controller-postgres}.sh`, each mirroring one Foundation job; `scripts/dogfood/verify-lanes.py` fails when a mirrored command no longer appears in both |
| Deployment | `scripts/dogfood/heman-up.sh <state-dir>`: PostgreSQL in podman, the controller with the source and notification catalogs and the GitHub token, a remote mTLS agent with the sealed source binding for this repository, the webhook trigger, and the pipeline rendered with the deployment's binding digest |
| Binding | `bins/agent/examples/render_source_binding.rs`: renders the acquirer configuration (runtime closure and all), credential, signing key, markers and bindings file from an intent, and prints the mapping digest the pipeline and catalog carry |
| Host prerequisites | rootless podman, sudo for the transport tmpfs and the AppArmor profile, `gh` logged in as the status writer, a Java runtime for the Jenkins compatibility contracts; the Rust toolchain, cargo-deny and actionlint are pinned by `tools/versions.env`, the Clojure CLI by `scripts/dogfood/versions.env` (checked against Foundation's `cli:` pin by `verify-lanes.py`), and the lanes fetch them themselves |
| Ingress | GitHub delivers to the controller's public hook route when the host has public ingress (Tailscale Funnel on the owner's host; `MCLOVING_DOGFOOD_PUBLIC_HOOK=1` with `MCLOVING_DOGFOOD_PUBLIC_BASE_URL` makes `heman-up.sh` register the repository webhook for the route and secret); until then `scripts/dogfood/bridge.sh` posts each new `main` head to the same route as a signed push delivery, so the receiver, filter, idempotency and admission path are the ones GitHub exercises |

The lanes not run here, and why: `rust-source-acquirer` and the boundary
suites need the user-namespace policy the acquirer's own tests exercise,
the `architecture` lane's retained-source verification walks the commit's
ancestry and the sealed acquirer publishes the tree without its history
(recorded as unmirrored in `verify-lanes.py`),
`ui-browser` needs the contained Chrome image, `deployment` and
`backup-restore` need a service user and a second host, and `formal` needs
the TLA+ tools; all are Foundation's alone. The verdict compared below is
Foundation's whole-run conclusion against the dogfood build's status.


## Notes (2026-09-27 redeploy on `0220759a` / #159)

After merging `fix(source-acquirer): bulk-prefetch blobs so AGENT-013 can pass on Luigi` (#159),
HeMan and Luigi dogfood were redeployed onto `0220759a6669444f15f0807b9b3c6ed9b34a753c`.

Sealed checkout of this repository at that tip (AGENT-013):

| Host | materialize wall (attempt start → receipt) | files | `source_unavailable` | build |
|---|---|---|---|---|
| HeMan | **13.0 s** | 2138 | false | `b8e6055b-0e34-452e-9183-6ff147c4c928` |
| Luigi | 64–72 s under load; quiet probe 2026-09-27 ~64.6 s (attempt start → rust-lint start on `4f65905`, build `a66da48a…`) | 2138 | false | `76343578…` / `a66da48a…` (checkout ok; lanes flaky — see notes) |

HeMan meets the <60 s acceptance. Luigi no longer fails closed with `source_unavailable`
(the pre-#159 failure mode / ~14 min drip); residual wall above 60 s on Luigi is noted for a
quieter follow-up probe, not a reopen of the promisor-drip bug. Row 1's ~14 min HeMan note
on `4a234c6f` is superseded for throughput by #159.

Consecutive match count after row 3: **3 / 10**.

## Notes (2026-09-27 match #4 on `e9b29a69` / #160 tip)

HeMan admitted main tip `e9b29a690a19` via signed bridge delivery after GitHub's
repository events API listed no `PushEvent` for the #160 squash-merge (only
`PullRequestEvent` / activity `pr_merge`). Delivery id
`branch-e9b29a690a19…` with push time `2026-09-27T18:42:00Z` (merge committer
date). Build `efceadff-e962-4ebe-be05-8faaf9d19e67` succeeded (all seven steps);
Foundation run `36341612189` success. HeMan dogfood binaries remain on
`0220759a` (#159 bulk-prefetch); tip is docs-only relative to that redeploy.

Consecutive match count after row 4: **4 / 10**.

## Notes (2026-09-27 match #5 on `99c42814` / #161 tip)

HeMan admitted PushEvent `22337221839` for main tip `99c42814756b` (#161
squash). Build `eb314375-49de-4b72-aaf3-4b7de3079b53` succeeded (all seven
steps); Foundation run `36360102505` success. Dogfood binaries remain on
`0220759a` (#159); tip is docs-only relative to that redeploy.

Consecutive match count after row 5: **5 / 10**.

## Notes (2026-09-28 match #6 on `83d2cb0b` / #162 tip)

HeMan admitted PushEvent `22341235473` for main tip `83d2cb0b1df0` (#162
squash). Build `35e0ed35-61a9-45ea-b705-f25e28bc2033` succeeded; Foundation
run `36364876716` success. Dogfood binaries remain on `0220759a` (#159).

Consecutive match count after row 6: **6 / 10**.

## Notes (2026-09-28 match #7 on `6824c8cb` / #163 tip)

HeMan admitted PushEvent `22345134247` for main tip `6824c8cb1ed0` (#163
squash). Build `6992c76b-7e18-4ad5-a0b4-82b0a2bb6ec0` succeeded; Foundation
run `36369627296` success. Dogfood binaries remain on `0220759a` (#159);
tip is docs-only relative to that redeploy.

Consecutive match count after row 7: **7 / 10**.

## Notes (2026-09-28 match #8 on `cf85367c` / #164 tip)

HeMan admitted main tip `cf85367ccea2` via signed bridge delivery after GitHub's
repository events API listed no new `PushEvent` for the #164 squash-merge
(watermark still `22347127820` / `e9b29a69`). Delivery id
`branch-cf85367ccea2…` with push time `2026-09-28T04:10:12Z` (merge committer
date). Build `a7f61824-2a76-4291-9f5a-5d17627f3498` succeeded; Foundation run
`36376562417` success. Dogfood binaries remain on `0220759a` (#159); tip is
docs-only relative to that redeploy.

Consecutive match count after row 8: **8 / 10**.

## Notes (2026-09-28 match #9 on `326e03fe` / #165 tip)

HeMan admitted PushEvent `22353341144` for main tip `326e03fe0024` (#165
squash). Build `69db9334-0f9e-4bb5-ac92-f3059ce40de6` succeeded; Foundation
run `36379650992` success. Dogfood binaries remain on `0220759a` (#159);
tip is docs-only relative to that redeploy.

Consecutive match count after row 9: **9 / 10**.

## Notes (2026-09-28 match #10 on `9a3468c6` / #166 tip)

HeMan admitted main tip `9a3468c687fa` via signed bridge delivery after GitHub's
repository events API listed no new `PushEvent` for the #166 squash-merge
(watermark still `22353341144` / `326e03fe`). Delivery id
`branch-9a3468c687fa…` with push time `2026-09-28T05:42:25Z` (merge committer
date). Build `ad6a8ae9-b40e-406b-bde7-6d5376fbd685` succeeded; Foundation run
`36383073183` success. Dogfood binaries remain on `0220759a` (#159); tip is
docs-only relative to that redeploy.

Consecutive match count after row 10: **10 / 10**.

### Luigi follow-up (2026-09-27 quiet probe; not a HeMan match row)

Luigi follow-up (2026-09-27 quiet probe): host load ~0.8–1.0, sealed checkout of
`4f65905` still ~64.6 s wall (attempt start → first lane log). Residual >60 s is
not load-only. rust-tests exit 101 on build `76343578…` was
`mcloving-input-adapter` `contained_boundary_is_typed_bounded_replay_safe_and_read_only`
panicking `ExpiredGrant`; a later build’s rust-tests passed and
`controller-postgres` failed in `remote_work::container_stage_runs_in_the_pinned_image_and_sees_only_the_workspace`.
Preserve Luigi-local `heman-up.sh` dirty patches (luigi-dogfood profile, gh token
fallback, PATH for bridge).


## Verdicts

Recorded by `scripts/dogfood/verdicts.sh`, newest last. `Foundation` is
the conclusion of the Foundation run GitHub started for the push (`gh run
list --workflow Foundation --branch main`: the one run of the commit
created within fifteen minutes after the push time the bridge recorded);
`McLoving` is `mcloving status` for the dogfood build the same push was
admitted as. The count of
consecutive matches is the acceptance. A push the branch moved past before
its build ran still checks out the pushed commit once `AGENT-013` fetches
that object by id (Foundation's behaviour); before that fix such a row failed
as `revision_mismatch` and counted as a mismatch.

| # | Commit | Build created (UTC) | Foundation run | Foundation | McLoving build | McLoving | Match |
|---|---|---|---|---|---|---|---|
| 1 | `4a234c6f7f1f` | 2026-09-26T09:07:51.317Z | 36218738244 | success | `b26d79f5-64f2-4625-8314-69189ecc3e37` | succeeded | yes |
| 2 | `0220759a6669` | 2026-09-27T05:52:49.348Z | 36298039770 | success | `b8e6055b-0e34-452e-9183-6ff147c4c928` | succeeded | yes |
| 3 | `4f65905a27b5` | 2026-09-27T17:27:04.724Z | 36336956714 | success | `cf3af674-d6a1-4fe3-96a0-5050497f5622` | succeeded | yes |
| 4 | `e9b29a690a19` | 2026-09-27T23:21:48.587Z | 36341612189 | success | `efceadff-e962-4ebe-be05-8faaf9d19e67` | succeeded | yes |
| 5 | `99c42814756b` | 2026-09-27T23:51:55.588Z | 36360102505 | success | `eb314375-49de-4b72-aaf3-4b7de3079b53` | succeeded | yes |
| 6 | `83d2cb0b1df0` | 2026-09-28T01:09:14.701Z | 36364876716 | success | `35e0ed35-61a9-45ea-b705-f25e28bc2033` | succeeded | yes |
| 7 | `6824c8cb1ed0` | 2026-09-28T02:23:25.870Z | 36369627296 | success | `6992c76b-7e18-4ad5-a0b4-82b0a2bb6ec0` | succeeded | yes |
| 8 | `cf85367ccea2` | 2026-09-28T04:11:19.605Z | 36376562417 | success | `a7f61824-2a76-4291-9f5a-5d17627f3498` | succeeded | yes |
| 9 | `326e03fe0024` | 2026-09-28T04:54:39.659Z | 36379650992 | success | `69db9334-0f9e-4bb5-ac92-f3059ce40de6` | succeeded | yes |
| 10 | `9a3468c687fa` | 2026-09-28T05:43:00.400Z | 36383073183 | success | `ad6a8ae9-b40e-406b-bde7-6d5376fbd685` | succeeded | yes |

## Timestamp erratum and independent readback (2026-10-05)

The original verdict table above is preserved. Independent hosted readbacks
confirm all ten Foundation runs succeeded on their recorded full main SHAs,
and each commit's successful `mcloving/foundation` status targets its recorded
build UUID. An isolated copy of the stopped original dogfood PostgreSQL volume
was queried with network disabled and read-only transactions; all ten stored
builds are `succeeded`.

The recorder's unpadded millisecond remainder caused two creation timestamps
to be written incorrectly. The API-equivalent timestamp is
`(EXTRACT(EPOCH FROM created_at) * 1000)::bigint`, matching the controller
store's rounded integer conversion, rather than truncating database precision.

| Row | Build | Original recorded creation time (UTC) | Correct API creation time (UTC) |
|---|---|---|---|
| 7 | `6992c76b-7e18-4ad5-a0b4-82b0a2bb6ec0` | 2026-09-28T02:23:25.870Z | 2026-09-28T02:23:25.087Z |
| 10 | `ad6a8ae9-b40e-406b-bde7-6d5376fbd685` | 2026-09-28T05:43:00.400Z | 2026-09-28T05:43:00.040Z |

All original table timestamps are reproduced by the old recorder. These two
corrections preserve build order, the ten-push denominator and all verdicts;
they do not constitute fresh pipeline executions. Selected nonsecret raw
readback fields and provenance are in
[`PAR-005_VERDICT_READBACK.json`](PAR-005_VERDICT_READBACK.json). The pending
recorder correction preserves three fractional digits, and its full-path
regression covers both observed remainders and refusal of genuinely older
builds. PAR-005 remains ACTIVE pending its review, merge and verification gates.
