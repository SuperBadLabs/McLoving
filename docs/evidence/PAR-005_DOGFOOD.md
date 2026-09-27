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
