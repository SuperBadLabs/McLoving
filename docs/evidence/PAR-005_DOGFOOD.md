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
| Host prerequisites | rootless podman, sudo for the transport tmpfs and the AppArmor profile, `gh` logged in as the status writer, a Java runtime for the Jenkins compatibility contracts; the Rust toolchain, cargo-deny, actionlint and the Clojure CLI are pinned by `tools/versions.env` and fetched by the lanes themselves |
| Ingress | GitHub delivers to the controller's public hook route when the host has public ingress (Tailscale Funnel on the owner's host); until then `scripts/dogfood/bridge.sh` posts each new `main` head to the same route as a signed push delivery, so the receiver, filter, idempotency and admission path are the ones GitHub exercises |

The lanes not run here, and why: `rust-source-acquirer` and the boundary
suites need the user-namespace policy the acquirer's own tests exercise,
the `architecture` lane's retained-source verification walks the commit's
ancestry and the sealed acquirer publishes the tree without its history
(recorded as unmirrored in `verify-lanes.py`),
`ui-browser` needs the contained Chrome image, `deployment` and
`backup-restore` need a service user and a second host, and `formal` needs
the TLA+ tools; all are Foundation's alone. The verdict compared below is
Foundation's whole-run conclusion against the dogfood build's status.

## Verdicts

Recorded by `scripts/dogfood/verdicts.sh`, newest last. `Foundation` is
`gh run list --workflow Foundation --branch main` for the commit;
`McLoving` is `mcloving builds` for the dogfood pipeline's build of that
commit. The count of consecutive matches is the acceptance. A push the branch
moved past before its build ran fails its checkout as `revision_mismatch`
(the acquirer fetches the branch and requires it to still resolve to the
pushed commit); such a row is a mismatch, not a match, until `AGENT-013`
fetches the exact object.

| # | Commit | Build created (UTC) | Foundation | McLoving build | McLoving | Match |
|---|---|---|---|---|---|---|
