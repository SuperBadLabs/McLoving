# PAR-001 closure receipt: GitHub webhook receiver

Ticket: `PAR-001`. Merged as PR #148, squash commit
`327a032a4da65e92ca313387fb966725811a7f7e` on 2026-09-11.

## What merged

- Public route `POST /api/v1/webhooks/github/{org}/{project}/{pipeline}/{trigger}`:
  no bearer; `X-GitHub-Delivery`, `X-GitHub-Event` and `X-Hub-Signature-256`
  required; the trigger must be an `scm_webhook` trigger naming provider
  `github`; the signature over the raw body is verified in constant time
  under a per-trigger secret derived by HMAC-SHA256 from the controller's
  `MCLOVING_WEBHOOK_KEY_FILE` (owner-private, 32..4096 bytes, opened
  `O_NOFOLLOW`, `secret nofollow` in the deployment contract) and the
  trigger's identity and `source_generation`, never stored, before any byte
  of the body is interpreted. Body bounded at GitHub's 25 MiB maximum; eight
  deliveries in flight, the permit taken before the body is buffered and
  released at a 30-second deadline (503 `webhook_busy` with `Retry-After`,
  408 `webhook_timeout`). Authorized `GET .../triggers/{id}/webhook`
  answers the hook path and secret, `no-store`.
- Mapping: branch push to the closed SCM payload (`repository.full_name`,
  `after`, branch, changed paths bounded at 128 and omitted for an oversized
  or truncated commit list); `pull_request` opened/synchronize/reopened to
  head sha and ref; tags, deletions, `ping` and other events acknowledged
  202 `ignored`, filter misses 202 `filtered`. `revision` and `branch`
  reach a pipeline only as parameters it declares.
- Ledger: admission through `admit_trigger_event` with the trigger's own
  event-source identity, receipt-timed (`DeliveryTiming::Receipt`): the event
  time is the database clock inside the serialized acceptance; the canonical
  payload is `{event_kind, payload, body_sha256}`; a redelivery is matched
  on the authenticated delivery alone, ahead of the trigger's current filter
  and pause state, and replays under its recorded caller identity. Unadmitted
  deliveries are `webhook_receipts` rows (migration 0038; event header, body
  digest, status, reason, caller, trigger generation revalidated under the
  lock); acceptance and redrive on every path refuse an id a receipt holds
  and receipts refuse an id the ledger holds, across both delivery and event
  identifier namespaces, so a delivery id's first authenticated decision is
  durable. The trigger transfer snapshot is schema 2 and carries the
  receipts in its digests.
- OpenAPI: `receiveGithubDelivery` with headers, `GithubDelivery` body and
  200/201/202 (oneOf)/408/422/503 answers; `readGithubWebhook` typed.

## Review

Twenty-six findings across eleven Codex rounds (5,1,2,2,5,2,2,2,2,2,1), all
fixed in the pull request; none deferred. The fifth round's five findings
were answered by one design, the durable indexed receipt table, rather than
by five patches.

## Verification

| Check | Result |
|---|---|
| `cargo clippy --locked --workspace --all-targets -- -D warnings` | clean |
| `cargo test -p mcloving-controller-api` (PostgreSQL) | 52 lib incl. 7 webhook unit tests; route_denials 8 (matrix 37); `tests/scm_webhook.rs` 1 covering admission, replay, generation revision, pause and narrowed filter, repeated ping, reused ids under other headers and bodies, identity rotation, filtered/ignored acknowledgements, pull request |
| `cargo test -p mcloving-controller-store` (fresh PostgreSQL) | all suites green incl. handoff receipts, event-id collision, superseded generation, redrive onto a receipt |
| `deploy/test-deployment.sh` (local) | passed |
| Proof (HeMan): `curl` against the running controller binary | 201 admit, 200 replay with the same build id, 409 altered body, 401 forged signature, one succeeded build whose stdout is the pushed commit hash |
| PR head Foundation and Windows | success |
| Exact-main Foundation | run 34612940947, success |
| Exact-main Windows Agent | run 34612940719, success |

## Threat model

Boundaries reviewed: TM-002, TM-011, TM-039 and TM-052; the closure section
in `docs/threat-model/README.md` records the review and its residuals (the
operator carries the secret to GitHub; GitHub's delivery id is trusted as
the idempotency key; an event filtered under a narrower filter is not
re-decided on redelivery). No production authority is granted.
