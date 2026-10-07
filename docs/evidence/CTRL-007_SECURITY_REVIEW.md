# CTRL-007 commit status reconciliation and configured NAT64: candidate evidence

This records the implementation author's source and local native observations for
`/root/milestone_m2/ctrl007`. CTRL-007 remains ACTIVE pending the coordinator's
independent disposition, protected merge, and post-merge Foundation/native
Windows verification. This receipt grants no production or deployment authority.
The allocated qualified base was
`4fa136de9515cf0ac6c423bfc9bd19d0ebc5c45a`; the candidate is identified below by
file bytes, not an invented commit. No Git or publication operation was performed
by this ticket agent. The original board is owned by the coordinator.

## Complete acceptance coverage

The original acceptance requires durable ordering already present in PAR-004:
mark an attempt in flight before sending, delay a later outcome for the same
status past the earlier local deadline, and re-post after stale settlement.
It explicitly observes that a target may apply a received body after this quiet
interval. CTRL-007 therefore requires a delivered GitHub row to read its
repository/commit/context after the interval, post the recorded outcome once
when it differs, bound attempts, and claim reconciliation exclusively across
controllers. It additionally requires configured RFC6052 network-specific
NAT64 prefixes to let the embedded IPv4 policy decide, with a genuinely late
older-write integration proof and a private-address decoding unit proof.

| Original clause | Candidate seam and local evidence |
| --- | --- |
| Preserve mark-before-send, quiet interval, newer-holder and stale-settlement ordering | Store `mark_notification_reconciliation_in_flight` takes the existing status-key advisory lock; terminal recording in `src/dag.rs` observes in-flight work; superseded claims do no target I/O. The existing notification integration plus `reconciliation_preserves_status_key_ordering_and_superseded_claims_send_nothing` executed. |
| Reconcile delivered GitHub repository/commit/exact context after quiet interval | Migration 0045 backfills existing delivered GitHub rows at delivered time plus 35 seconds without changing delivery truth. `current_github_status` reads the latest exact context; `reconcile` compares state, description and target URL and sends at most one correction per observation. Pagination, mismatches, matches, unrelated Unicode contexts and realistic complete records executed. |
| Durable bounded attempts | Twelve separate observation attempts per terminal generation are charged in the database before I/O. Successful matching/correction never resets them; final exhausted claims are reaped without more I/O. Budget, no-reset and crashed-final-claim tests executed. |
| Two controllers do not hold one live reconciliation claim | Due selection uses `FOR UPDATE SKIP LOCKED`, a 90-second lease and fresh UUID. Mark and settlement require generation, charged attempt, UUID and live lease. Actual concurrent claims, expiry/reclaim, stale token, stale generation and late expired settlement tests executed. |
| Timed-out older body applied after newer post and quiet interval | The integration sink retains the older received body in an independently alive target task after client timeout. It applies that body after the newer success and real quiet wait, then two production worker scans produce one exact-context GET/correction and restore the newer status. The test ran in the final ten-test target. |
| Configured RFC6052 prefix uses embedded IPv4, refusing private destination | `parse_notification_nat64_prefixes`, prefix decoding and `address_refusal` cover /32,/40,/48,/56,/64,/96. Units exercise private and public IPv4 controls, invalid reserved-u/suffix encodings and malformed configuration. Integration refuses configured synthesized private addresses before connecting. |
| Shipped configuration/deployment boundary | Startup validates `MCLOVING_NOTIFICATION_NAT64_PREFIXES` before configuration/database work and installs the frozen policy into ApiState. Actual binary tests refuse present-empty and illegal nonempty /72. The installed environment guard exercises unset, all six valid widths, nine malformed values and ambient/matching/dropped/changed contract values. |

Production seams: `crates/controller-api/src/notifications.rs` (parser,
address admission, pinned GET, exact-context selection, reconciliation and
public worker); `crates/controller-store/src/lib.rs` (claim, mark, settle);
`crates/controller-store/src/dag.rs` (terminal-generation transitions);
`crates/domain/src/notifications.rs` (separate budget/claim model);
`bins/controller/src/main.rs` (early startup loader); deployment guard/library
and template. Migration 0045 was reserved after checking highest existing
migration 0044 and no filename collision. Its upgrade test executes the real
migration against previously delivered GitHub and webhook rows and preserves
accepted-delivery truth.

## Network and response boundary

GET and corrective POST use the existing credential-scoped resolved target and
startup-frozen catalog. Repository/commit/own context admission remains strict;
no target supplies a new authority or a pagination URL. Each request resolves
and checks every address, pins the accepted answers while retaining TLS/Host
identity, disables redirects/proxies/automatic retries, and keeps the existing
system-root TLS policy. Missing credentials and configured synthesized private
addresses are refused before connection. A webhook gains no reconciliation.

GET requests the commit-status list with `per_page=100`, at most ten generated
pages, at most 512 KiB per complete JSON page and 2 MiB over the whole search.
The combined mark/read/correction has a 30-second deadline; connection and
request timeouts remain five and twenty seconds. Every list record must have
typed JSON fields and a known state; unrelated context labels may contain
Unicode. The first exact context in GitHub's reverse chronological response is
selected; its state, description and target URL must match. A short page without
that context is affirmative absence and permits one post. Redirect, malformed,
oversized, torn, over-100-record or exhausted full-page searches are inconclusive
failures and cause no corrective POST. Unknown creator/avatar/URL/id/timestamp
metadata is ignored but charged to the byte budgets. Realistic complete matching
and mismatching 100-record pages, and aggregate byte exhaustion, executed.
POST answers retain their separate 64 KiB limit. These are finite admitted bounds,
not a promise that arbitrary GitHub responses fit them.

A configured NAT64 policy accepts one to 32 comma-separated canonical global
IPv6 networks, at most 4096 characters, with exact RFC6052 legal widths, no
whitespace, host bits, duplicates or overlaps, and no existing special-purpose
or 6to4 range. Unset means no network-specific prefixes; present-empty is a
configuration error. Extraction skips the reserved u octet for widths through
/64 and uses the final four octets for /96. A matching prefix with nonzero u or
unused suffix is refused rather than treated as ordinary global IPv6. The
embedded IPv4 decides through the existing private/reserved policy, including
synthesized loopback even with the debug direct-loopback test seam. Existing
well-known NAT64, mapped IPv4, local-use NAT64 and 6to4 guards remain.

## Meaningful RED and retained unearned attempts

`/tmp/mcloving-milestones/M2/CTRL-007/red-custody.json` binds saved original
production hashes, root-qualified point-in-time 4fa comparisons, exact commands,
selected environment, exits and raw log hashes. Saved copies are historical
source custody; they are not the currently authored source.

- `red-reconciliation-target-owned.log`: exit 101 after 92.10 seconds using the
  existing public worker API against original production. The older body really
  applied after newer success; two scans returned zero reconciliations where
  one was required. This is a semantic failure, not a missing new-method error.
- `red-nat64-nonempty-startup.log`: exit 101 with original relevant production
  restored for the invocation. The actual shipped binary ignored illegal
  nonempty `2606:4700::/72` and reached the database migration connection instead
  of named configuration refusal. Present-empty RED is also retained, with the
  nonempty case establishing the requirement independently of optional-env
  interpretation.
- Independent coordinator review identified foreign-context grammar poisoning
  and the reused POST byte limit. `red-unrelated-unicode-context.log` and
  `red-complete-github-status-page.log` each exit 101 at the specific runtime
  assertion. Narrow Unicode admission and separate bounded GET budgets correct
  those failures while retaining own-target and response guards.

Earlier `red-reconciliation.log` was an unearned fixture assertion expecting an
uppercase repository although the catalog resolves lowercase. Earlier
`red-reconciliation-corrected.log` was an unearned model: its HTTP handler died
on disconnect before the old body could apply. Both raw logs remain; the sink
was corrected to retain target-owned work. Initial deployment attempts in
`green-deployment-nat64.log`, `green-deployment-nat64-unsandboxed.log` and
`green-deployment-nat64-unsandboxed-corrected.log` failed fixture prerequisites
(sandbox virtual ownership, template password placeholder, and inherited
nonprivate umask). Only the private fixture was fixed; guards were not weakened.
The initial Clippy failure detected held test mutex guards/default-field
reassignment and is retained. No such failed attempt earns a passing receipt.

## Final native verification and mutation checks

The final sequential campaign completed 2026-10-07 UTC against the frozen source
inventory below. `final-verification.json` records actual argv, start time, exit
and SHA-256 for each raw log. All nine checks exited zero: format, six notification
units, one loader unit, one actual shipped-startup test, one existing store
notification test, verified ten notification integration tests, warning-denied
Clippy across API/store/controller all targets, installed deployment guard, and
shell syntax. The full integration target ran ten tests with zero ignored or
filtered, in 93.54 seconds, with the verifier's
`rust-test-execution-ok label=notifications tests=10` marker. New PostgreSQL
cases are explicitly ignored only in ordinary database-less test runs; both the
native local script and Foundation gate invoke `--include-ignored` and require
the exact ten-test execution count. Local evidence does not assert new remote
Foundation or Windows runs.

Six specific source mutations each exited 101 at an executed semantic test:
omit corrective POST, ignore exact context, bypass configured NAT64, reset the
durable observation budget, ignore the live claim lease, and ignore settlement
UUID. `mutations/results.json` binds each command, raw log, mutated/original/
restored hashes and byte-identical restoration. Full final verification followed
restoration. The coordinator reported independently reading all 17 changed files,
the complete new tests and six raw mutation logs; that reported review is not
represented here as final approval or earned closure.

Native execution used the existing shared Cargo target and sccache server:
`CARGO_TARGET_DIR=/sn8100/work/forge/McLoving/target`,
`RUSTC_WRAPPER=/home/srikanth/.local/bin/sccache`,
`SCCACHE_SERVER_UDS=/run/user/1000/sccache.sock`. It used only ticket-owned
PostgreSQL 17.6 container
`db48181ac9fe3567d51b184785f0cfdc43064a049196fb72d1a914f2066f06ab`, pinned image
`docker.io/library/postgres@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94`,
network none, no published ports, data tmpfs and a Unix socket under a mode-0700
private parent. SQL version/listen-address readiness and inspection are retained
in `native-fixture/`. Exact owned-container removal exited zero and exact
`podman container exists` exited one; `native-fixture/cleanup.json` records the
2026-10-07T00:51:09Z observation. Shared target/cache and other resources were
preserved; no native work remained at handoff.

Final raw log identity (all exit zero):

| Check | SHA-256 |
| --- | --- |
| format | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| notification-units | `5aaeddd5097392043a8dd9f70e85ee09030f3c01e15c02b6ec9e4f4ab2d4bb8a` |
| loader-unit | `d0f136727838dbbed85cf59b54b399017eec7102427ca148469939ce6d3a1234` |
| shipped-startup | `cd09be8986b8ab05d74969d616721523544cc8b1b9b9c789005472d133ee1dee` |
| existing-store-notification | `7b373ffcbedb1746ebf8ff18b6c22ba8315f4adf3b36fbe55e396a99f4efff37` |
| notifications | `270f5f774bbc971b8efb870424edbbc2b6d6a848ae7114c0c3c781f8c63d70a8` |
| strict-clippy | `d27f75f548526a211cad380750dc545576a2f5e65b2db9a71edd4f185b24d49a` |
| deployment-guard | `e3b316ec2aaa488b625c40a82c77bfc8f61891aee741f7e7f82c3c5e1a09a166` |
| shell-syntax | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

## Frozen candidate source identity

This is the 17-file byte inventory used for final native checks, independently
rechecked after those checks and fixture cleanup. Receipt-only additions to this
security review and the threat-model candidate section follow that freeze.

| Repository path | SHA-256 |
| --- | --- |
| `crates/controller-api/src/notifications.rs` | `93cb840047330cee04ac39bc076f53269804c3c46889c54d37bb2f3bbdec0e4f` |
| `crates/controller-api/src/lib.rs` | `aa82f5ba3bb6230aa3cbe0f47ad4d24a6fe7c3e100aa1456906c1e0d5351cdaa` |
| `crates/controller-api/tests/notifications.rs` | `c9f6f669952442a76e6249a592ef1463c1afa0b02f413461f3a46078e5bdffc7` |
| `crates/controller-store/src/lib.rs` | `194dd9ee0ac1e3e47bb3378c1cb35e8fee5c250720e60511bb02dd4ca5de0d80` |
| `crates/controller-store/src/dag.rs` | `c6640f773e51af3cd008fa13e1de87575f105cce15729eb4412a4fed934174fa` |
| `crates/controller-store/migrations/0045_notification_reconciliation.sql` | `ac80a7c2d31fdebe630ee722c634d6a42ec1b3e493f0f68440c05411753621fb` |
| `crates/domain/src/notifications.rs` | `f30568c551966d712ce1dc23dc05f318d847f20f0ec827d2b6cd6f522b26a023` |
| `bins/controller/src/main.rs` | `e4d63a03a094607697e378ce3a4d11f2ac4acc9c29e92189a0ea8323796e6f6d` |
| `bins/controller/tests/notification_nat64_startup.rs` | `a6cafa481189a6ea0bc4a3bf3da45d995e2c09fd86fc3fc29c5282f9aee0ca76` |
| `deploy/bin/mcloving-deploy-lib.sh` | `22d1321622fa6bc502afcd3dc44cc229a7a41a41eb73df1296a78796e3e53fc5` |
| `deploy/bin/mcloving-env-guard` | `df11dd19abe81915c7b72af5cb5fd5f1a2e424325997fb18789d1eb999e6b34e` |
| `deploy/env/controller.env.example` | `592f4f430bc3c7630a870fc98431cb7991005eea6449db7fd612a4e952fea3ae` |
| `deploy/test-notification-nat64.sh` | `8cd88d5bc8eaf265d3355aabb95b35ec16639ffd560e080063ee048ac646af8d` |
| `deploy/test-deployment.sh` | `13980d2de49e7147e521ff66da15999db0aa88c2eae586da68fef8454bf408f5` |
| `docs/architecture/PUBLIC_API_V1.md` | `c7a35247bb3c07a3e95335ed00f9b9f85db2599e290e9a7a3314cfb2355a2252` |
| `.github/workflows/foundation.yml` | `eb75859aee87da02f3550bd98fabdff83ea6bb2d12e3b0ef934377df35cdbee5` |
| `scripts/test-controller-postgres.sh` | `51b781253b4a260385f5dd34120716ee71bb367186c981ec7aa5dc813f12428a` |

## Affected threats and residual limits

TM-039 gains target observation and durable token-fenced reconciliation while
preserving delivery acceptance truth, generation fencing and tenant/status-key
ordering. TM-054 gains configured RFC6052 decoding at the same SSRF boundary for
GET and POST. TM-013 credential custody and digest-pinned mapping authority remain
in place. TM-018 is relevant to the explicit claim, deadline, count, JSON/page and
byte budgets; TM-005/TM-017/TM-038 include migration 0045 and upgrade scheduling.
The candidate grants no new public authentication, pool/agent execution,
compiler, enrollment, artifact, restore, migration or decommission capability.
These scope determinations require the coordinator's independent disposition.

Convergence is finite: only twelve observation attempts per generation, with
35-second successful-observation spacing and bounded failure backoff. A target
can apply an older body after the last observation or after exhaustion, or be
unavailable throughout the budget. The implementation cannot guarantee eventual
latest status against an arbitrarily delayed/external writer; it records bounded
reconciliation failure separately without falsely revoking accepted delivery.
Public-looking addresses routed privately by the deployment and an unconfigured
translator remain operator network-policy risks. The operator must name its
network-specific prefixes. System TLS roots remain trusted; custom CA pinning is
not added. Tenant-partitioned status-key fencing still allows two organizations
mapping the same repository/commit/context to race at GitHub; use separate
contexts or one organization mapping. Existing arbitrary-commit-within-mapped-
repository authority and bounded retry of permanent 4xx answers remain. No remote
service calls or production migration/deployment were performed by this agent.
