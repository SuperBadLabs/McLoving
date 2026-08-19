# Public API v1

Status: implemented by UX-002 and extended by CONSUMER-001, ADMIN-001,
JOBSTATE-001, TRIG-001, and DISC-001.

The Rust CLI is an HTTP client and has no privileged database or controller
shortcut. Every protected request requires `Authorization: Bearer <token>`.
Production authentication is durable and database-backed: automation uses a
separately revocable, generation-bound service identity and humans use an OIDC
authorization-code session. The shipped controller provisions its initial
service credential from `MCLOVING_API_TOKEN` and
`MCLOVING_API_TOKEN_GENERATION`; this credential must be distinct from the
artifact-agent credential. `MCLOVING_API_PRINCIPALS_PATH` is retired and its
presence is a startup error. Process-local static principals remain only as a
test/compatibility constructor and cannot host OIDC.

Human login uses authorization code with PKCE S256, one-time random state and
nonce, an exact redirect allowlist, a bounded no-redirect token exchange, and
an exact provisioned JWKS byte digest. ID tokens accept only RSA signature
algorithms and validate the unique key ID, signature, issuer, audience,
subject, expiry, not-before, issued-at, nonce, and configured group claim.
The configured group claim must be present and contain only strings; missing or
malformed membership fails authentication rather than silently granting an
empty group set.
Unknown external subjects are denied: an operator must first create the
immutable source-realm-to-provider-subject provenance edge. Group changes,
identity disable/delete, provider or JWKS generation changes, refresh, logout,
and revocation fence existing credentials in PostgreSQL across every active
controller. Access and refresh credentials are opaque random values; only
SHA-256 digests are stored, refresh is one-time, and all credential-bearing
responses set `Cache-Control: no-store` and `Pragma: no-cache`.
Refresh rotation cannot extend the original absolute refresh deadline, and
reuse of an already-rotated refresh credential revokes the identity's active
session family. OIDC start is source-address rate limited before a durable
one-time attempt is allocated.

Build submission names an already-saved pipeline and sends only typed parameter
values as JSON to `POST .../pipelines/{pipeline}/builds`. It requires an
`Idempotency-Key` header scoped to the project; an exact replay returns the
original durable build even if the pipeline was later revised or its
operational generation changed. Replay validation loads the original bound
revision before resolving current state and still rejects changed parameters,
platform, trust pool, or pipeline identity. First admission loads and compiles
the saved current revision, then atomically binds pipeline ID, revision,
semantic digest, and enabled operational generation to the build.
Caller-supplied YAML cannot mint work.
The optional `McLoving-Platform` and `McLoving-Trust-Pool` headers retain their
strict platform and certificate-bound pool behavior; the CLI exposes these as
`submit --platform` and `submit --trust-pool`.

Operational state is independent of revisioned pipeline source. `GET
.../pipelines/{pipeline}/state` returns the current append-only state record and
ETag. `PUT` to the same route requires project-configure authorization, a
quoted `If-Match` generation, `Idempotency-Key`, reviewed reason, source
identity/generation/effective time, and provenance SHA-256. A valid
`enabled`/`disabled` transition advances exactly one generation. Exact retries
return the original record, divergent key reuse conflicts, and stale or future
preconditions fail without changing state. The complete runtime fence is
defined in `PIPELINE_OPERATIONAL_STATE_V1.md`.

Discovery configuration and reconciliation are typed public contracts. Parent
GET/PUT binds an immutable generation and ETag; PUT requires project-configure,
`If-Match`, and `Idempotency-Key`. The scan route requires project-configure
and accepts only a digest-bound webhook delta or complete periodic/recovery
snapshot; its dedicated 128 MiB transport cap admits the complete documented
4,096-observation denominator. Child listing requires project-view. Exact storage, filtering,
quarantine, orphan, and transfer semantics are defined in `DISCOVERY_V1.md`.
Discovery receipt and child digests use the API-wide lowercase hexadecimal
encoding rather than exposing internal byte arrays. Child listing returns an
object with `items` and nullable `next_after`; it uses a stable, exclusive
child-key cursor, defaults to 50 rows, and rejects limits outside 1 through 200.

The versioned routes are:

- `GET /api/v1/organizations/{organization}/auth/oidc/{provider}/start?redirect_uri=...`
- `GET /api/v1/organizations/{organization}/auth/oidc/{provider}/callback?code=...&state=...`
- `POST /api/v1/organizations/{organization}/auth/session/refresh`
- `POST /api/v1/organizations/{organization}/auth/session/logout`
- `GET /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/state`
- `PUT /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/state`
- `GET /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/discovery/{parent}`
- `PUT /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/discovery/{parent}`
- `POST /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/discovery/{parent}/scans`
- `GET /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/discovery/{parent}/children?after=...&limit=...`
- `POST /api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/builds`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs`
- `POST /api/v1/organizations/{organization}/projects/{project}/builds/{build}/cancel`
- `GET /api/v1/organizations/{organization}/scheduler/explain?capability=linux`

Artifact staging uses the public service credential, but immutable artifact
commit additionally requires `McLoving-Agent-Authorization: Bearer <token>`.
The staging request body is arbitrary binary bytes under
`application/octet-stream`; it is never JSON encoded.
The shipped controller requires `MCLOVING_ARTIFACT_AGENT_TOKEN` and binds that
independent secret to the configured embedded agent ID; public API credentials
alone can never impersonate the leased artifact publisher.

Cancellation is a durable request. Queued work becomes terminal immediately;
owned work becomes `cancelling` until the fenced agent proves process-tree
termination. Status reports both build and attempt state plus the cancellation
flag. Logs are controller-committed, SHA-256-bound chunks ordered by a global
cursor. Continuation requires the complete
`after_attempt_id`/`after_fence`/`after_sequence`/`after_stream` tuple so a
saved cursor remains exact across attempt re-fencing. Every item exposes exact
`content_hex`; `text` is present only when the
whole chunk is valid UTF-8, so clients can always reproduce the digest without
lossy replacement. Errors have stable `code` and `message` fields.

External read-side migration uses only this API. The CLI exposes `pipelines`
with the stable slug cursor and `builds` with the paired creation-microsecond
and build-UUID cursor; `builds --status queued` is the queue view. Existing
`status`, `graph`, `logs`, `watch`, `tests`, `artifacts`, and
`artifact-download` commands cover the remaining read contract. Partial build
and log cursors fail locally rather than issuing an ambiguous request.

External administrative migration also uses only this API. `mcloving apply`
converges a pipeline definition through `PUT .../pipelines/{pipeline}` with a
mandatory quoted `If-Match` revision; revision zero creates, the current
revision updates or returns unchanged, and stale revisions fail with the stable
precondition error. `pipeline-state` reads state and `set-pipeline-state`
advances it through the same generation precondition and provenance contract.
`submit` accepts a pipeline UUID plus parameters; it never uploads executable
source. `cancel`, `retry`, and `approve` retain their separate action
authorization, idempotency/fencing, and audit contracts. The
complete supported/retired/pending write-operation denominator is defined in
`EXTERNAL_ADMIN_CLIENTS_V1.md`; the API does not silently translate unsupported
Jenkins controller operations.

The Wave 1 deployable profile runs one embedded Linux worker for exactly one
configured organization. It requires separate
`MCLOVING_MIGRATION_DATABASE_URL` and `MCLOVING_DATABASE_URL` credentials; the
migration pool is closed before the API and worker start, and the runtime role
must be the RLS-constrained `mcloving_tenant`. Worker identity, organization,
capabilities, lease/poll intervals, session epoch, workspace root, and SQLite
journal path are explicit required environment settings.
`MCLOVING_AGENT_CAPABILITIES` must satisfy the sealed capability vocabulary
(`CAPABILITY_VOCABULARY_V1.md`): it declares `platform:linux` or
`platform:windows` (plus optional exact tokens), or exactly the sentinel
`disabled` to run without an embedded claimer; anything else fails startup
with a named `EmbeddedWorkerCapabilityError`. A remote agent
transport and multi-organization scheduler remain later work.

OIDC is disabled only when every `MCLOVING_OIDC_*` variable is absent. A
partial configuration fails startup. An enabled provider requires its UUID,
issuer, audience, authorization/token/JWKS endpoints, client ID, group claim,
configuration and JWKS generations, exact lowercase JWKS SHA-256, and
comma-separated exact redirect allowlist. A confidential client additionally
sets `MCLOVING_OIDC_CLIENT_SECRET`. TTL, clock-skew, request-timeout, and JWKS
byte limits have bounded operator overrides: access sessions are capped at one
hour, refresh sessions at 24 hours, provider requests at 60 seconds, clock skew
at five minutes, and JWKS responses at 4 MiB. The durable provider generation
and digest bind those local controls, including the exact redirect allowlist,
so a stale replica fails closed during configuration rollout. Network endpoints
and redirects must use HTTPS; loopback HTTP exists solely for contained
protocol tests.

Identity administration is an offline migration-role operation rather than a
public route. Operators use the shipped `mcloving-identity-admin` binary for
reviewed human provenance binding, compare-and-swap lifecycle changes,
compare-and-swap identity-provider enable/disable, and service-credential revocation.
Provider status changes advance its configuration generation and fence existing sessions.
The binary accepts identifiers, provenance
digests, actors, and revocation reasons, never raw credential values.
