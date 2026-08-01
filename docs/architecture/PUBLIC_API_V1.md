# Public API v1

Status: implemented by UX-001.

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

Pipeline submission sends strict YAML as `application/yaml` and requires an
`Idempotency-Key` header. The key is scoped to the project and returns the
original durable build on replay. The optional `McLoving-Platform` header
selects the node capability independently as exactly `linux` or `windows`; its
default is `linux`. The optional `McLoving-Trust-Pool` header selects the exact
certificate-bound agent pool required by the admitted node; it must be
non-empty and have no surrounding whitespace. Its default is `trusted-linux`.
The CLI exposes the same choices as `submit --platform` and
`submit --trust-pool`. Wave 1 accepts exactly one stage.

The versioned routes are:

- `GET /api/v1/organizations/{organization}/auth/oidc/{provider}/start?redirect_uri=...`
- `GET /api/v1/organizations/{organization}/auth/oidc/{provider}/callback?code=...&state=...`
- `POST /api/v1/organizations/{organization}/auth/session/refresh`
- `POST /api/v1/organizations/{organization}/auth/session/logout`
- `POST /api/v1/organizations/{organization}/projects/{project}/builds`
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

The Wave 1 deployable profile runs one embedded Linux worker for exactly one
configured organization. It requires separate
`MCLOVING_MIGRATION_DATABASE_URL` and `MCLOVING_DATABASE_URL` credentials; the
migration pool is closed before the API and worker start, and the runtime role
must be the RLS-constrained `mcloving_tenant`. Worker identity, organization,
capabilities, lease/poll intervals, session epoch, workspace root, and SQLite
journal path are explicit required environment settings. A remote agent
transport and multi-organization scheduler remain later work.

OIDC is disabled only when every `MCLOVING_OIDC_*` variable is absent. A
partial configuration fails startup. An enabled provider requires its UUID,
issuer, audience, authorization/token/JWKS endpoints, client ID, group claim,
configuration and JWKS generations, exact lowercase JWKS SHA-256, and
comma-separated exact redirect allowlist. A confidential client additionally
sets `MCLOVING_OIDC_CLIENT_SECRET`. TTL, clock-skew, request-timeout, and JWKS
byte limits have bounded operator overrides. Network endpoints and redirects
must use HTTPS; loopback HTTP exists solely for contained protocol tests.

Identity administration is an offline migration-role operation rather than a
public route. Operators use the shipped `mcloving-identity-admin` binary for
reviewed human provenance binding, compare-and-swap lifecycle changes, and
service-credential revocation. The binary accepts identifiers, provenance
digests, actors, and revocation reasons, never raw credential values.
