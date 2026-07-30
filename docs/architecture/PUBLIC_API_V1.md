# Public API v1

Status: implemented by UX-001.

The Rust CLI is an HTTP client and has no privileged database or controller
shortcut. Every request requires `Authorization: Bearer <token>`. The initial
deployment token is an operator-provisioned service credential of at least 32
bytes. Distinct human principals can be loaded from
`MCLOVING_API_PRINCIPALS_PATH`; each tab-separated line is
`token<TAB>subject<TAB>project UUID<TAB>role`, where the role is `viewer`,
`developer`, `admin`, or `owner`. Each token resolves to that per-request
principal, so multi-party approval policy counts distinct authenticated
subjects rather than a controller-wide service identity.

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

- `POST /api/v1/organizations/{organization}/projects/{project}/builds`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs`
- `POST /api/v1/organizations/{organization}/projects/{project}/builds/{build}/cancel`
- `GET /api/v1/organizations/{organization}/scheduler/explain?capability=linux`

Artifact staging uses the public service credential, but immutable artifact
commit additionally requires `McLoving-Agent-Authorization: Bearer <token>`.
The shipped controller requires `MCLOVING_ARTIFACT_AGENT_TOKEN` and binds that
independent secret to the configured embedded agent ID; public API credentials
alone can never impersonate the leased artifact publisher.

Cancellation is a durable request. Queued work becomes terminal immediately;
owned work becomes `cancelling` until the fenced agent proves process-tree
termination. Status reports both build and attempt state plus the cancellation
flag. Logs are controller-committed, SHA-256-bound chunks ordered by a global
cursor. Every item exposes exact `content_hex`; `text` is present only when the
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
