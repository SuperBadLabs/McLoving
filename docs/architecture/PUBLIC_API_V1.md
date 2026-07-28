# Public API v1

Status: implemented by UX-001.

The Rust CLI is an HTTP client and has no privileged database or controller
shortcut. Every request requires `Authorization: Bearer <token>`. The initial
deployment token is an operator-provisioned service credential of at least 32
bytes; OIDC and scoped service-identity issuance remain later product surface.

Pipeline submission sends strict YAML as `application/yaml` and requires an
`Idempotency-Key` header. The key is scoped to the project and returns the
original durable build on replay. Wave 1 accepts exactly one stage.

The versioned routes are:

- `POST /api/v1/organizations/{organization}/projects/{project}/builds`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}`
- `GET /api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs`
- `POST /api/v1/organizations/{organization}/projects/{project}/builds/{build}/cancel`
- `GET /api/v1/organizations/{organization}/scheduler/explain?capability=linux`

Cancellation is a durable request, not a claim that execution has stopped.
Status reports both build and attempt state plus the cancellation flag. Logs
are controller-committed, SHA-256-bound chunks ordered by sequence. Errors
have stable `code` and `message` fields.
