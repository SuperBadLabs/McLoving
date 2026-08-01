# Identity and authentication v1

Status: IDP-001 implementation candidate.

McLoving treats identity as durable controller truth. A principal is never
identified by a mutable display name or a process-local token file. PostgreSQL
binds every human or service identity to one organization, lifecycle state and
generation; sessions and service credentials retain the exact generations
against which they were issued. Runtime reads use the tenant RLS role.

## Human provenance and lifecycle

A human mapping binds an immutable OIDC provider/external-subject pair to one
McLoving principal and retains the exact Jenkins source-realm digest, immutable
source identity, membership generation, alias history, and reviewed provenance
digest. Database triggers make those fields immutable. Upgrade migrations
quarantine legacy human rows without this evidence as disabled generation 2;
they cannot be reactivated without a reviewed replacement mapping. The
replacement path is a one-way database-trigger exception that fills every
immutable provider/provenance field on the exact quarantined row before a
separate compare-and-swap activation.

Lifecycle transitions are compare-and-swap operations. Disable or delete
increments the identity generation and immediately invalidates every older
session. A source subject cannot be silently reused, renamed, moved between
providers or tenants, or rebound to a different principal. Group snapshots are
canonical sets with a digest and generation; a changed set advances the
generation and fences older sessions.

## OIDC boundary

The public flow is authorization code plus PKCE S256. Start records a bounded,
expiring, one-time state digest, nonce digest, verifier, exact redirect, and
provider configuration generation. Callback consumes that state before the
external exchange, follows no redirects, bounds token/JWKS responses, requires
the configured raw JWKS digest, and validates the signed ID token before any
session exists. Failure is closed and requires a fresh login attempt.

Provider configuration and JWKS rotations are explicit generations. The
controller must be restarted with the new exact configuration/digest and
generation; stale sessions fail their transaction-time generation checks.
Refresh credentials rotate once, replacing both access and refresh digests.
Rotation preserves the original absolute refresh deadline rather than
extending it. Reuse of an already-rotated refresh credential revokes every
active session for that identity and emits a security audit event.
Logout, administrative revocation, group change, provider disable/rotation,
and identity lifecycle change are visible to every controller through the
database rather than an in-process cache.

## Automation boundary

Automation uses service identities with explicit scopes and independent
generation-bound credentials. Raw tokens are supplied only at provisioning or
request time; PostgreSQL stores SHA-256 digests. Rotation provisions a new
generation and atomically revokes every older credential. Reusing a generation
is idempotent only when its exact token digest and binding match. The
controller's public API token
and artifact-agent publication token must be distinct, and the latter does not
gain public API authority.

## Operator and retention boundary

Human provisioning, lifecycle transitions, identity-provider enable/disable, and service-credential revocation
are intentionally absent from the public API. The shipped
`mcloving-identity-admin` binary performs those audited operations offline with
`MCLOVING_MIGRATION_DATABASE_URL`. It requires explicit organization,
identity/provider or credential UUIDs, immutable source/provenance SHA-256
digests, compare-and-swap lifecycle/provider generations, actor, and reason fields. Provider
status changes advance the provider configuration generation, immediately fencing existing
sessions and login attempts. Disabling a service identity atomically revokes its active
credentials so reactivation cannot resurrect them. It
does not accept raw access, refresh, or service-token values.

Identity/provider/service-credential provisioning is serialized per tenant with a
transaction-scoped advisory lock, making exact active-active bootstrap idempotent even
when the durable row does not yet exist. Refresh-token family revocation occurs only
when a credential previously revoked by successful rotation is presented again; unknown,
expired, lifecycle-fenced, group-fenced, or provider-fenced credentials fail closed without
revoking an unrelated newer session.

OIDC start is limited per source address to 60 attempts per minute with a
bounded 4,096-client in-memory index. PostgreSQL retains at most 1,024 live
attempt rows per tenant/provider by expiring or evicting the oldest attempt.
Expired replay evidence and inactive sessions are retained for 30 days after
their security deadline, and group history retains the latest 128 generations
per identity. Pruning occurs transactionally during session issuance.

## Verification contract

The IDP-001 gate covers migration/RLS behavior, immutable provenance,
one-time state and ID-token replay rejection, PKCE exchange, exact JWKS and
claim validation, cross-tenant denial, group-generation fencing, refresh
rotation/replay denial, logout, service provisioning idempotence,
absolute refresh expiry and reuse-family revocation, atomic service rotation,
legacy-human binding, scope resolution, credential revocation, service disable/reactivation
fencing, identity and provider disable, audit-chain
integrity, and the shipped controller/remote-agent PostgreSQL spine. The final
ticket close additionally requires rollback/restore evidence and independent
security review; until those receipts are attached, the board remains ACTIVE.
