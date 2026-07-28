# Threat model

Status: Foundation skeleton

## Protected assets

- Controller state and tenant isolation.
- Pipeline and source provenance.
- Credentials and signing material.
- Agent and connector identities.
- Logs, artifacts, caches, and audit evidence.
- Deployment authority.

## Trust boundaries

- Browser/CLI to public API.
- Webhooks to ingress.
- Compatibility worker to IR validator.
- Controller to PostgreSQL and object storage.
- Controller to outbound-connected agents.
- Controller to connectors, secret brokers, and provisioners.
- Trusted, untrusted, release, deployment, and signing agent pools.

## Initial threats

- Cross-tenant object reference.
- Stale lease result publication.
- Duplicate external side effects.
- Fork pipeline credential access.
- Pipeline-parser denial of service.
- Agent or connector impersonation.
- Cache poisoning.
- Log or artifact secret disclosure.
- Escaped process descendants.
- Compromised extension requesting excess authority.
- Database rollback resurrecting stale authority.
- Supply-chain substitution.

## Required analyses

Each implementation ticket identifies changed assets, actors, boundaries,
abuse cases, mitigations, residual risk, and verification. The complete threat
model and security acceptance suite begin with `SEC-001`.
