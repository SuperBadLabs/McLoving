use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::audit::append_audit_record;
use super::authz::{Principal, PrincipalKind, ProjectRole, ServiceScope};
use super::{Store, StoreError};

const MAX_GROUPS: usize = 4096;
const MAX_ACTIVE_LOGIN_ATTEMPTS_PER_PROVIDER: i64 = 1024;
const IDENTITY_HISTORY_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1_000;
const RETAINED_GROUP_GENERATIONS: i64 = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityLifecycle {
    Active,
    Disabled,
    Deleted,
}

impl IdentityLifecycle {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            "deleted" => Ok(Self::Deleted),
            _ => Err(StoreError::InvalidIdentityOperation(
                "identity lifecycle state is unknown".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProviderWrite {
    pub organization_id: Uuid,
    pub provider_id: Uuid,
    pub issuer: String,
    pub audience: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub group_claim: String,
    pub configuration_generation: i64,
    pub configuration_digest: [u8; 32],
    pub jwks_generation: i64,
    pub jwks_digest: [u8; 32],
    pub enabled: bool,
    pub actor_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityProviderConfig {
    pub provider_id: Uuid,
    pub issuer: String,
    pub audience: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub client_id: String,
    pub group_claim: String,
    pub configuration_generation: i64,
    pub configuration_digest: [u8; 32],
    pub jwks_generation: i64,
    pub jwks_digest: [u8; 32],
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewHumanIdentity {
    pub organization_id: Uuid,
    pub identity_id: Uuid,
    pub subject: String,
    pub provider_id: Uuid,
    pub external_subject: String,
    pub source_realm_digest: [u8; 32],
    pub source_identity_id: String,
    pub source_membership_generation: i64,
    pub alias_history: Vec<String>,
    pub provenance_digest: [u8; 32],
    pub actor_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewServiceIdentity {
    pub organization_id: Uuid,
    pub identity_id: Uuid,
    pub subject: String,
    pub scopes: BTreeSet<ServiceScope>,
    pub actor_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NewServiceCredential {
    pub organization_id: Uuid,
    pub credential_id: Uuid,
    pub identity_id: Uuid,
    pub generation: i64,
    pub token_digest: [u8; 32],
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub actor_subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceCredential {
    pub credential_id: Uuid,
    pub identity_id: Uuid,
    pub generation: i64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginAttempt {
    pub organization_id: Uuid,
    pub attempt_id: Uuid,
    pub provider_id: Uuid,
    pub state_digest: [u8; 32],
    pub nonce_digest: [u8; 32],
    pub pkce_verifier: String,
    pub redirect_uri: String,
    pub provider_configuration_generation: i64,
    pub expires_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIdentityClaims {
    pub organization_id: Uuid,
    pub provider_id: Uuid,
    pub issuer: String,
    pub external_subject: String,
    pub groups: Vec<String>,
    pub provider_configuration_generation: i64,
    pub provider_jwks_generation: i64,
    pub id_token_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIssue {
    pub session_id: Uuid,
    pub token_digest: [u8; 32],
    pub refresh_token_digest: Option<[u8; 32]>,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub refresh_expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionView {
    pub session_id: Uuid,
    pub identity_id: Uuid,
    pub identity_lifecycle_generation: i64,
    pub group_generation: i64,
    pub issued_at_unix_ms: i64,
    pub expires_at_unix_ms: i64,
    pub refresh_expires_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedIdentity {
    pub identity_id: Uuid,
    pub principal: Principal,
    pub lifecycle: IdentityLifecycle,
    pub lifecycle_generation: i64,
    pub group_generation: i64,
    pub session_id: Option<Uuid>,
    pub service_credential_id: Option<Uuid>,
}

impl Store {
    pub async fn identity_provider_config(
        &self,
        organization_id: Uuid,
        provider_id: Uuid,
    ) -> Result<IdentityProviderConfig, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query_as::<_, ProviderRow>(
            "SELECT provider_id, issuer, audience, authorization_endpoint,
                    token_endpoint, jwks_uri, client_id, group_claim,
                    configuration_generation, configuration_digest,
                    jwks_generation, jwks_digest, enabled
             FROM identity_providers
             WHERE organization_id = $1 AND provider_id = $2",
        )
        .bind(organization_id)
        .bind(provider_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC provider is unknown".to_owned()))?;
        tx.commit().await?;
        provider_from_row(row)
    }

    pub async fn provision_identity_provider(
        &self,
        input: &IdentityProviderWrite,
    ) -> Result<IdentityProviderConfig, StoreError> {
        validate_provider(input)?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_identity_provisioning(&mut tx, input.organization_id).await?;
        let provider = provision_identity_provider_in_transaction(&mut tx, input).await?;
        tx.commit().await?;
        Ok(provider)
    }

    /// Atomically rolls out the public API credential and its OIDC provider configuration.
    ///
    /// A rejected half of the rollout rolls back the other half, preserving the previously
    /// deployable controller configuration and API credential.
    pub async fn provision_controller_authentication(
        &self,
        credential: &NewServiceCredential,
        provider: &IdentityProviderWrite,
    ) -> Result<(ServiceCredential, IdentityProviderConfig), StoreError> {
        if credential.organization_id != provider.organization_id {
            return invalid("service credential and identity provider must share an organization");
        }
        validate_service_credential(credential)?;
        validate_provider(provider)?;
        let mut tx = self.tenant_transaction(credential.organization_id).await?;
        lock_identity_provisioning(&mut tx, credential.organization_id).await?;
        let provider = provision_identity_provider_in_transaction(&mut tx, provider).await?;
        let credential = provision_service_credential_in_transaction(&mut tx, credential).await?;
        tx.commit().await?;
        Ok((credential, provider))
    }

    pub async fn transition_identity_provider_enabled(
        &self,
        organization_id: Uuid,
        provider_id: Uuid,
        expected_configuration_generation: i64,
        enabled: bool,
        reason: &str,
        actor_subject: &str,
    ) -> Result<i64, StoreError> {
        validate_canonical(reason, "provider status reason", 1024)?;
        validate_canonical(actor_subject, "actor subject", 512)?;
        if expected_configuration_generation <= 0 {
            return invalid("expected provider configuration generation must be positive");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let current = sqlx::query_as::<_, (i64, bool)>(
            "SELECT configuration_generation, enabled
             FROM identity_providers
             WHERE organization_id = $1 AND provider_id = $2
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(provider_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC provider is unknown".to_owned()))?;
        if current.0 != expected_configuration_generation {
            return Err(StoreError::IdentityConflict(
                "identity-provider configuration generation is stale".to_owned(),
            ));
        }
        if current.1 == enabled {
            tx.commit().await?;
            return Ok(current.0);
        }
        let generation = current.0.checked_add(1).ok_or_else(|| {
            StoreError::InvalidIdentityOperation(
                "identity-provider configuration generation overflow".to_owned(),
            )
        })?;
        sqlx::query(
            "UPDATE identity_providers
             SET enabled = $3, configuration_generation = $4,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND provider_id = $2",
        )
        .bind(organization_id)
        .bind(provider_id)
        .bind(enabled)
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            organization_id,
            "identity",
            actor_subject,
            "identity_provider_status_transitioned",
            &format!("identity-provider:{provider_id}"),
            json!({
                "from_enabled": current.1,
                "to_enabled": enabled,
                "configuration_generation": generation,
                "reason": reason,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(generation)
    }

    pub async fn provision_human_identity(
        &self,
        input: &NewHumanIdentity,
    ) -> Result<(), StoreError> {
        validate_canonical(&input.subject, "identity subject", 512)?;
        validate_canonical(&input.external_subject, "external subject", 512)?;
        validate_canonical(&input.source_identity_id, "source identity ID", 512)?;
        validate_canonical(&input.actor_subject, "actor subject", 512)?;
        if input.source_membership_generation <= 0 {
            return invalid("source membership generation must be positive");
        }
        let aliases = canonical_strings(&input.alias_history, "alias")?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_identity_provisioning(&mut tx, input.organization_id).await?;
        let legacy = sqlx::query_as::<_, (Uuid, String, String, String, i64, Option<Uuid>)>(
            "SELECT id, subject, kind, lifecycle_state, lifecycle_generation, provider_id
             FROM identities
             WHERE organization_id = $1 AND (id = $2 OR subject = $3)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.identity_id)
        .bind(&input.subject)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(legacy) = legacy {
            if legacy.0 == input.identity_id
                && legacy.1 == input.subject
                && legacy.2 == "human"
                && legacy.3 == "disabled"
                && legacy.4 == 2
                && legacy.5.is_none()
            {
                sqlx::query(
                    "UPDATE identities
                     SET provider_id = $4, external_subject = $5,
                         source_realm_digest = $6, source_identity_id = $7,
                         source_membership_generation = $8, alias_history = $9,
                         provenance_digest = $10, updated_at = clock_timestamp()
                     WHERE organization_id = $1 AND id = $2 AND subject = $3",
                )
                .bind(input.organization_id)
                .bind(input.identity_id)
                .bind(&input.subject)
                .bind(input.provider_id)
                .bind(&input.external_subject)
                .bind(input.source_realm_digest.as_slice())
                .bind(&input.source_identity_id)
                .bind(input.source_membership_generation)
                .bind(json!(aliases))
                .bind(input.provenance_digest.as_slice())
                .execute(&mut *tx)
                .await?;
                append_audit_record(
                    &mut tx,
                    input.organization_id,
                    "identity",
                    &input.actor_subject,
                    "legacy_human_identity_bound",
                    &format!("identity:{}", input.identity_id),
                    json!({
                        "provider_id": input.provider_id,
                        "source_realm_digest": hex::encode(input.source_realm_digest),
                        "source_identity_id": input.source_identity_id,
                        "source_membership_generation": input.source_membership_generation,
                        "provenance_digest": hex::encode(input.provenance_digest),
                    }),
                )
                .await?;
                tx.commit().await?;
                return Ok(());
            }
            let exact_mapping = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                     SELECT 1 FROM identities
                     WHERE organization_id = $1 AND id = $2 AND subject = $3
                       AND kind = 'human' AND provider_id = $4
                       AND external_subject = $5 AND source_realm_digest = $6
                       AND source_identity_id = $7
                       AND source_membership_generation = $8
                       AND alias_history = $9 AND provenance_digest = $10
                 )",
            )
            .bind(input.organization_id)
            .bind(input.identity_id)
            .bind(&input.subject)
            .bind(input.provider_id)
            .bind(&input.external_subject)
            .bind(input.source_realm_digest.as_slice())
            .bind(&input.source_identity_id)
            .bind(input.source_membership_generation)
            .bind(json!(aliases))
            .bind(input.provenance_digest.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if exact_mapping {
                tx.commit().await?;
                return Ok(());
            }
            return Err(StoreError::IdentityConflict(
                "human identity collides with an immutable existing binding".to_owned(),
            ));
        }
        let collision = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM identities
             WHERE organization_id = $1
               AND (id = $2 OR subject = $3
                    OR (provider_id = $4 AND external_subject = $5))",
        )
        .bind(input.organization_id)
        .bind(input.identity_id)
        .bind(&input.subject)
        .bind(input.provider_id)
        .bind(&input.external_subject)
        .fetch_one(&mut *tx)
        .await?;
        if collision != 0 {
            return Err(StoreError::IdentityConflict(
                "human identity collides with an immutable existing binding".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO identities(
                 id, organization_id, subject, kind, provider_id, external_subject,
                 source_realm_digest, source_identity_id,
                 source_membership_generation, alias_history, provenance_digest
             ) VALUES ($1,$2,$3,'human',$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(input.identity_id)
        .bind(input.organization_id)
        .bind(&input.subject)
        .bind(input.provider_id)
        .bind(&input.external_subject)
        .bind(input.source_realm_digest.as_slice())
        .bind(&input.source_identity_id)
        .bind(input.source_membership_generation)
        .bind(json!(aliases))
        .bind(input.provenance_digest.as_slice())
        .execute(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            input.organization_id,
            "identity",
            &input.actor_subject,
            "human_identity_provisioned",
            &format!("identity:{}", input.identity_id),
            json!({
                "provider_id": input.provider_id,
                "source_realm_digest": hex::encode(input.source_realm_digest),
                "source_identity_id": input.source_identity_id,
                "source_membership_generation": input.source_membership_generation,
                "provenance_digest": hex::encode(input.provenance_digest),
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn provision_service_identity(
        &self,
        input: &NewServiceIdentity,
    ) -> Result<(), StoreError> {
        validate_canonical(&input.subject, "service subject", 512)?;
        validate_canonical(&input.actor_subject, "actor subject", 512)?;
        if input.scopes.is_empty() {
            return invalid("service identity must have at least one explicit scope");
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_identity_provisioning(&mut tx, input.organization_id).await?;
        let existing = sqlx::query_as::<_, (Uuid, String, String, String)>(
            "SELECT id, subject, kind, lifecycle_state FROM identities
             WHERE organization_id = $1 AND (id = $2 OR subject = $3)
             FOR UPDATE",
        )
        .bind(input.organization_id)
        .bind(input.identity_id)
        .bind(&input.subject)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(existing) = existing {
            let scopes = sqlx::query_scalar::<_, String>(
                "SELECT scope FROM service_scopes
                 WHERE organization_id = $1 AND identity_id = $2
                 ORDER BY scope",
            )
            .bind(input.organization_id)
            .bind(existing.0)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .map(|scope| parse_scope(&scope))
            .collect::<Result<BTreeSet<_>, _>>()?;
            if existing.0 == input.identity_id
                && existing.1 == input.subject
                && existing.2 == "service"
                && existing.3 == "active"
                && scopes == input.scopes
            {
                tx.commit().await?;
                return Ok(());
            }
            return Err(StoreError::IdentityConflict(
                "service identity collides with an immutable existing binding or scope set"
                    .to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO identities(id, organization_id, subject, kind)
             VALUES ($1,$2,$3,'service')",
        )
        .bind(input.identity_id)
        .bind(input.organization_id)
        .bind(&input.subject)
        .execute(&mut *tx)
        .await?;
        for scope in &input.scopes {
            sqlx::query(
                "INSERT INTO service_scopes(identity_id, organization_id, scope)
                 VALUES ($1,$2,$3)",
            )
            .bind(input.identity_id)
            .bind(input.organization_id)
            .bind(scope_name(*scope))
            .execute(&mut *tx)
            .await?;
        }
        append_audit_record(
            &mut tx,
            input.organization_id,
            "identity",
            &input.actor_subject,
            "service_identity_provisioned",
            &format!("identity:{}", input.identity_id),
            json!({"scopes": input.scopes.iter().map(|s| scope_name(*s)).collect::<Vec<_>>() }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn provision_service_credential(
        &self,
        input: &NewServiceCredential,
    ) -> Result<ServiceCredential, StoreError> {
        validate_service_credential(input)?;
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        lock_identity_provisioning(&mut tx, input.organization_id).await?;
        let credential = provision_service_credential_in_transaction(&mut tx, input).await?;
        tx.commit().await?;
        Ok(credential)
    }

    pub async fn record_oidc_login_attempt(&self, input: &LoginAttempt) -> Result<(), StoreError> {
        validate_canonical(&input.pkce_verifier, "PKCE verifier", 128)?;
        validate_canonical(&input.redirect_uri, "redirect URI", 2048)?;
        if input.pkce_verifier.len() < 43
            || input.provider_configuration_generation <= 0
            || input.expires_at_unix_ms < 0
        {
            return invalid("OIDC login attempt bounds are invalid");
        }
        let mut tx = self.tenant_transaction(input.organization_id).await?;
        sqlx::query(
            "DELETE FROM oidc_login_attempts
             WHERE organization_id = $1
               AND (expires_at_unix_ms < (extract(epoch FROM clock_timestamp()) * 1000)::bigint
                    OR consumed_at_unix_ms < (extract(epoch FROM clock_timestamp()) * 1000)::bigint - 600000)",
        )
        .bind(input.organization_id)
        .execute(&mut *tx)
        .await?;
        let active_attempts = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM oidc_login_attempts
             WHERE organization_id = $1 AND provider_id = $2
               AND consumed_at_unix_ms IS NULL
               AND expires_at_unix_ms >= (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .bind(input.organization_id)
        .bind(input.provider_id)
        .fetch_one(&mut *tx)
        .await?;
        if active_attempts >= MAX_ACTIVE_LOGIN_ATTEMPTS_PER_PROVIDER {
            sqlx::query(
                "DELETE FROM oidc_login_attempts
                 WHERE organization_id = $1 AND attempt_id = (
                     SELECT attempt_id FROM oidc_login_attempts
                     WHERE organization_id = $1 AND provider_id = $2
                       AND consumed_at_unix_ms IS NULL
                     ORDER BY created_at, attempt_id
                     FOR UPDATE SKIP LOCKED LIMIT 1
                 )",
            )
            .bind(input.organization_id)
            .bind(input.provider_id)
            .execute(&mut *tx)
            .await?;
        }
        let provider_generation = sqlx::query_scalar::<_, i64>(
            "SELECT configuration_generation FROM identity_providers
             WHERE organization_id = $1 AND provider_id = $2 AND enabled",
        )
        .bind(input.organization_id)
        .bind(input.provider_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC provider is unavailable".to_owned()))?;
        if provider_generation != input.provider_configuration_generation {
            return Err(StoreError::IdentityConflict(
                "OIDC login attempt uses a stale provider generation".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO oidc_login_attempts(
                 organization_id, attempt_id, provider_id, state_digest,
                 nonce_digest, pkce_verifier, redirect_uri,
                 provider_configuration_generation, expires_at_unix_ms
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(input.organization_id)
        .bind(input.attempt_id)
        .bind(input.provider_id)
        .bind(input.state_digest.as_slice())
        .bind(input.nonce_digest.as_slice())
        .bind(&input.pkce_verifier)
        .bind(&input.redirect_uri)
        .bind(input.provider_configuration_generation)
        .bind(input.expires_at_unix_ms)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn consume_oidc_login_attempt(
        &self,
        organization_id: Uuid,
        state_digest: [u8; 32],
        now_unix_ms: i64,
    ) -> Result<LoginAttempt, StoreError> {
        if now_unix_ms < 0 {
            return invalid("OIDC callback timestamp is invalid");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let row = sqlx::query_as::<_, LoginRow>(
            "SELECT attempt_id, provider_id, state_digest, nonce_digest,
                    pkce_verifier, redirect_uri,
                    provider_configuration_generation, expires_at_unix_ms,
                    consumed_at_unix_ms
             FROM oidc_login_attempts
             WHERE organization_id = $1 AND state_digest = $2
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(state_digest.as_slice())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC state is unknown".to_owned()))?;
        if row.8.is_some() || now_unix_ms > row.7 {
            return Err(StoreError::IdentityConflict(
                "OIDC state is expired or already consumed".to_owned(),
            ));
        }
        let generation = sqlx::query_scalar::<_, i64>(
            "SELECT configuration_generation FROM identity_providers
             WHERE organization_id = $1 AND provider_id = $2 AND enabled",
        )
        .bind(organization_id)
        .bind(row.1)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC provider is unavailable".to_owned()))?;
        if generation != row.6 {
            return Err(StoreError::IdentityConflict(
                "OIDC state was created under a stale provider generation".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE oidc_login_attempts SET consumed_at_unix_ms = $3
             WHERE organization_id = $1 AND attempt_id = $2",
        )
        .bind(organization_id)
        .bind(row.0)
        .bind(now_unix_ms)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(LoginAttempt {
            organization_id,
            attempt_id: row.0,
            provider_id: row.1,
            state_digest: digest_array(&row.2)?,
            nonce_digest: digest_array(&row.3)?,
            pkce_verifier: row.4,
            redirect_uri: row.5,
            provider_configuration_generation: row.6,
            expires_at_unix_ms: row.7,
        })
    }

    pub async fn issue_human_session(
        &self,
        claims: &OidcIdentityClaims,
        issue: &SessionIssue,
    ) -> Result<SessionView, StoreError> {
        validate_canonical(&claims.issuer, "OIDC issuer", 2048)?;
        validate_canonical(&claims.external_subject, "OIDC subject", 512)?;
        let groups = canonical_strings(&claims.groups, "OIDC group")?;
        if issue.issued_at_unix_ms < 0
            || issue.expires_at_unix_ms <= issue.issued_at_unix_ms
            || issue.refresh_token_digest.is_some() != issue.refresh_expires_at_unix_ms.is_some()
            || issue
                .refresh_expires_at_unix_ms
                .is_some_and(|expires| expires <= issue.expires_at_unix_ms)
        {
            return invalid("session lifetime is invalid");
        }
        let group_digest = digest_strings(&groups);
        let mut tx = self.tenant_transaction(claims.organization_id).await?;
        prune_identity_security_history(&mut tx, claims.organization_id, issue.issued_at_unix_ms)
            .await?;
        let provider = sqlx::query_as::<_, (String, i64, i64, bool)>(
            "SELECT issuer, configuration_generation, jwks_generation, enabled
             FROM identity_providers
             WHERE organization_id = $1 AND provider_id = $2",
        )
        .bind(claims.organization_id)
        .bind(claims.provider_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC provider is unknown".to_owned()))?;
        if !provider.3
            || provider.0 != claims.issuer
            || provider.1 != claims.provider_configuration_generation
            || provider.2 != claims.provider_jwks_generation
        {
            return Err(StoreError::IdentityConflict(
                "OIDC issuer or provider generation does not match current trust".to_owned(),
            ));
        }
        let identity = sqlx::query_as::<_, IdentityRow>(
            "SELECT id, subject, kind, lifecycle_state, lifecycle_generation,
                    group_generation, group_digest
             FROM identities
             WHERE organization_id = $1 AND provider_id = $2 AND external_subject = $3
             FOR UPDATE",
        )
        .bind(claims.organization_id)
        .bind(claims.provider_id)
        .bind(&claims.external_subject)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("OIDC identity is not mapped".to_owned()))?;
        if identity.2 != "human" || identity.3 != "active" {
            return Err(StoreError::IdentityConflict(
                "OIDC identity is disabled or deleted".to_owned(),
            ));
        }
        let current_group_digest = digest_array(&identity.6)?;
        let group_generation = if current_group_digest == group_digest {
            identity.5
        } else {
            let next = identity.5.checked_add(1).ok_or_else(|| {
                StoreError::InvalidIdentityOperation("group generation overflow".to_owned())
            })?;
            sqlx::query(
                "UPDATE identities SET group_generation = $3, group_digest = $4,
                     updated_at = clock_timestamp()
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(claims.organization_id)
            .bind(identity.0)
            .bind(next)
            .bind(group_digest.as_slice())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO identity_group_snapshots(
                     organization_id, identity_id, generation, groups, group_digest,
                     provider_configuration_generation, provider_jwks_generation,
                     observed_at_unix_ms
                 ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(claims.organization_id)
            .bind(identity.0)
            .bind(next)
            .bind(json!(groups))
            .bind(group_digest.as_slice())
            .bind(claims.provider_configuration_generation)
            .bind(claims.provider_jwks_generation)
            .bind(issue.issued_at_unix_ms)
            .execute(&mut *tx)
            .await?;
            next
        };
        let replayed = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1 FROM oidc_token_replays
                 WHERE organization_id = $1 AND id_token_digest = $2
             )",
        )
        .bind(claims.organization_id)
        .bind(claims.id_token_digest.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if replayed {
            return Err(StoreError::IdentityConflict(
                "OIDC ID token was already consumed".to_owned(),
            ));
        }
        reject_credential_digest_collision(&mut tx, claims.organization_id, &issue.token_digest)
            .await?;
        if let Some(refresh_digest) = &issue.refresh_token_digest {
            reject_credential_digest_collision(&mut tx, claims.organization_id, refresh_digest)
                .await?;
        }
        sqlx::query(
            "INSERT INTO oidc_token_replays(
                 organization_id, id_token_digest, identity_id, expires_at_unix_ms
             ) VALUES ($1,$2,$3,$4)",
        )
        .bind(claims.organization_id)
        .bind(claims.id_token_digest.as_slice())
        .bind(identity.0)
        .bind(issue.expires_at_unix_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO identity_sessions(
                 organization_id, session_id, identity_id, token_digest,
                 provider_configuration_generation, provider_jwks_generation,
                 identity_lifecycle_generation, group_generation,
                 issued_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms,
                 refresh_token_digest, refresh_expires_at_unix_ms, family_id
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$9,$11,$12,$2)",
        )
        .bind(claims.organization_id)
        .bind(issue.session_id)
        .bind(identity.0)
        .bind(issue.token_digest.as_slice())
        .bind(claims.provider_configuration_generation)
        .bind(claims.provider_jwks_generation)
        .bind(identity.4)
        .bind(group_generation)
        .bind(issue.issued_at_unix_ms)
        .bind(issue.expires_at_unix_ms)
        .bind(
            issue
                .refresh_token_digest
                .as_ref()
                .map(|digest| digest.as_slice()),
        )
        .bind(issue.refresh_expires_at_unix_ms)
        .execute(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            claims.organization_id,
            "authentication",
            &identity.1,
            "oidc_session_issued",
            &format!("identity-session:{}", issue.session_id),
            json!({
                "identity_id": identity.0,
                "provider_id": claims.provider_id,
                "configuration_generation": claims.provider_configuration_generation,
                "jwks_generation": claims.provider_jwks_generation,
                "lifecycle_generation": identity.4,
                "group_generation": group_generation,
                "expires_at_unix_ms": issue.expires_at_unix_ms,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(SessionView {
            session_id: issue.session_id,
            identity_id: identity.0,
            identity_lifecycle_generation: identity.4,
            group_generation,
            issued_at_unix_ms: issue.issued_at_unix_ms,
            expires_at_unix_ms: issue.expires_at_unix_ms,
            refresh_expires_at_unix_ms: issue.refresh_expires_at_unix_ms,
            revoked_at_unix_ms: None,
        })
    }

    pub async fn authenticate_api_token(
        &self,
        organization_id: Uuid,
        token_digest: [u8; 32],
        now_unix_ms: i64,
    ) -> Result<AuthenticatedIdentity, StoreError> {
        if now_unix_ms < 0 {
            return invalid("authentication timestamp is invalid");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let session = sqlx::query_as::<_, SessionAuthRow>(
            "SELECT s.session_id, s.identity_id, i.subject, i.kind,
                    i.lifecycle_state, i.lifecycle_generation, i.group_generation
             FROM identity_sessions s
             JOIN identities i ON i.organization_id = s.organization_id
                              AND i.id = s.identity_id
             JOIN identity_providers p ON p.organization_id = i.organization_id
                                      AND p.provider_id = i.provider_id
             WHERE s.organization_id = $1 AND s.token_digest = $2
               AND s.revoked_at_unix_ms IS NULL AND s.expires_at_unix_ms > $3
               AND i.lifecycle_state = 'active'
               AND s.identity_lifecycle_generation = i.lifecycle_generation
               AND s.group_generation = i.group_generation
               AND p.enabled
               AND s.provider_configuration_generation = p.configuration_generation
               AND s.provider_jwks_generation = p.jwks_generation",
        )
        .bind(organization_id)
        .bind(token_digest.as_slice())
        .bind(now_unix_ms)
        .fetch_optional(&mut *tx)
        .await?;
        let service = sqlx::query_as::<_, ServiceAuthRow>(
            "SELECT c.credential_id, c.identity_id, i.subject, i.kind,
                    i.lifecycle_state, i.lifecycle_generation, i.group_generation
             FROM service_credentials c
             JOIN identities i ON i.organization_id = c.organization_id
                              AND i.id = c.identity_id
             WHERE c.organization_id = $1 AND c.token_digest = $2
               AND c.revoked_at_unix_ms IS NULL
               AND (c.expires_at_unix_ms IS NULL OR c.expires_at_unix_ms > $3)
               AND i.lifecycle_state = 'active'",
        )
        .bind(organization_id)
        .bind(token_digest.as_slice())
        .bind(now_unix_ms)
        .fetch_optional(&mut *tx)
        .await?;
        if session.is_some() && service.is_some() {
            return Err(StoreError::IdentityConflict(
                "credential digest is ambiguously bound".to_owned(),
            ));
        }
        let (
            identity_id,
            subject,
            kind,
            lifecycle,
            lifecycle_generation,
            group_generation,
            session_id,
            credential_id,
        ) = match (session, service) {
            (Some(row), None) => (row.1, row.2, row.3, row.4, row.5, row.6, Some(row.0), None),
            (None, Some(row)) => (row.1, row.2, row.3, row.4, row.5, row.6, None, Some(row.0)),
            (None, None) => {
                return Err(StoreError::IdentityConflict(
                    "credential is unknown, stale, expired, or revoked".to_owned(),
                ));
            }
            (Some(_), Some(_)) => unreachable!(),
        };
        let principal =
            load_principal(&mut tx, organization_id, identity_id, &subject, &kind).await?;
        if let Some(id) = session_id {
            sqlx::query(
                "UPDATE identity_sessions SET last_seen_at_unix_ms = GREATEST(last_seen_at_unix_ms, $3)
                 WHERE organization_id = $1 AND session_id = $2
                   AND last_seen_at_unix_ms <= $3 - 60000",
            )
            .bind(organization_id)
            .bind(id)
            .bind(now_unix_ms)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(AuthenticatedIdentity {
            identity_id,
            principal,
            lifecycle: IdentityLifecycle::parse(&lifecycle)?,
            lifecycle_generation,
            group_generation,
            session_id,
            service_credential_id: credential_id,
        })
    }

    pub async fn rotate_human_session(
        &self,
        organization_id: Uuid,
        current_refresh_token_digest: [u8; 32],
        issue: &SessionIssue,
    ) -> Result<SessionView, StoreError> {
        let Some(next_refresh_digest) = issue.refresh_token_digest else {
            return invalid("a refreshed session requires a rotating refresh credential");
        };
        let Some(_requested_refresh_expiry) = issue.refresh_expires_at_unix_ms else {
            return invalid("a refreshed session requires a refresh expiry");
        };
        if issue.issued_at_unix_ms < 0 || issue.expires_at_unix_ms <= issue.issued_at_unix_ms {
            return invalid("refreshed session lifetime is invalid");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        if let Some(family_id) = session_family_for_refresh_digest(
            &mut tx,
            organization_id,
            &current_refresh_token_digest,
        )
        .await?
        {
            lock_session_family(&mut tx, organization_id, family_id).await?;
        }
        let current = sqlx::query_as::<_, SessionRefreshRow>(
            "SELECT s.session_id, s.identity_id, i.subject,
                    s.provider_configuration_generation,
                    s.provider_jwks_generation,
                    s.identity_lifecycle_generation, s.group_generation,
                    s.family_id, s.refresh_expires_at_unix_ms
             FROM identity_sessions s
             JOIN identities i ON i.organization_id = s.organization_id
                              AND i.id = s.identity_id
             JOIN identity_providers p ON p.organization_id = i.organization_id
                                      AND p.provider_id = i.provider_id
             WHERE s.organization_id = $1 AND s.refresh_token_digest = $2
               AND s.revoked_at_unix_ms IS NULL
               AND s.refresh_expires_at_unix_ms > $3
               AND i.kind = 'human' AND i.lifecycle_state = 'active'
               AND s.identity_lifecycle_generation = i.lifecycle_generation
               AND s.group_generation = i.group_generation
               AND p.enabled
               AND s.provider_configuration_generation = p.configuration_generation
               AND s.provider_jwks_generation = p.jwks_generation
             FOR UPDATE OF s",
        )
        .bind(organization_id)
        .bind(current_refresh_token_digest.as_slice())
        .bind(issue.issued_at_unix_ms)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(current) = current else {
            revoke_session_family_on_refresh_reuse(
                &mut tx,
                organization_id,
                &current_refresh_token_digest,
                issue.issued_at_unix_ms,
            )
            .await?;
            tx.commit().await?;
            return Err(StoreError::IdentityConflict(
                "refresh credential is unknown, stale, expired, or revoked".to_owned(),
            ));
        };
        let absolute_refresh_expiry = current.8.ok_or_else(|| {
            StoreError::IdentityConflict("refresh credential has no absolute expiry".to_owned())
        })?;
        if issue.expires_at_unix_ms >= absolute_refresh_expiry {
            return Err(StoreError::IdentityConflict(
                "refresh credential is too close to its absolute expiry; reauthentication is required"
                    .to_owned(),
            ));
        }
        reject_credential_digest_collision(&mut tx, organization_id, &issue.token_digest).await?;
        reject_credential_digest_collision(&mut tx, organization_id, &next_refresh_digest).await?;
        sqlx::query(
            "UPDATE identity_sessions
             SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $3),
                 revocation_reason = 'refresh_rotation'
             WHERE organization_id = $1 AND session_id = $2",
        )
        .bind(organization_id)
        .bind(current.0)
        .bind(issue.issued_at_unix_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO identity_sessions(
                 organization_id, session_id, identity_id, token_digest,
                 provider_configuration_generation, provider_jwks_generation,
                 identity_lifecycle_generation, group_generation,
                 issued_at_unix_ms, expires_at_unix_ms, last_seen_at_unix_ms,
                 refresh_token_digest, refresh_expires_at_unix_ms, family_id
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$9,$11,$12,$13)",
        )
        .bind(organization_id)
        .bind(issue.session_id)
        .bind(current.1)
        .bind(issue.token_digest.as_slice())
        .bind(current.3)
        .bind(current.4)
        .bind(current.5)
        .bind(current.6)
        .bind(issue.issued_at_unix_ms)
        .bind(issue.expires_at_unix_ms)
        .bind(next_refresh_digest.as_slice())
        .bind(absolute_refresh_expiry)
        .bind(current.7)
        .execute(&mut *tx)
        .await?;
        append_audit_record(
            &mut tx,
            organization_id,
            "authentication",
            &current.2,
            "oidc_session_refreshed",
            &format!("identity-session:{}", issue.session_id),
            json!({
                "identity_id": current.1,
                "replaced_session_id": current.0,
                "configuration_generation": current.3,
                "jwks_generation": current.4,
                "lifecycle_generation": current.5,
                "group_generation": current.6,
                "expires_at_unix_ms": issue.expires_at_unix_ms,
                "refresh_expires_at_unix_ms": absolute_refresh_expiry,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(SessionView {
            session_id: issue.session_id,
            identity_id: current.1,
            identity_lifecycle_generation: current.5,
            group_generation: current.6,
            issued_at_unix_ms: issue.issued_at_unix_ms,
            expires_at_unix_ms: issue.expires_at_unix_ms,
            refresh_expires_at_unix_ms: Some(absolute_refresh_expiry),
            revoked_at_unix_ms: None,
        })
    }

    pub async fn refresh_session_provider(
        &self,
        organization_id: Uuid,
        refresh_token_digest: [u8; 32],
        now_unix_ms: i64,
    ) -> Result<Uuid, StoreError> {
        if now_unix_ms < 0 {
            return invalid("refresh lookup timestamp is invalid");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let provider_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT i.provider_id
             FROM identity_sessions s
             JOIN identities i ON i.organization_id = s.organization_id
                              AND i.id = s.identity_id
             JOIN identity_providers p ON p.organization_id = i.organization_id
                                      AND p.provider_id = i.provider_id
             WHERE s.organization_id = $1 AND s.refresh_token_digest = $2
               AND s.revoked_at_unix_ms IS NULL
               AND s.refresh_expires_at_unix_ms > $3
               AND i.kind = 'human' AND i.lifecycle_state = 'active'
               AND s.identity_lifecycle_generation = i.lifecycle_generation
               AND s.group_generation = i.group_generation
               AND p.enabled
               AND s.provider_configuration_generation = p.configuration_generation
               AND s.provider_jwks_generation = p.jwks_generation",
        )
        .bind(organization_id)
        .bind(refresh_token_digest.as_slice())
        .bind(now_unix_ms)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(provider_id) = provider_id else {
            revoke_session_family_on_refresh_reuse(
                &mut tx,
                organization_id,
                &refresh_token_digest,
                now_unix_ms,
            )
            .await?;
            tx.commit().await?;
            return Err(StoreError::IdentityConflict(
                "refresh credential is unknown, stale, expired, or revoked".to_owned(),
            ));
        };
        tx.commit().await?;
        Ok(provider_id)
    }

    pub async fn revoke_session(
        &self,
        organization_id: Uuid,
        session_id: Uuid,
        now_unix_ms: i64,
        reason: &str,
        actor_subject: &str,
    ) -> Result<bool, StoreError> {
        validate_canonical(reason, "revocation reason", 256)?;
        validate_canonical(actor_subject, "actor subject", 512)?;
        if now_unix_ms < 0 {
            return invalid("revocation timestamp is invalid");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let family_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT family_id
             FROM identity_sessions
             WHERE organization_id = $1 AND session_id = $2",
        )
        .bind(organization_id)
        .bind(session_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(family_id) = family_id else {
            tx.commit().await?;
            return Ok(false);
        };
        lock_session_family(&mut tx, organization_id, family_id).await?;
        let revocation_reason = sqlx::query_scalar::<_, Option<String>>(
            "SELECT revocation_reason
             FROM identity_sessions
             WHERE organization_id = $1 AND session_id = $2
             FOR UPDATE",
        )
        .bind(organization_id)
        .bind(session_id)
        .fetch_optional(&mut *tx)
        .await?
        .flatten();
        let changed = match revocation_reason.as_deref() {
            None => sqlx::query(
                "UPDATE identity_sessions
                     SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $3),
                         revocation_reason = $4
                     WHERE organization_id = $1 AND session_id = $2
                       AND revoked_at_unix_ms IS NULL",
            )
            .bind(organization_id)
            .bind(session_id)
            .bind(now_unix_ms)
            .bind(reason)
            .execute(&mut *tx)
            .await?
            .rows_affected(),
            Some("refresh_rotation") => {
                // A refresh may commit after API authentication but before
                // logout reaches this row lock. In that ordering the access
                // token identifies the rotated predecessor, so revoke only
                // the active descendants in that session lineage. The shared
                // predecessor row lock serializes this update against rotation
                // of that same generation without affecting another device.
                sqlx::query(
                    "UPDATE identity_sessions
                     SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $3),
                         revocation_reason = $4
                     WHERE organization_id = $1 AND family_id = $2
                       AND revoked_at_unix_ms IS NULL",
                )
                .bind(organization_id)
                .bind(family_id)
                .bind(now_unix_ms)
                .bind(reason)
                .execute(&mut *tx)
                .await?
                .rows_affected()
            }
            Some(_) => 0,
        };
        if changed > 0 {
            append_audit_record(
                &mut tx,
                organization_id,
                "authentication",
                actor_subject,
                "oidc_session_revoked",
                &format!("credential:{session_id}"),
                json!({
                    "reason": reason,
                    "revoked_at_unix_ms": now_unix_ms,
                    "revoked_sessions": changed,
                }),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(changed > 0)
    }

    pub async fn revoke_service_credential(
        &self,
        organization_id: Uuid,
        credential_id: Uuid,
        now_unix_ms: i64,
        reason: &str,
        actor_subject: &str,
    ) -> Result<bool, StoreError> {
        revoke_credential_record(
            self,
            organization_id,
            "service_credentials",
            "credential_id",
            credential_id,
            now_unix_ms,
            reason,
            actor_subject,
            "service_credential_revoked",
        )
        .await
    }

    pub async fn transition_identity_lifecycle(
        &self,
        organization_id: Uuid,
        identity_id: Uuid,
        expected_generation: i64,
        next: IdentityLifecycle,
        actor_subject: &str,
    ) -> Result<i64, StoreError> {
        validate_canonical(actor_subject, "actor subject", 512)?;
        if expected_generation <= 0 {
            return invalid("expected identity generation must be positive");
        }
        let mut tx = self.tenant_transaction(organization_id).await?;
        let current = sqlx::query_as::<_, (String, i64, String)>(
            "SELECT lifecycle_state, lifecycle_generation, subject
             FROM identities WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(organization_id)
        .bind(identity_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| StoreError::IdentityConflict("identity is unknown".to_owned()))?;
        if current.1 != expected_generation {
            return Err(StoreError::IdentityConflict(
                "identity lifecycle generation is stale".to_owned(),
            ));
        }
        let current_state = IdentityLifecycle::parse(&current.0)?;
        if current_state == IdentityLifecycle::Deleted && next != IdentityLifecycle::Deleted {
            return Err(StoreError::IdentityConflict(
                "deleted identity cannot be reactivated or reused".to_owned(),
            ));
        }
        if current_state == next {
            tx.commit().await?;
            return Ok(current.1);
        }
        let generation = current.1.checked_add(1).ok_or_else(|| {
            StoreError::InvalidIdentityOperation("identity generation overflow".to_owned())
        })?;
        sqlx::query(
            "UPDATE identities SET lifecycle_state = $3, lifecycle_generation = $4,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(identity_id)
        .bind(next.as_str())
        .bind(generation)
        .execute(&mut *tx)
        .await?;
        let revoked_service_credentials =
            if current_state == IdentityLifecycle::Active && next != IdentityLifecycle::Active {
                sqlx::query(
                    "UPDATE service_credentials
                 SET revoked_at_unix_ms = GREATEST(
                         issued_at_unix_ms,
                         (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint
                     ),
                     revocation_reason = 'identity_lifecycle_transition'
                 WHERE organization_id = $1 AND identity_id = $2
                   AND revoked_at_unix_ms IS NULL",
                )
                .bind(organization_id)
                .bind(identity_id)
                .execute(&mut *tx)
                .await?
                .rows_affected()
            } else {
                0
            };
        append_audit_record(
            &mut tx,
            organization_id,
            "identity",
            actor_subject,
            "identity_lifecycle_transitioned",
            &format!("identity:{identity_id}"),
            json!({
                "from": current_state,
                "to": next,
                "generation": generation,
                "revoked_service_credentials": revoked_service_credentials,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(generation)
    }
}

type ProviderRow = (
    Uuid,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    Vec<u8>,
    i64,
    Vec<u8>,
    bool,
);
type LoginRow = (
    Uuid,
    Uuid,
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    i64,
    i64,
    Option<i64>,
);
type IdentityRow = (Uuid, String, String, String, i64, i64, Vec<u8>);
type SessionAuthRow = (Uuid, Uuid, String, String, String, i64, i64);
type ServiceAuthRow = (Uuid, Uuid, String, String, String, i64, i64);
type SessionRefreshRow = (Uuid, Uuid, String, i64, i64, i64, i64, Uuid, Option<i64>);

fn provider_from_write(input: &IdentityProviderWrite) -> IdentityProviderConfig {
    IdentityProviderConfig {
        provider_id: input.provider_id,
        issuer: input.issuer.clone(),
        audience: input.audience.clone(),
        authorization_endpoint: input.authorization_endpoint.clone(),
        token_endpoint: input.token_endpoint.clone(),
        jwks_uri: input.jwks_uri.clone(),
        client_id: input.client_id.clone(),
        group_claim: input.group_claim.clone(),
        configuration_generation: input.configuration_generation,
        configuration_digest: input.configuration_digest,
        jwks_generation: input.jwks_generation,
        jwks_digest: input.jwks_digest,
        enabled: input.enabled,
    }
}

fn provider_from_row(row: ProviderRow) -> Result<IdentityProviderConfig, StoreError> {
    Ok(IdentityProviderConfig {
        provider_id: row.0,
        issuer: row.1,
        audience: row.2,
        authorization_endpoint: row.3,
        token_endpoint: row.4,
        jwks_uri: row.5,
        client_id: row.6,
        group_claim: row.7,
        configuration_generation: row.8,
        configuration_digest: digest_array(&row.9)?,
        jwks_generation: row.10,
        jwks_digest: digest_array(&row.11)?,
        enabled: row.12,
    })
}

fn validate_provider(input: &IdentityProviderWrite) -> Result<(), StoreError> {
    for (value, label, max) in [
        (&input.issuer, "issuer", 2048),
        (&input.audience, "audience", 512),
        (
            &input.authorization_endpoint,
            "authorization endpoint",
            2048,
        ),
        (&input.token_endpoint, "token endpoint", 2048),
        (&input.jwks_uri, "JWKS URI", 2048),
        (&input.client_id, "client ID", 512),
        (&input.group_claim, "group claim", 128),
        (&input.actor_subject, "actor subject", 512),
    ] {
        validate_canonical(value, label, max)?;
    }
    if input.configuration_generation <= 0 || input.jwks_generation <= 0 {
        return invalid("identity provider generations must be positive");
    }
    Ok(())
}

fn validate_service_credential(input: &NewServiceCredential) -> Result<(), StoreError> {
    validate_canonical(&input.actor_subject, "actor subject", 512)?;
    if input.generation <= 0 || input.issued_at_unix_ms < 0 {
        return invalid("service credential generation or timestamp is invalid");
    }
    if input
        .expires_at_unix_ms
        .is_some_and(|value| value <= input.issued_at_unix_ms)
    {
        return invalid("service credential expiry must follow issuance");
    }
    Ok(())
}

async fn provision_identity_provider_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &IdentityProviderWrite,
) -> Result<IdentityProviderConfig, StoreError> {
    let current = sqlx::query_as::<_, ProviderRow>(
        "SELECT provider_id, issuer, audience, authorization_endpoint,
                token_endpoint, jwks_uri, client_id, group_claim,
                configuration_generation, configuration_digest,
                jwks_generation, jwks_digest, enabled
         FROM identity_providers
         WHERE organization_id = $1 AND provider_id = $2
         FOR UPDATE",
    )
    .bind(input.organization_id)
    .bind(input.provider_id)
    .fetch_optional(&mut **tx)
    .await?;

    if let Some(current) = current {
        let current = provider_from_row(current)?;
        if current == provider_from_write(input) {
            return Ok(current);
        }
        if input.issuer != current.issuer {
            return Err(StoreError::IdentityConflict(
                "an identity-provider issuer is immutable; replacement requires a new provider and reviewed identity mappings"
                    .to_owned(),
            ));
        }
        if input.configuration_generation != current.configuration_generation + 1
            || input.jwks_generation < current.jwks_generation
        {
            return Err(StoreError::IdentityConflict(
                "identity-provider generations must advance exactly and never regress".to_owned(),
            ));
        }
        sqlx::query(
            "UPDATE identity_providers
             SET issuer = $3, audience = $4, authorization_endpoint = $5,
                 token_endpoint = $6, jwks_uri = $7, client_id = $8,
                 group_claim = $9, configuration_generation = $10,
                 configuration_digest = $11, jwks_generation = $12,
                 jwks_digest = $13, enabled = $14,
                 updated_at = clock_timestamp()
             WHERE organization_id = $1 AND provider_id = $2",
        )
        .bind(input.organization_id)
        .bind(input.provider_id)
        .bind(&input.issuer)
        .bind(&input.audience)
        .bind(&input.authorization_endpoint)
        .bind(&input.token_endpoint)
        .bind(&input.jwks_uri)
        .bind(&input.client_id)
        .bind(&input.group_claim)
        .bind(input.configuration_generation)
        .bind(input.configuration_digest.as_slice())
        .bind(input.jwks_generation)
        .bind(input.jwks_digest.as_slice())
        .bind(input.enabled)
        .execute(&mut **tx)
        .await?;
    } else {
        if input.configuration_generation != 1 || input.jwks_generation != 1 {
            return Err(StoreError::IdentityConflict(
                "a new identity provider must begin at generation one".to_owned(),
            ));
        }
        sqlx::query(
            "INSERT INTO identity_providers(
                 organization_id, provider_id, issuer, audience,
                 authorization_endpoint, token_endpoint, jwks_uri, client_id,
                 group_claim, configuration_generation, configuration_digest,
                 jwks_generation, jwks_digest, enabled
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(input.organization_id)
        .bind(input.provider_id)
        .bind(&input.issuer)
        .bind(&input.audience)
        .bind(&input.authorization_endpoint)
        .bind(&input.token_endpoint)
        .bind(&input.jwks_uri)
        .bind(&input.client_id)
        .bind(&input.group_claim)
        .bind(input.configuration_generation)
        .bind(input.configuration_digest.as_slice())
        .bind(input.jwks_generation)
        .bind(input.jwks_digest.as_slice())
        .bind(input.enabled)
        .execute(&mut **tx)
        .await?;
    }

    append_audit_record(
        tx,
        input.organization_id,
        "identity",
        &input.actor_subject,
        "identity_provider_provisioned",
        &format!("identity-provider:{}", input.provider_id),
        json!({
            "configuration_generation": input.configuration_generation,
            "configuration_digest": hex::encode(input.configuration_digest),
            "jwks_generation": input.jwks_generation,
            "jwks_digest": hex::encode(input.jwks_digest),
            "enabled": input.enabled,
        }),
    )
    .await?;
    Ok(provider_from_write(input))
}

async fn provision_service_credential_in_transaction(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    input: &NewServiceCredential,
) -> Result<ServiceCredential, StoreError> {
    let existing = sqlx::query_as::<_, (Uuid, Uuid, i64, Vec<u8>, i64, Option<i64>, Option<i64>)>(
        "SELECT credential_id, identity_id, generation, token_digest, issued_at_unix_ms,
                    expires_at_unix_ms, revoked_at_unix_ms
             FROM service_credentials
             WHERE organization_id = $1 AND (credential_id = $2 OR token_digest = $3)",
    )
    .bind(input.organization_id)
    .bind(input.credential_id)
    .bind(input.token_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(existing) = existing {
        if existing.0 == input.credential_id
            && existing.1 == input.identity_id
            && existing.2 == input.generation
            && existing.3.as_slice() == input.token_digest
            && existing.5 == input.expires_at_unix_ms
            && existing.6.is_none()
        {
            return Ok(ServiceCredential {
                credential_id: existing.0,
                identity_id: existing.1,
                generation: existing.2,
                issued_at_unix_ms: existing.4,
                expires_at_unix_ms: existing.5,
                revoked_at_unix_ms: existing.6,
            });
        }
        return Err(StoreError::IdentityConflict(
            "service credential collides with an existing binding".to_owned(),
        ));
    }
    let identity = sqlx::query_as::<_, (String, String)>(
        "SELECT kind, lifecycle_state FROM identities
         WHERE organization_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(input.organization_id)
    .bind(input.identity_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| StoreError::IdentityConflict("service identity is unknown".to_owned()))?;
    if identity.0 != "service" || identity.1 != "active" {
        return Err(StoreError::IdentityConflict(
            "service credential requires an active service identity".to_owned(),
        ));
    }
    let next_generation = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(max(generation), 0) + 1 FROM service_credentials
         WHERE organization_id = $1 AND identity_id = $2",
    )
    .bind(input.organization_id)
    .bind(input.identity_id)
    .fetch_one(&mut **tx)
    .await?;
    if input.generation != next_generation {
        return Err(StoreError::IdentityConflict(
            "service credential generation must advance exactly".to_owned(),
        ));
    }
    reject_credential_digest_collision(tx, input.organization_id, &input.token_digest).await?;
    sqlx::query(
        "INSERT INTO service_credentials(
             organization_id, credential_id, identity_id, generation,
             token_digest, issued_at_unix_ms, expires_at_unix_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(input.organization_id)
    .bind(input.credential_id)
    .bind(input.identity_id)
    .bind(input.generation)
    .bind(input.token_digest.as_slice())
    .bind(input.issued_at_unix_ms)
    .bind(input.expires_at_unix_ms)
    .execute(&mut **tx)
    .await?;
    let superseded = sqlx::query(
        "UPDATE service_credentials
         SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $4),
             revocation_reason = 'superseded_generation'
         WHERE organization_id = $1 AND identity_id = $2
           AND credential_id <> $3 AND revoked_at_unix_ms IS NULL",
    )
    .bind(input.organization_id)
    .bind(input.identity_id)
    .bind(input.credential_id)
    .bind(input.issued_at_unix_ms)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    append_audit_record(
        tx,
        input.organization_id,
        "identity",
        &input.actor_subject,
        "service_credential_provisioned",
        &format!("service-credential:{}", input.credential_id),
        json!({
            "identity_id": input.identity_id,
            "generation": input.generation,
            "superseded_credentials": superseded,
        }),
    )
    .await?;
    Ok(ServiceCredential {
        credential_id: input.credential_id,
        identity_id: input.identity_id,
        generation: input.generation,
        issued_at_unix_ms: input.issued_at_unix_ms,
        expires_at_unix_ms: input.expires_at_unix_ms,
        revoked_at_unix_ms: None,
    })
}

async fn load_principal(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    identity_id: Uuid,
    subject: &str,
    kind: &str,
) -> Result<Principal, StoreError> {
    let project_rows = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT project_id, role FROM project_memberships
         WHERE organization_id = $1 AND identity_id = $2 ORDER BY project_id",
    )
    .bind(organization_id)
    .bind(identity_id)
    .fetch_all(&mut **tx)
    .await?;
    let scope_rows = sqlx::query_scalar::<_, String>(
        "SELECT scope FROM service_scopes
         WHERE organization_id = $1 AND identity_id = $2 ORDER BY scope",
    )
    .bind(organization_id)
    .bind(identity_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut project_roles = BTreeMap::new();
    for (project_id, role) in project_rows {
        project_roles.insert(project_id, parse_role(&role)?);
    }
    let mut service_scopes = BTreeSet::new();
    for scope in scope_rows {
        service_scopes.insert(parse_scope(&scope)?);
    }
    let kind = match kind {
        "human" => PrincipalKind::Human,
        "service" => PrincipalKind::Service,
        _ => return invalid("identity kind is unknown"),
    };
    Ok(Principal {
        subject: subject.to_owned(),
        kind,
        organization_id,
        project_roles,
        service_scopes,
    })
}

async fn prune_identity_security_history(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    now_unix_ms: i64,
) -> Result<(), StoreError> {
    let cutoff = now_unix_ms.saturating_sub(IDENTITY_HISTORY_RETENTION_MS);
    sqlx::query(
        "DELETE FROM oidc_token_replays
         WHERE organization_id = $1 AND expires_at_unix_ms < $2",
    )
    .bind(organization_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM identity_sessions
         WHERE organization_id = $1
           AND COALESCE(revoked_at_unix_ms, expires_at_unix_ms) < $2
           AND COALESCE(refresh_expires_at_unix_ms, expires_at_unix_ms) < $2",
    )
    .bind(organization_id)
    .bind(cutoff)
    .execute(&mut **tx)
    .await?;
    sqlx::query(
        "DELETE FROM identity_group_snapshots snapshots
         USING identities identity
         WHERE snapshots.organization_id = $1
           AND identity.organization_id = snapshots.organization_id
           AND identity.id = snapshots.identity_id
           AND snapshots.generation <= identity.group_generation - $2",
    )
    .bind(organization_id)
    .bind(RETAINED_GROUP_GENERATIONS)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn lock_identity_provisioning(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("mcloving.identity-provisioning.{organization_id}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn revoke_session_family_on_refresh_reuse(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    refresh_token_digest: &[u8; 32],
    now_unix_ms: i64,
) -> Result<(), StoreError> {
    let Some(family_id) =
        session_family_for_refresh_digest(tx, organization_id, refresh_token_digest).await?
    else {
        return Ok(());
    };
    lock_session_family(tx, organization_id, family_id).await?;
    let stale = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT s.identity_id, i.subject, s.revocation_reason
         FROM identity_sessions s
         JOIN identities i ON i.organization_id = s.organization_id
                          AND i.id = s.identity_id
         WHERE s.organization_id = $1 AND s.refresh_token_digest = $2
         FOR UPDATE OF s",
    )
    .bind(organization_id)
    .bind(refresh_token_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?;
    let Some((identity_id, subject, revocation_reason)) = stale else {
        return Ok(());
    };
    if revocation_reason.as_deref() != Some("refresh_rotation") {
        return Ok(());
    }
    let revoked = sqlx::query(
        "UPDATE identity_sessions
         SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $3),
             revocation_reason = 'refresh_reuse_detected'
         WHERE organization_id = $1 AND family_id = $2
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(organization_id)
    .bind(family_id)
    .bind(now_unix_ms)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    append_audit_record(
        tx,
        organization_id,
        "authentication",
        &subject,
        "oidc_refresh_reuse_detected",
        &format!("identity-session-family:{family_id}"),
        json!({
            "identity_id": identity_id,
            "session_family_id": family_id,
            "revoked_sessions": revoked,
            "detected_at_unix_ms": now_unix_ms,
        }),
    )
    .await?;
    Ok(())
}

async fn session_family_for_refresh_digest(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    refresh_token_digest: &[u8; 32],
) -> Result<Option<Uuid>, StoreError> {
    Ok(sqlx::query_scalar::<_, Uuid>(
        "SELECT family_id
         FROM identity_sessions
         WHERE organization_id = $1 AND refresh_token_digest = $2",
    )
    .bind(organization_id)
    .bind(refresh_token_digest.as_slice())
    .fetch_optional(&mut **tx)
    .await?)
}

async fn lock_session_family(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    family_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "mcloving.identity-session-family.{organization_id}.{family_id}"
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn reject_credential_digest_collision(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    organization_id: Uuid,
    digest: &[u8; 32],
) -> Result<(), StoreError> {
    let collision = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM identity_sessions WHERE organization_id = $1 AND token_digest = $2)
             OR EXISTS(SELECT 1 FROM identity_sessions WHERE organization_id = $1 AND refresh_token_digest = $2)
             OR EXISTS(SELECT 1 FROM service_credentials WHERE organization_id = $1 AND token_digest = $2)",
    )
    .bind(organization_id)
    .bind(digest.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    if collision {
        return Err(StoreError::IdentityConflict(
            "credential digest is already bound".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn revoke_credential_record(
    store: &Store,
    organization_id: Uuid,
    table: &str,
    key_column: &str,
    record_id: Uuid,
    now_unix_ms: i64,
    reason: &str,
    actor_subject: &str,
    action: &str,
) -> Result<bool, StoreError> {
    validate_canonical(reason, "revocation reason", 256)?;
    validate_canonical(actor_subject, "actor subject", 512)?;
    if now_unix_ms < 0 {
        return invalid("revocation timestamp is invalid");
    }
    let mut tx = store.tenant_transaction(organization_id).await?;
    let query = format!(
        "UPDATE {table}
         SET revoked_at_unix_ms = GREATEST(issued_at_unix_ms, $3), revocation_reason = $4
         WHERE organization_id = $1 AND {key_column} = $2 AND revoked_at_unix_ms IS NULL"
    );
    let changed = sqlx::query(&query)
        .bind(organization_id)
        .bind(record_id)
        .bind(now_unix_ms)
        .bind(reason)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 1;
    if changed {
        append_audit_record(
            &mut tx,
            organization_id,
            "authentication",
            actor_subject,
            action,
            &format!("credential:{record_id}"),
            json!({"reason": reason, "revoked_at_unix_ms": now_unix_ms}),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(changed)
}

fn canonical_strings(values: &[String], label: &str) -> Result<Vec<String>, StoreError> {
    if values.len() > MAX_GROUPS {
        return invalid("identity string set exceeds its bounded size");
    }
    let mut canonical = BTreeSet::new();
    for value in values {
        validate_canonical(value, label, 512)?;
        if !canonical.insert(value.clone()) {
            return Err(StoreError::InvalidIdentityOperation(format!(
                "{label} values must be unique"
            )));
        }
    }
    Ok(canonical.into_iter().collect())
}

fn digest_strings(values: &[String]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"mcloving.identity.string-set.v1\0");
    for value in values {
        hash.update(value.len().to_be_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().into()
}

fn digest_array(value: &[u8]) -> Result<[u8; 32], StoreError> {
    value.try_into().map_err(|_| {
        StoreError::InvalidIdentityOperation("identity digest has an invalid length".to_owned())
    })
}

fn validate_canonical(value: &str, label: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max || value.trim() != value || value.contains('\0') {
        return Err(StoreError::InvalidIdentityOperation(format!(
            "{label} is empty, non-canonical, or too long"
        )));
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, StoreError> {
    Err(StoreError::InvalidIdentityOperation(message.to_owned()))
}

fn scope_name(scope: ServiceScope) -> &'static str {
    match scope {
        ServiceScope::ProjectRead => "project_read",
        ServiceScope::BuildSubmit => "build_submit",
        ServiceScope::BuildCancel => "build_cancel",
        ServiceScope::SecretUse => "secret_use",
        ServiceScope::ProjectAdmin => "project_admin",
        ServiceScope::AuditRead => "audit_read",
        ServiceScope::SchedulerControl => "scheduler_control",
    }
}

fn parse_scope(value: &str) -> Result<ServiceScope, StoreError> {
    match value {
        "project_read" => Ok(ServiceScope::ProjectRead),
        "build_submit" => Ok(ServiceScope::BuildSubmit),
        "build_cancel" => Ok(ServiceScope::BuildCancel),
        "secret_use" => Ok(ServiceScope::SecretUse),
        "project_admin" => Ok(ServiceScope::ProjectAdmin),
        "audit_read" => Ok(ServiceScope::AuditRead),
        "scheduler_control" => Ok(ServiceScope::SchedulerControl),
        _ => invalid("service scope is unknown"),
    }
}

fn parse_role(value: &str) -> Result<ProjectRole, StoreError> {
    match value {
        "viewer" => Ok(ProjectRole::Viewer),
        "developer" => Ok(ProjectRole::Developer),
        "admin" => Ok(ProjectRole::Admin),
        "owner" => Ok(ProjectRole::Owner),
        _ => invalid("project role is unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_digest_is_order_independent_after_canonicalization() {
        let left = canonical_strings(&["ops".to_owned(), "dev".to_owned()], "group").unwrap();
        let right = canonical_strings(&["dev".to_owned(), "ops".to_owned()], "group").unwrap();
        assert_eq!(left, right);
        assert_eq!(digest_strings(&left), digest_strings(&right));
    }

    #[test]
    fn aliases_and_groups_reject_duplicates_and_noncanonical_values() {
        assert!(canonical_strings(&["ops".to_owned(), "ops".to_owned()], "group").is_err());
        assert!(canonical_strings(&[" ops".to_owned()], "group").is_err());
    }
}
