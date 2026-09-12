//! Human project roles (PAR-003): who may grant and revoke a project role,
//! and what a revocation does to the identity's live sessions.
//!
//! Two authorities write memberships. The offline admin tool, under the
//! migration role, bootstraps a project's first Owner and may grant or
//! revoke any role; it is the only way an Owner appears in a project that
//! has none. A project principal acting through the API needs Admin or
//! better in the project, and Owner to grant Owner, to change an Owner's
//! role or to revoke an Owner. The last Owner of a project cannot be
//! revoked or demoted by either authority. A revocation or a demotion bumps
//! the identity's lifecycle generation, so every session issued under the
//! old generation stops authenticating at once, the fence a lifecycle
//! transition applies. Every change is one audit record.

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::audit::append_audit_record;
use super::authz::ProjectRole;
use super::{Store, StoreError};

/// Who is writing the membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipAuthority {
    /// The offline admin tool under the migration role: may bootstrap the
    /// first Owner and manage any role.
    Bootstrap,
    /// A human principal through the API, named by identity and by the
    /// lifecycle generation its bearer authenticated under. Its role in the
    /// project is read again under the membership lock, so a demotion,
    /// revocation or fence that committed after authentication is seen.
    Principal {
        identity_id: Uuid,
        lifecycle_generation: i64,
    },
    /// A service principal, or a mapped-policy principal, that passed the
    /// project's configure action: acts as an Admin and never as an Owner.
    Delegated,
}

/// The authority's role in the project as resolved under the lock: `None`
/// for the admin tool, which is not bounded by a role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResolvedAuthority {
    kind: &'static str,
    role: Option<ProjectRole>,
    identity_id: Option<Uuid>,
}

impl MembershipAuthority {
    async fn resolve(
        self,
        tx: &mut Transaction<'_, Postgres>,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<ResolvedAuthority, StoreError> {
        match self {
            Self::Bootstrap => Ok(ResolvedAuthority {
                kind: "bootstrap",
                role: None,
                identity_id: None,
            }),
            Self::Delegated => Ok(ResolvedAuthority {
                kind: "delegated",
                role: Some(ProjectRole::Admin),
                identity_id: None,
            }),
            Self::Principal {
                identity_id,
                lifecycle_generation,
            } => {
                let current = sqlx::query_scalar::<_, i64>(
                    "SELECT lifecycle_generation FROM identities
                     WHERE organization_id = $1 AND id = $2 AND lifecycle_state = 'active'",
                )
                .bind(organization_id)
                .bind(identity_id)
                .fetch_optional(&mut **tx)
                .await?;
                if current != Some(lifecycle_generation) {
                    return denied(
                        "the caller's session was fenced after it authenticated; sign in again",
                    );
                }
                let role = current_role(tx, organization_id, project_id, identity_id).await?;
                let Some(role) = role else {
                    return denied("the caller holds no role in the project");
                };
                Ok(ResolvedAuthority {
                    kind: "principal",
                    role: Some(role),
                    identity_id: Some(identity_id),
                })
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRoleGrant<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub identity_id: Uuid,
    pub role: ProjectRole,
    pub authority: MembershipAuthority,
    pub actor_subject: &'a str,
    pub reason: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRoleRevocation<'a> {
    pub organization_id: Uuid,
    pub project_id: Uuid,
    pub identity_id: Uuid,
    pub authority: MembershipAuthority,
    pub actor_subject: &'a str,
    pub reason: &'a str,
}

/// One membership row as recorded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectMembership {
    pub identity_id: Uuid,
    pub project_id: Uuid,
    pub subject: String,
    pub role: ProjectRole,
    pub granted_by: String,
    pub granted_at_unix_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectRoleGrantOutcome {
    /// A new membership.
    Granted(ProjectMembership),
    /// An existing membership's role changed; a demotion fenced the
    /// identity's sessions and reports the new lifecycle generation.
    Changed {
        membership: ProjectMembership,
        previous: ProjectRole,
        fenced_generation: Option<i64>,
    },
    /// The membership already carried this role; nothing was written.
    Unchanged(ProjectMembership),
}

impl ProjectRoleGrantOutcome {
    pub fn membership(&self) -> &ProjectMembership {
        match self {
            Self::Granted(membership)
            | Self::Changed { membership, .. }
            | Self::Unchanged(membership) => membership,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectRoleRevocationOutcome {
    pub identity_id: Uuid,
    pub project_id: Uuid,
    pub previous: ProjectRole,
    /// The identity's lifecycle generation after the fence; sessions issued
    /// under an earlier generation no longer authenticate.
    pub fenced_generation: i64,
}

impl ProjectRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Developer => "developer",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "developer" => Ok(Self::Developer),
            "admin" => Ok(Self::Admin),
            "owner" => Ok(Self::Owner),
            _ => Err(StoreError::InvalidIdentityOperation(
                "project role is unknown".to_owned(),
            )),
        }
    }
}

impl Serialize for ProjectRole {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProjectRole {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(|_| {
            serde::de::Error::custom("project role must be viewer, developer, admin or owner")
        })
    }
}

impl Store {
    /// Grants a project role, or changes the role an identity already holds.
    pub async fn grant_project_role(
        &self,
        grant: &ProjectRoleGrant<'_>,
    ) -> Result<ProjectRoleGrantOutcome, StoreError> {
        validate_text(grant.actor_subject, "actor subject", 512)?;
        validate_text(grant.reason, "project role reason", 1024)?;
        let mut tx = self.tenant_transaction(grant.organization_id).await?;
        lock_project_memberships(&mut tx, grant.organization_id, grant.project_id).await?;
        require_project(&mut tx, grant.organization_id, grant.project_id).await?;
        let subject =
            require_human_identity(&mut tx, grant.organization_id, grant.identity_id).await?;
        let owners = owner_count(&mut tx, grant.organization_id, grant.project_id).await?;
        let previous = current_role(
            &mut tx,
            grant.organization_id,
            grant.project_id,
            grant.identity_id,
        )
        .await?;
        let authority = grant
            .authority
            .resolve(&mut tx, grant.organization_id, grant.project_id)
            .await?;
        if let Some(actor_role) = authority.role {
            if actor_role < ProjectRole::Admin {
                return denied("granting a project role needs the Admin role or better");
            }
            if grant.role == ProjectRole::Owner && owners == 0 {
                return denied(
                    "a project's first Owner is bootstrapped through the identity admin tool, not the API",
                );
            }
            if (grant.role == ProjectRole::Owner || previous == Some(ProjectRole::Owner))
                && actor_role != ProjectRole::Owner
            {
                return denied("only an Owner may grant Owner or change an Owner's role");
            }
        }
        let now_unix_ms = database_unix_ms(&mut tx).await?;
        let membership =
            |role: ProjectRole, granted_by: String, granted_at_unix_ms: i64| ProjectMembership {
                identity_id: grant.identity_id,
                project_id: grant.project_id,
                subject: subject.clone(),
                role,
                granted_by,
                granted_at_unix_ms,
            };
        match previous {
            Some(existing) if existing == grant.role => {
                let (granted_by, granted_at_unix_ms) = sqlx::query_as::<_, (String, i64)>(
                    "SELECT granted_by, granted_at_unix_ms FROM project_memberships
                     WHERE organization_id = $1 AND project_id = $2 AND identity_id = $3",
                )
                .bind(grant.organization_id)
                .bind(grant.project_id)
                .bind(grant.identity_id)
                .fetch_one(&mut *tx)
                .await?;
                tx.commit().await?;
                Ok(ProjectRoleGrantOutcome::Unchanged(membership(
                    existing,
                    granted_by,
                    granted_at_unix_ms,
                )))
            }
            Some(existing) => {
                if existing == ProjectRole::Owner && owners <= 1 {
                    return denied("the last Owner of a project cannot be demoted");
                }
                sqlx::query(
                    "UPDATE project_memberships
                     SET role = $4, granted_by = $5, granted_at_unix_ms = $6
                     WHERE organization_id = $1 AND project_id = $2 AND identity_id = $3",
                )
                .bind(grant.organization_id)
                .bind(grant.project_id)
                .bind(grant.identity_id)
                .bind(grant.role.as_str())
                .bind(grant.actor_subject)
                .bind(now_unix_ms)
                .execute(&mut *tx)
                .await?;
                let fenced_generation = if grant.role < existing {
                    Some(
                        fence_identity_sessions(&mut tx, grant.organization_id, grant.identity_id)
                            .await?,
                    )
                } else {
                    None
                };
                append_audit_record(
                    &mut tx,
                    grant.organization_id,
                    "identity",
                    grant.actor_subject,
                    "project_role_changed",
                    &format!("identity:{}", grant.identity_id),
                    json!({
                        "project_id": grant.project_id,
                        "role": grant.role,
                        "previous_role": existing,
                        "authority": authority.kind,
                        "actor_role": authority.role,
                        "actor_identity_id": authority.identity_id,
                        "fenced_generation": fenced_generation,
                        "reason": grant.reason,
                    }),
                )
                .await?;
                tx.commit().await?;
                Ok(ProjectRoleGrantOutcome::Changed {
                    membership: membership(grant.role, grant.actor_subject.to_owned(), now_unix_ms),
                    previous: existing,
                    fenced_generation,
                })
            }
            None => {
                sqlx::query(
                    "INSERT INTO project_memberships
                         (identity_id, organization_id, project_id, role, granted_by, granted_at_unix_ms)
                     VALUES ($3, $1, $2, $4, $5, $6)",
                )
                .bind(grant.organization_id)
                .bind(grant.project_id)
                .bind(grant.identity_id)
                .bind(grant.role.as_str())
                .bind(grant.actor_subject)
                .bind(now_unix_ms)
                .execute(&mut *tx)
                .await?;
                append_audit_record(
                    &mut tx,
                    grant.organization_id,
                    "identity",
                    grant.actor_subject,
                    "project_role_granted",
                    &format!("identity:{}", grant.identity_id),
                    json!({
                        "project_id": grant.project_id,
                        "role": grant.role,
                        "authority": authority.kind,
                        "actor_role": authority.role,
                        "actor_identity_id": authority.identity_id,
                        "bootstrap_owner": grant.role == ProjectRole::Owner && owners == 0,
                        "reason": grant.reason,
                    }),
                )
                .await?;
                tx.commit().await?;
                Ok(ProjectRoleGrantOutcome::Granted(membership(
                    grant.role,
                    grant.actor_subject.to_owned(),
                    now_unix_ms,
                )))
            }
        }
    }

    /// Revokes an identity's project role and fences its live sessions.
    pub async fn revoke_project_role(
        &self,
        revocation: &ProjectRoleRevocation<'_>,
    ) -> Result<ProjectRoleRevocationOutcome, StoreError> {
        validate_text(revocation.actor_subject, "actor subject", 512)?;
        validate_text(revocation.reason, "project role reason", 1024)?;
        let mut tx = self.tenant_transaction(revocation.organization_id).await?;
        lock_project_memberships(&mut tx, revocation.organization_id, revocation.project_id)
            .await?;
        require_project(&mut tx, revocation.organization_id, revocation.project_id).await?;
        let previous = current_role(
            &mut tx,
            revocation.organization_id,
            revocation.project_id,
            revocation.identity_id,
        )
        .await?
        .ok_or_else(|| {
            StoreError::IdentityConflict("identity holds no role in the project".to_owned())
        })?;
        let authority = revocation
            .authority
            .resolve(&mut tx, revocation.organization_id, revocation.project_id)
            .await?;
        if let Some(actor_role) = authority.role {
            if actor_role < ProjectRole::Admin {
                return denied("revoking a project role needs the Admin role or better");
            }
            if previous == ProjectRole::Owner && actor_role != ProjectRole::Owner {
                return denied("only an Owner may revoke an Owner");
            }
        }
        if previous == ProjectRole::Owner {
            let owners =
                owner_count(&mut tx, revocation.organization_id, revocation.project_id).await?;
            if owners <= 1 {
                return denied("the last Owner of a project cannot be revoked");
            }
        }
        sqlx::query(
            "DELETE FROM project_memberships
             WHERE organization_id = $1 AND project_id = $2 AND identity_id = $3",
        )
        .bind(revocation.organization_id)
        .bind(revocation.project_id)
        .bind(revocation.identity_id)
        .execute(&mut *tx)
        .await?;
        let fenced_generation =
            fence_identity_sessions(&mut tx, revocation.organization_id, revocation.identity_id)
                .await?;
        append_audit_record(
            &mut tx,
            revocation.organization_id,
            "identity",
            revocation.actor_subject,
            "project_role_revoked",
            &format!("identity:{}", revocation.identity_id),
            json!({
                "project_id": revocation.project_id,
                "previous_role": previous,
                "authority": authority.kind,
                "actor_role": authority.role,
                "actor_identity_id": authority.identity_id,
                "fenced_generation": fenced_generation,
                "reason": revocation.reason,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(ProjectRoleRevocationOutcome {
            identity_id: revocation.identity_id,
            project_id: revocation.project_id,
            previous,
            fenced_generation,
        })
    }

    /// The project's memberships, by subject.
    pub async fn project_memberships(
        &self,
        organization_id: Uuid,
        project_id: Uuid,
    ) -> Result<Vec<ProjectMembership>, StoreError> {
        let mut tx = self.tenant_transaction(organization_id).await?;
        require_project(&mut tx, organization_id, project_id).await?;
        let rows = sqlx::query_as::<_, (Uuid, String, String, String, i64)>(
            "SELECT m.identity_id, i.subject, m.role, m.granted_by, m.granted_at_unix_ms
             FROM project_memberships m
             JOIN identities i ON i.organization_id = m.organization_id AND i.id = m.identity_id
             WHERE m.organization_id = $1 AND m.project_id = $2
             ORDER BY i.subject, m.identity_id",
        )
        .bind(organization_id)
        .bind(project_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(
                |(identity_id, subject, role, granted_by, granted_at_unix_ms)| {
                    Ok(ProjectMembership {
                        identity_id,
                        project_id,
                        subject,
                        role: ProjectRole::parse(&role)?,
                        granted_by,
                        granted_at_unix_ms,
                    })
                },
            )
            .collect()
    }
}

fn denied<T>(message: &str) -> Result<T, StoreError> {
    Err(StoreError::ProjectRoleDenied(message.to_owned()))
}

fn validate_text(value: &str, label: &str, max: usize) -> Result<(), StoreError> {
    if value.is_empty() || value.len() > max || value.trim() != value || value.contains('\0') {
        return Err(StoreError::InvalidIdentityOperation(format!(
            "{label} is empty, non-canonical, or too long"
        )));
    }
    Ok(())
}

/// Every membership write for a project enters here first, so the Owner
/// count a decision reads cannot change under it.
async fn lock_project_memberships(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "mcloving.project-memberships.{organization_id}.{project_id}"
        ))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

async fn require_project(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<(), StoreError> {
    let exists = sqlx::query_scalar::<_, i32>(
        "SELECT 1 FROM projects WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_optional(&mut **tx)
    .await?;
    if exists.is_none() {
        return Err(StoreError::IdentityConflict(
            "project is unknown in the organization".to_owned(),
        ));
    }
    Ok(())
}

/// A role is held by a human identity of the organization that is not
/// deleted; answers its subject.
async fn require_human_identity(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    identity_id: Uuid,
) -> Result<String, StoreError> {
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT subject, kind, lifecycle_state FROM identities
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(identity_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| StoreError::IdentityConflict("identity is unknown".to_owned()))?;
    if row.1 != "human" {
        return Err(StoreError::IdentityConflict(
            "project roles are held by human identities; services carry scopes".to_owned(),
        ));
    }
    if row.2 == "deleted" {
        return Err(StoreError::IdentityConflict(
            "a deleted identity cannot hold a project role".to_owned(),
        ));
    }
    Ok(row.0)
}

async fn owner_count(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM project_memberships
         WHERE organization_id = $1 AND project_id = $2 AND role = 'owner'",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn current_role(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    project_id: Uuid,
    identity_id: Uuid,
) -> Result<Option<ProjectRole>, StoreError> {
    sqlx::query_scalar::<_, String>(
        "SELECT role FROM project_memberships
         WHERE organization_id = $1 AND project_id = $2 AND identity_id = $3",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(identity_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|role| ProjectRole::parse(&role))
    .transpose()
}

async fn database_unix_ms(tx: &mut Transaction<'_, Postgres>) -> Result<i64, StoreError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint",
    )
    .fetch_one(&mut **tx)
    .await?)
}

/// Bumps the identity's lifecycle generation, the fence a lifecycle
/// transition applies: every session issued under the previous generation
/// stops authenticating. Answers the new generation.
pub(crate) async fn fence_identity_sessions(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    identity_id: Uuid,
) -> Result<i64, StoreError> {
    let generation = sqlx::query_scalar::<_, i64>(
        "UPDATE identities
         SET lifecycle_generation = lifecycle_generation + 1, updated_at = clock_timestamp()
         WHERE organization_id = $1 AND id = $2
         RETURNING lifecycle_generation",
    )
    .bind(organization_id)
    .bind(identity_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| StoreError::IdentityConflict("identity is unknown".to_owned()))?;
    Ok(generation)
}
