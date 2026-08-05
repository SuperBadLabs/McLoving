use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

/// Authenticated principal class. Authentication alone grants nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrincipalKind {
    Human,
    Service,
}

/// Human project role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ProjectRole {
    Viewer,
    Developer,
    Admin,
    Owner,
}

/// Scoped authority available to a service identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ServiceScope {
    ProjectRead,
    BuildSubmit,
    BuildCancel,
    SecretUse,
    ProjectAdmin,
    AuditRead,
    SchedulerControl,
}

/// Central action vocabulary for controller authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Action {
    ProjectView,
    BuildTrigger,
    BuildCancel,
    ProjectConfigure,
    ApprovalAct,
    BuildRetry,
    ArtifactRead,
    ArtifactWrite,
    TestRead,
    LogRead,
    SecretUse,
    AuditRead,
    SchedulerControl,
}

impl Action {
    pub const MAPPABLE: [Self; 12] = [
        Self::ProjectView,
        Self::BuildTrigger,
        Self::BuildCancel,
        Self::ProjectConfigure,
        Self::ApprovalAct,
        Self::BuildRetry,
        Self::ArtifactRead,
        Self::ArtifactWrite,
        Self::TestRead,
        Self::LogRead,
        Self::SecretUse,
        Self::AuditRead,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectView => "project_view",
            Self::BuildTrigger => "build_trigger",
            Self::BuildCancel => "build_cancel",
            Self::ProjectConfigure => "project_configure",
            Self::ApprovalAct => "approval_act",
            Self::BuildRetry => "build_retry",
            Self::ArtifactRead => "artifact_read",
            Self::ArtifactWrite => "artifact_write",
            Self::TestRead => "test_read",
            Self::LogRead => "log_read",
            Self::SecretUse => "secret_use",
            Self::AuditRead => "audit_read",
            Self::SchedulerControl => "scheduler_control",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "project_view" => Some(Self::ProjectView),
            "build_trigger" => Some(Self::BuildTrigger),
            "build_cancel" => Some(Self::BuildCancel),
            "project_configure" => Some(Self::ProjectConfigure),
            "approval_act" => Some(Self::ApprovalAct),
            "build_retry" => Some(Self::BuildRetry),
            "artifact_read" => Some(Self::ArtifactRead),
            "artifact_write" => Some(Self::ArtifactWrite),
            "test_read" => Some(Self::TestRead),
            "log_read" => Some(Self::LogRead),
            "secret_use" => Some(Self::SecretUse),
            "audit_read" => Some(Self::AuditRead),
            "scheduler_control" => Some(Self::SchedulerControl),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantDecision {
    Allow,
    Deny,
}

impl GrantDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Fully authenticated identity and its already-loaded grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub subject: String,
    pub kind: PrincipalKind,
    pub organization_id: Uuid,
    pub project_roles: BTreeMap<Uuid, ProjectRole>,
    pub service_scopes: BTreeSet<ServiceScope>,
    /// Projects whose imported Jenkins policy disables role-lattice fallback.
    pub mapped_projects: BTreeSet<Uuid>,
    /// Current, provenance-valid action decisions for imported project policy.
    pub action_grants: BTreeMap<(Uuid, Action), GrantDecision>,
}

/// Auditable authorization success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationGrant {
    pub subject: String,
    pub organization_id: Uuid,
    pub project_id: Option<Uuid>,
    pub action: Action,
}

/// Stable deny reason; callers must not infer permission from authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationDenied {
    #[error("resource belongs to another organization")]
    TenantMismatch,
    #[error("the action requires a project-scoped resource")]
    ProjectRequired,
    #[error("the authenticated principal has no matching grant")]
    NoMatchingGrant,
}

/// Deny-by-default policy engine used by every controller surface.
pub fn authorize(
    principal: &Principal,
    resource_organization_id: Uuid,
    resource_project_id: Option<Uuid>,
    action: Action,
) -> Result<AuthorizationGrant, AuthorizationDenied> {
    if principal.organization_id != resource_organization_id {
        return Err(AuthorizationDenied::TenantMismatch);
    }
    if !matches!(action, Action::SchedulerControl | Action::AuditRead)
        && resource_project_id.is_none()
    {
        return Err(AuthorizationDenied::ProjectRequired);
    }

    let allowed = if let Some(project_id) = resource_project_id
        && principal.mapped_projects.contains(&project_id)
    {
        matches!(
            principal.action_grants.get(&(project_id, action)),
            Some(GrantDecision::Allow)
        )
    } else {
        match principal.kind {
            PrincipalKind::Service => service_allows(principal, action),
            PrincipalKind::Human => human_allows(principal, resource_project_id, action)?,
        }
    };
    if !allowed {
        return Err(AuthorizationDenied::NoMatchingGrant);
    }

    Ok(AuthorizationGrant {
        subject: principal.subject.clone(),
        organization_id: resource_organization_id,
        project_id: resource_project_id,
        action,
    })
}

fn service_allows(principal: &Principal, action: Action) -> bool {
    let required = match action {
        Action::ProjectView | Action::ArtifactRead | Action::TestRead | Action::LogRead => {
            ServiceScope::ProjectRead
        }
        Action::BuildTrigger | Action::BuildRetry | Action::ArtifactWrite => {
            ServiceScope::BuildSubmit
        }
        Action::BuildCancel => ServiceScope::BuildCancel,
        Action::ProjectConfigure | Action::ApprovalAct => ServiceScope::ProjectAdmin,
        Action::SecretUse => ServiceScope::SecretUse,
        Action::AuditRead => ServiceScope::AuditRead,
        Action::SchedulerControl => ServiceScope::SchedulerControl,
    };
    principal.service_scopes.contains(&required)
}

fn human_allows(
    principal: &Principal,
    project_id: Option<Uuid>,
    action: Action,
) -> Result<bool, AuthorizationDenied> {
    if matches!(action, Action::SchedulerControl | Action::AuditRead) {
        return Ok(false);
    }
    let project_id = project_id.ok_or(AuthorizationDenied::ProjectRequired)?;
    let Some(role) = principal.project_roles.get(&project_id) else {
        return Ok(false);
    };
    Ok(match action {
        Action::ProjectView | Action::ArtifactRead | Action::TestRead | Action::LogRead => true,
        Action::BuildTrigger | Action::BuildCancel | Action::BuildRetry | Action::ArtifactWrite => {
            *role >= ProjectRole::Developer
        }
        Action::SecretUse | Action::ProjectConfigure | Action::ApprovalAct => {
            *role >= ProjectRole::Admin
        }
        Action::AuditRead | Action::SchedulerControl => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn human(role: ProjectRole, organization_id: Uuid, project_id: Uuid) -> Principal {
        Principal {
            subject: "oidc:person".into(),
            kind: PrincipalKind::Human,
            organization_id,
            project_roles: [(project_id, role)].into(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        }
    }

    #[test]
    fn authentication_without_a_project_grant_is_denied() {
        let organization_id = Uuid::new_v4();
        let principal = Principal {
            subject: "oidc:person".into(),
            kind: PrincipalKind::Human,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        assert_eq!(
            authorize(
                &principal,
                organization_id,
                Some(Uuid::new_v4()),
                Action::ProjectView
            ),
            Err(AuthorizationDenied::NoMatchingGrant)
        );
    }

    #[test]
    fn cross_tenant_substitution_is_denied_before_role_evaluation() {
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let principal = human(ProjectRole::Owner, organization_id, project_id);
        assert_eq!(
            authorize(
                &principal,
                Uuid::new_v4(),
                Some(project_id),
                Action::ProjectConfigure
            ),
            Err(AuthorizationDenied::TenantMismatch)
        );
    }

    #[test]
    fn human_role_matrix_is_least_privilege() {
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let viewer = human(ProjectRole::Viewer, organization_id, project_id);
        assert!(
            authorize(
                &viewer,
                organization_id,
                Some(project_id),
                Action::ProjectView
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                &viewer,
                organization_id,
                Some(project_id),
                Action::BuildTrigger
            ),
            Err(AuthorizationDenied::NoMatchingGrant)
        );
    }

    #[test]
    fn scheduler_control_requires_an_explicit_service_scope() {
        let organization_id = Uuid::new_v4();
        let mut principal = Principal {
            subject: "service:scheduler".into(),
            kind: PrincipalKind::Service,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: BTreeSet::new(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        assert_eq!(
            authorize(&principal, organization_id, None, Action::SchedulerControl),
            Err(AuthorizationDenied::NoMatchingGrant)
        );
        principal
            .service_scopes
            .insert(ServiceScope::SchedulerControl);
        assert!(authorize(&principal, organization_id, None, Action::SchedulerControl).is_ok());
    }

    #[test]
    fn project_scoped_service_actions_require_a_project() {
        let organization_id = Uuid::new_v4();
        let principal = Principal {
            subject: "service:submitter".into(),
            kind: PrincipalKind::Service,
            organization_id,
            project_roles: BTreeMap::new(),
            service_scopes: [
                ServiceScope::ProjectRead,
                ServiceScope::BuildSubmit,
                ServiceScope::BuildCancel,
                ServiceScope::SecretUse,
                ServiceScope::ProjectAdmin,
            ]
            .into(),
            mapped_projects: BTreeSet::new(),
            action_grants: BTreeMap::new(),
        };
        for action in [
            Action::ProjectView,
            Action::BuildTrigger,
            Action::BuildCancel,
            Action::ProjectConfigure,
            Action::ApprovalAct,
            Action::BuildRetry,
            Action::ArtifactRead,
            Action::ArtifactWrite,
            Action::TestRead,
            Action::LogRead,
            Action::SecretUse,
        ] {
            assert_eq!(
                authorize(&principal, organization_id, None, action),
                Err(AuthorizationDenied::ProjectRequired)
            );
        }
    }

    #[test]
    fn mapped_policy_disables_lattice_fallback_and_honors_explicit_decisions() {
        let organization_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let mut principal = human(ProjectRole::Owner, organization_id, project_id);
        principal.mapped_projects.insert(project_id);
        principal
            .action_grants
            .insert((project_id, Action::ProjectView), GrantDecision::Allow);
        principal
            .action_grants
            .insert((project_id, Action::BuildTrigger), GrantDecision::Deny);
        assert!(
            authorize(
                &principal,
                organization_id,
                Some(project_id),
                Action::ProjectView
            )
            .is_ok()
        );
        for action in [Action::BuildTrigger, Action::ProjectConfigure] {
            assert_eq!(
                authorize(&principal, organization_id, Some(project_id), action),
                Err(AuthorizationDenied::NoMatchingGrant)
            );
        }
    }
}
