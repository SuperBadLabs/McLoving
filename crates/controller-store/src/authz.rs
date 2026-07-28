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
    SchedulerControl,
}

/// Central action vocabulary for controller authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    ProjectRead,
    BuildSubmit,
    BuildCancel,
    SecretUse,
    ProjectAdmin,
    SchedulerControl,
}

/// Fully authenticated identity and its already-loaded grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    pub subject: String,
    pub kind: PrincipalKind,
    pub organization_id: Uuid,
    pub project_roles: BTreeMap<Uuid, ProjectRole>,
    pub service_scopes: BTreeSet<ServiceScope>,
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
    if action != Action::SchedulerControl && resource_project_id.is_none() {
        return Err(AuthorizationDenied::ProjectRequired);
    }

    let allowed = match principal.kind {
        PrincipalKind::Service => service_allows(principal, action),
        PrincipalKind::Human => human_allows(principal, resource_project_id, action)?,
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
        Action::ProjectRead => ServiceScope::ProjectRead,
        Action::BuildSubmit => ServiceScope::BuildSubmit,
        Action::BuildCancel => ServiceScope::BuildCancel,
        Action::SecretUse => ServiceScope::SecretUse,
        Action::SchedulerControl => ServiceScope::SchedulerControl,
        Action::ProjectAdmin => return false,
    };
    principal.service_scopes.contains(&required)
}

fn human_allows(
    principal: &Principal,
    project_id: Option<Uuid>,
    action: Action,
) -> Result<bool, AuthorizationDenied> {
    if action == Action::SchedulerControl {
        return Ok(false);
    }
    let project_id = project_id.ok_or(AuthorizationDenied::ProjectRequired)?;
    let Some(role) = principal.project_roles.get(&project_id) else {
        return Ok(false);
    };
    Ok(match action {
        Action::ProjectRead => true,
        Action::BuildSubmit | Action::BuildCancel => *role >= ProjectRole::Developer,
        Action::SecretUse | Action::ProjectAdmin => *role >= ProjectRole::Admin,
        Action::SchedulerControl => false,
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
        };
        assert_eq!(
            authorize(
                &principal,
                organization_id,
                Some(Uuid::new_v4()),
                Action::ProjectRead
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
                Action::ProjectAdmin
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
                Action::ProjectRead
            )
            .is_ok()
        );
        assert_eq!(
            authorize(
                &viewer,
                organization_id,
                Some(project_id),
                Action::BuildSubmit
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
            ]
            .into(),
        };
        for action in [
            Action::ProjectRead,
            Action::BuildSubmit,
            Action::BuildCancel,
            Action::SecretUse,
        ] {
            assert_eq!(
                authorize(&principal, organization_id, None, action),
                Err(AuthorizationDenied::ProjectRequired)
            );
        }
    }
}
