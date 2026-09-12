//! PAR-003: human project roles are granted and revoked by the admin tool
//! and by project principals, under the rules the ticket states, and a
//! revocation fences the identity's live sessions at once.

use mcloving_controller_store::authz::ProjectRole;
use mcloving_controller_store::{
    DurableCaller, IdentityProviderWrite, MembershipAuthority, NewHumanIdentity,
    OidcIdentityClaims, ProjectRoleGrant, ProjectRoleGrantOutcome, ProjectRoleRevocation,
    SessionIssue, Store, StoreError,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect(&url)
        .await
        .expect("connect to the explicitly configured PostgreSQL test database");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

/// The runtime role the controller runs under: the API path writes
/// memberships and fences sessions as this role, never as the owner.
async fn runtime_store(admin: &Store) -> Store {
    let mut setup = admin.pool().begin().await.expect("begin role setup");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind("mcloving.test.authorization-role-login")
        .execute(&mut *setup)
        .await
        .expect("serialize runtime-role setup");
    let login_enabled: bool =
        sqlx::query_scalar("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'mcloving_tenant'")
            .fetch_one(&mut *setup)
            .await
            .expect("inspect runtime role");
    if !login_enabled {
        sqlx::query("ALTER ROLE mcloving_tenant LOGIN")
            .execute(&mut *setup)
            .await
            .expect("enable test-only runtime login");
    }
    setup.commit().await.expect("commit runtime-role setup");
    let options = std::env::var("MCLOVING_TEST_DATABASE_URL")
        .expect("database URL remains configured")
        .parse::<PgConnectOptions>()
        .expect("parse PostgreSQL test URL")
        .username("mcloving_tenant");
    Store::new(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect as the runtime role"),
    )
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

struct Tenant {
    organization_id: Uuid,
    project_id: Uuid,
    provider_id: Uuid,
    provider: IdentityProviderWrite,
}

async fn tenant(admin: &Store) -> Tenant {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let provider_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            &format!("project-{project_id}"),
        )
        .await
        .expect("create project");
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id,
        issuer: "https://idp.par003.test".to_owned(),
        audience: "mcloving-par003".to_owned(),
        authorization_endpoint: "https://idp.par003.test/authorize".to_owned(),
        token_endpoint: "https://idp.par003.test/token".to_owned(),
        jwks_uri: "https://idp.par003.test/jwks".to_owned(),
        client_id: "mcloving-par003".to_owned(),
        group_claim: "groups".to_owned(),
        configuration_generation: 1,
        configuration_digest: digest("par003-provider-generation-1"),
        jwks_generation: 1,
        jwks_digest: digest("par003-jwks-generation-1"),
        enabled: true,
        actor_subject: "reviewer:par003".to_owned(),
    };
    admin
        .provision_identity_provider(&provider)
        .await
        .expect("provision provider");
    Tenant {
        organization_id,
        project_id,
        provider_id,
        provider,
    }
}

async fn human(admin: &Store, tenant: &Tenant, name: &str) -> Uuid {
    let identity_id = Uuid::new_v4();
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id: tenant.organization_id,
            identity_id,
            subject: format!("human:{name}"),
            provider_id: tenant.provider_id,
            external_subject: external_subject(identity_id),
            source_realm_digest: digest("par003-source-realm"),
            source_identity_id: format!("jenkins-user-{name}"),
            source_membership_generation: 1,
            alias_history: Vec::new(),
            provenance_digest: digest("par003-provenance"),
            actor_subject: "reviewer:par003".to_owned(),
        })
        .await
        .expect("provision human identity");
    identity_id
}

fn external_subject(identity_id: Uuid) -> String {
    format!("par003-{identity_id}")
}

/// Issues a bearer for the human through the runtime role and answers the
/// token digest the API authenticates with.
async fn session(runtime: &Store, tenant: &Tenant, identity_id: Uuid, label: &str) -> [u8; 32] {
    let external_subject = external_subject(identity_id);
    let token = digest(label);
    runtime
        .issue_human_session(
            &OidcIdentityClaims {
                organization_id: tenant.organization_id,
                provider_id: tenant.provider_id,
                issuer: tenant.provider.issuer.clone(),
                external_subject,
                groups: Vec::new(),
                provider_configuration_generation: tenant.provider.configuration_generation,
                provider_jwks_generation: tenant.provider.jwks_generation,
                id_token_digest: digest(&format!("{label}-id-token")),
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: token,
                refresh_token_digest: Some(digest(&format!("{label}-refresh"))),
                issued_at_unix_ms: 10_000,
                expires_at_unix_ms: 80_000,
                refresh_expires_at_unix_ms: Some(90_000),
            },
        )
        .await
        .expect("issue human session");
    token
}

fn grant<'a>(
    tenant: &Tenant,
    identity_id: Uuid,
    role: ProjectRole,
    authority: MembershipAuthority,
    reason: &'a str,
) -> ProjectRoleGrant<'a> {
    ProjectRoleGrant {
        organization_id: tenant.organization_id,
        project_id: tenant.project_id,
        identity_id,
        role,
        authority,
        actor_subject: "reviewer:par003",
        reason,
    }
}

fn revocation<'a>(
    tenant: &Tenant,
    identity_id: Uuid,
    authority: MembershipAuthority,
    reason: &'a str,
) -> ProjectRoleRevocation<'a> {
    ProjectRoleRevocation {
        organization_id: tenant.organization_id,
        project_id: tenant.project_id,
        identity_id,
        authority,
        actor_subject: "reviewer:par003",
        reason,
    }
}

/// The authority a human's bearer carries: its identity and the lifecycle
/// generation it authenticated under, read now.
async fn as_principal(admin: &Store, tenant: &Tenant, identity_id: Uuid) -> MembershipAuthority {
    let lifecycle_generation = sqlx::query_scalar::<_, i64>(
        "SELECT lifecycle_generation FROM identities WHERE organization_id = $1 AND id = $2",
    )
    .bind(tenant.organization_id)
    .bind(identity_id)
    .fetch_one(admin.pool())
    .await
    .expect("read lifecycle generation");
    MembershipAuthority::Principal(DurableCaller {
        identity_id,
        lifecycle_generation,
        session_id: None,
        service_credential_id: None,
    })
}

const DELEGATED: MembershipAuthority = MembershipAuthority::Delegated { caller: None };

fn is_denied<T: std::fmt::Debug>(result: Result<T, StoreError>) -> bool {
    matches!(result, Err(StoreError::ProjectRoleDenied(_)))
}

#[tokio::test]
async fn owners_are_bootstrapped_offline_and_managed_only_by_owners() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let tenant = tenant(&admin).await;
    let runtime = runtime_store(&admin).await;
    let alice = human(&admin, &tenant, "alice").await;
    let bob = human(&admin, &tenant, "bob").await;
    let carol = human(&admin, &tenant, "carol").await;
    let bootstrap = MembershipAuthority::Bootstrap;

    // No Owner exists and alice holds nothing: the API cannot mint one.
    let as_alice = as_principal(&admin, &tenant, alice).await;
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                alice,
                ProjectRole::Owner,
                as_alice,
                "no bootstrap"
            ))
            .await
    ));
    // The admin tool bootstraps the first Owner.
    assert!(matches!(
        admin
            .grant_project_role(&grant(
                &tenant,
                alice,
                ProjectRole::Owner,
                bootstrap,
                "bootstrap owner"
            ))
            .await
            .unwrap(),
        ProjectRoleGrantOutcome::Granted(_)
    ));
    // A delegated caller (service or mapped policy) manages below Owner.
    assert!(matches!(
        runtime
            .grant_project_role(&grant(
                &tenant,
                bob,
                ProjectRole::Admin,
                DELEGATED,
                "service grants admin"
            ))
            .await
            .unwrap(),
        ProjectRoleGrantOutcome::Granted(_)
    ));
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                carol,
                ProjectRole::Owner,
                DELEGATED,
                "service grants owner"
            ))
            .await
    ));
    // A durable delegated caller is revalidated: a stale generation is refused.
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                carol,
                ProjectRole::Viewer,
                MembershipAuthority::Delegated {
                    caller: Some(DurableCaller {
                        identity_id: alice,
                        lifecycle_generation: 99,
                        session_id: None,
                        service_credential_id: None,
                    }),
                },
                "fenced service caller"
            ))
            .await
    ));
    // An Admin manages roles below Owner and nothing at Owner.
    let as_bob = as_principal(&admin, &tenant, bob).await;
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                carol,
                ProjectRole::Owner,
                as_bob,
                "admin grants owner"
            ))
            .await
    ));
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                alice,
                ProjectRole::Viewer,
                as_bob,
                "admin demotes owner"
            ))
            .await
    ));
    assert!(is_denied(
        runtime
            .revoke_project_role(&revocation(&tenant, alice, as_bob, "admin revokes owner"))
            .await
    ));
    assert!(matches!(
        runtime
            .grant_project_role(&grant(
                &tenant,
                carol,
                ProjectRole::Developer,
                as_bob,
                "admin grants developer"
            ))
            .await
            .unwrap(),
        ProjectRoleGrantOutcome::Granted(_)
    ));
    // A Developer manages nothing.
    let as_carol = as_principal(&admin, &tenant, carol).await;
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                bob,
                ProjectRole::Viewer,
                as_carol,
                "developer demotes"
            ))
            .await
    ));
    // The last Owner is never revoked or demoted, by either authority.
    assert!(is_denied(
        runtime
            .revoke_project_role(&revocation(&tenant, alice, as_alice, "last owner"))
            .await
    ));
    assert!(is_denied(
        admin
            .grant_project_role(&grant(
                &tenant,
                alice,
                ProjectRole::Admin,
                bootstrap,
                "last owner demoted offline"
            ))
            .await
    ));
    // An Owner grants Owner (a promotion, no fence); the second Owner then
    // revokes the first.
    assert!(matches!(
        runtime
            .grant_project_role(&grant(
                &tenant,
                carol,
                ProjectRole::Owner,
                as_alice,
                "second owner"
            ))
            .await
            .unwrap(),
        ProjectRoleGrantOutcome::Changed {
            previous: ProjectRole::Developer,
            fenced_generation: None,
            ..
        }
    ));
    let as_carol = as_principal(&admin, &tenant, carol).await;
    let revoked = runtime
        .revoke_project_role(&revocation(&tenant, alice, as_carol, "first owner leaves"))
        .await
        .expect("an owner revokes another owner while one remains");
    assert_eq!(revoked.previous, ProjectRole::Owner);
    // alice's authority was captured before the revocation: her session is
    // fenced and her role gone, so the stale authority writes nothing.
    assert!(is_denied(
        runtime
            .grant_project_role(&grant(
                &tenant,
                bob,
                ProjectRole::Viewer,
                as_alice,
                "stale owner"
            ))
            .await
    ));
    // Re-granting the same role is a no-op; an unknown identity is refused;
    // revoking a role not held is a conflict.
    assert!(matches!(
        runtime
            .grant_project_role(&grant(&tenant, bob, ProjectRole::Admin, as_carol, "again"))
            .await
            .unwrap(),
        ProjectRoleGrantOutcome::Unchanged(_)
    ));
    assert!(matches!(
        runtime
            .grant_project_role(&grant(
                &tenant,
                Uuid::new_v4(),
                ProjectRole::Viewer,
                as_carol,
                "unknown"
            ))
            .await,
        Err(StoreError::IdentityConflict(_))
    ));
    assert!(matches!(
        runtime
            .revoke_project_role(&revocation(&tenant, alice, as_carol, "already gone"))
            .await,
        Err(StoreError::IdentityConflict(_))
    ));
    let memberships = runtime
        .project_memberships(tenant.organization_id, tenant.project_id)
        .await
        .unwrap();
    assert_eq!(
        memberships
            .iter()
            .map(|membership| (membership.subject.as_str(), membership.role))
            .collect::<Vec<_>>(),
        vec![
            ("human:bob", ProjectRole::Admin),
            ("human:carol", ProjectRole::Owner)
        ]
    );
    assert!(
        memberships
            .iter()
            .all(|membership| membership.granted_by == "reviewer:par003"
                && membership.granted_at_unix_ms > 0)
    );
    let actions = sqlx::query_scalar::<_, String>(
        "SELECT action || ':' || (payload->>'authority') FROM audit_events
         WHERE organization_id = $1 AND action LIKE 'project_role_%' ORDER BY sequence",
    )
    .bind(tenant.organization_id)
    .fetch_all(admin.pool())
    .await
    .unwrap();
    assert_eq!(
        actions,
        vec![
            "project_role_granted:bootstrap",
            "project_role_granted:delegated",
            "project_role_granted:principal",
            "project_role_changed:principal",
            "project_role_revoked:principal",
        ]
    );
}

#[tokio::test]
async fn revocation_and_demotion_fence_the_identity_sessions_at_once() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let tenant = tenant(&admin).await;
    let runtime = runtime_store(&admin).await;
    let owner = human(&admin, &tenant, "owner").await;
    let viewer = human(&admin, &tenant, "viewer").await;
    admin
        .grant_project_role(&grant(
            &tenant,
            owner,
            ProjectRole::Owner,
            MembershipAuthority::Bootstrap,
            "bootstrap owner",
        ))
        .await
        .unwrap();
    let as_owner = as_principal(&admin, &tenant, owner).await;
    runtime
        .grant_project_role(&grant(
            &tenant,
            viewer,
            ProjectRole::Developer,
            as_owner,
            "developer",
        ))
        .await
        .unwrap();
    let token = session(&runtime, &tenant, viewer, "viewer-session-1").await;
    let authenticated = runtime
        .authenticate_api_token(tenant.organization_id, token, 20_000)
        .await
        .expect("developer bearer authenticates");
    assert_eq!(
        authenticated
            .principal
            .project_roles
            .get(&tenant.project_id)
            .copied(),
        Some(ProjectRole::Developer)
    );

    // A demotion fences: the bearer issued under the old generation dies,
    // a new session carries the lower role.
    let demoted = runtime
        .grant_project_role(&grant(
            &tenant,
            viewer,
            ProjectRole::Viewer,
            as_owner,
            "demote",
        ))
        .await
        .unwrap();
    let ProjectRoleGrantOutcome::Changed {
        previous,
        fenced_generation: Some(generation),
        ..
    } = demoted
    else {
        panic!("demotion is a change that fences: {demoted:?}");
    };
    assert_eq!(previous, ProjectRole::Developer);
    assert_eq!(generation, 2);
    assert!(
        runtime
            .authenticate_api_token(tenant.organization_id, token, 21_000)
            .await
            .is_err(),
        "a bearer issued before the demotion no longer authenticates"
    );
    let token = session(&runtime, &tenant, viewer, "viewer-session-2").await;
    assert_eq!(
        runtime
            .authenticate_api_token(tenant.organization_id, token, 22_000)
            .await
            .unwrap()
            .principal
            .project_roles
            .get(&tenant.project_id)
            .copied(),
        Some(ProjectRole::Viewer)
    );
    // A promotion does not fence.
    let promoted = runtime
        .grant_project_role(&grant(
            &tenant,
            viewer,
            ProjectRole::Admin,
            as_owner,
            "promote",
        ))
        .await
        .unwrap();
    assert!(matches!(
        promoted,
        ProjectRoleGrantOutcome::Changed {
            fenced_generation: None,
            ..
        }
    ));
    assert!(
        runtime
            .authenticate_api_token(tenant.organization_id, token, 23_000)
            .await
            .is_ok()
    );
    // A revocation fences and the identity holds no role afterwards.
    let revoked = runtime
        .revoke_project_role(&revocation(&tenant, viewer, as_owner, "revoke"))
        .await
        .unwrap();
    assert_eq!(revoked.fenced_generation, 3);
    assert!(
        runtime
            .authenticate_api_token(tenant.organization_id, token, 24_000)
            .await
            .is_err(),
        "the revoked identity's bearer no longer authenticates"
    );
    let token = session(&runtime, &tenant, viewer, "viewer-session-3").await;
    assert!(
        runtime
            .authenticate_api_token(tenant.organization_id, token, 25_000)
            .await
            .unwrap()
            .principal
            .project_roles
            .is_empty()
    );
}
