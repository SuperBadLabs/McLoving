use std::collections::BTreeSet;

use mcloving_controller_store::{
    IdentityLifecycle, IdentityProviderWrite, LoginAttempt, NewHumanIdentity, NewServiceCredential,
    NewServiceIdentity, OidcIdentityClaims, SessionIssue, Store, StoreError,
    authz::{PrincipalKind, ProjectRole, ServiceScope},
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

async fn unprivileged_store(admin: &Store) -> Store {
    let mut setup = admin
        .pool()
        .begin()
        .await
        .expect("begin runtime-role setup");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind("mcloving.test.identity-role-login")
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
            .expect("connect as runtime role"),
    )
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

#[tokio::test]
async fn identity_sessions_and_service_credentials_are_fenced_and_audited() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let second_organization_id = Uuid::new_v4();
    let second_project_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "identity-lifecycle",
        )
        .await
        .expect("create identity test tenant");
    admin
        .create_project(
            second_organization_id,
            &format!("org-{second_organization_id}"),
            second_project_id,
            "identity-lifecycle-second-tenant",
        )
        .await
        .expect("create a real second tenant for isolation checks");

    let quarantined_legacy_human_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO identities(
             id, organization_id, subject, kind, lifecycle_state, lifecycle_generation
         ) VALUES ($1,$2,$3,'human','disabled',2)",
    )
    .bind(quarantined_legacy_human_id)
    .bind(organization_id)
    .bind(format!("legacy:{quarantined_legacy_human_id}"))
    .execute(admin.pool())
    .await
    .expect("the migration's disabled legacy-human quarantine remains representable");
    assert!(
        admin
            .transition_identity_lifecycle(
                organization_id,
                quarantined_legacy_human_id,
                2,
                IdentityLifecycle::Active,
                "operator:identity",
            )
            .await
            .is_err(),
        "an unmapped legacy human must not be reactivated without a reviewed replacement binding"
    );

    let provider_id = Uuid::new_v4();
    admin
        .provision_identity_provider(&IdentityProviderWrite {
            organization_id,
            provider_id,
            issuer: "https://id.example.test".to_owned(),
            audience: "mcloving".to_owned(),
            authorization_endpoint: "https://id.example.test/authorize".to_owned(),
            token_endpoint: "https://id.example.test/token".to_owned(),
            jwks_uri: "https://id.example.test/jwks".to_owned(),
            client_id: "mcloving".to_owned(),
            group_claim: "groups".to_owned(),
            configuration_generation: 1,
            configuration_digest: digest("provider-v1"),
            jwks_generation: 1,
            jwks_digest: digest("jwks-v1"),
            enabled: true,
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("provision exact provider");
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id,
            identity_id: quarantined_legacy_human_id,
            subject: format!("legacy:{quarantined_legacy_human_id}"),
            provider_id,
            external_subject: "reviewed-legacy-person".to_owned(),
            source_realm_digest: digest("legacy-jenkins-realm"),
            source_identity_id: "legacy-jenkins-user".to_owned(),
            source_membership_generation: 4,
            alias_history: vec!["legacy-login".to_owned()],
            provenance_digest: digest("legacy-reviewed-provenance"),
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("bind the quarantined legacy human through the reviewed mapping path");
    assert_eq!(
        admin
            .transition_identity_lifecycle(
                organization_id,
                quarantined_legacy_human_id,
                2,
                IdentityLifecycle::Active,
                "operator:identity",
            )
            .await
            .expect("activate the legacy human only after immutable binding"),
        3
    );

    let human_id = Uuid::new_v4();
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id,
            identity_id: human_id,
            subject: format!("principal:{human_id}"),
            provider_id,
            external_subject: "immutable-person-42".to_owned(),
            source_realm_digest: digest("jenkins-realm"),
            source_identity_id: "jenkins-user-42".to_owned(),
            source_membership_generation: 7,
            alias_history: vec!["old-login".to_owned()],
            provenance_digest: digest("mig-000-provenance"),
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("provision reviewed immutable human mapping");
    sqlx::query(
        "INSERT INTO project_memberships(identity_id, organization_id, project_id, role)
         VALUES ($1,$2,$3,'developer')",
    )
    .bind(human_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(admin.pool())
    .await
    .expect("provision reviewed human role");

    let runtime = unprivileged_store(&admin).await;
    let login = LoginAttempt {
        organization_id,
        attempt_id: Uuid::new_v4(),
        provider_id,
        state_digest: digest("state-1"),
        nonce_digest: digest("nonce-1"),
        pkce_verifier: "A".repeat(43),
        redirect_uri: "https://controller.example.test/callback".to_owned(),
        provider_configuration_generation: 1,
        expires_at_unix_ms: 20_000,
    };
    runtime
        .record_oidc_login_attempt(&login)
        .await
        .expect("persist one-time OIDC state");
    assert_eq!(
        runtime
            .consume_oidc_login_attempt(organization_id, login.state_digest, 10_000)
            .await
            .expect("consume OIDC state")
            .attempt_id,
        login.attempt_id
    );
    assert!(matches!(
        runtime
            .consume_oidc_login_attempt(organization_id, login.state_digest, 10_001)
            .await,
        Err(StoreError::IdentityConflict(_))
    ));

    let session_token = digest("human-session-1");
    let claims = OidcIdentityClaims {
        organization_id,
        provider_id,
        issuer: "https://id.example.test".to_owned(),
        external_subject: "immutable-person-42".to_owned(),
        groups: vec!["developers".to_owned()],
        provider_configuration_generation: 1,
        provider_jwks_generation: 1,
        id_token_digest: digest("id-token-1"),
    };
    let first_session = runtime
        .issue_human_session(
            &claims,
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: session_token,
                refresh_token_digest: Some(digest("human-refresh-1")),
                issued_at_unix_ms: 10_000,
                expires_at_unix_ms: 30_000,
                refresh_expires_at_unix_ms: Some(60_000),
            },
        )
        .await
        .expect("issue generation-bound OIDC session");
    let authenticated = runtime
        .authenticate_api_token(organization_id, session_token, 10_100)
        .await
        .expect("authenticate durable human session");
    assert_eq!(authenticated.identity_id, human_id);
    assert_eq!(authenticated.principal.kind, PrincipalKind::Human);
    assert_eq!(
        authenticated.principal.project_roles.get(&project_id),
        Some(&ProjectRole::Developer)
    );
    assert!(
        runtime
            .issue_human_session(
                &claims,
                &SessionIssue {
                    session_id: Uuid::new_v4(),
                    token_digest: digest("replayed-session"),
                    refresh_token_digest: Some(digest("replayed-refresh")),
                    issued_at_unix_ms: 10_200,
                    expires_at_unix_ms: 30_000,
                    refresh_expires_at_unix_ms: Some(60_000),
                },
            )
            .await
            .is_err(),
        "an ID token must be consumed only once"
    );

    let changed_groups = OidcIdentityClaims {
        groups: vec!["operators".to_owned()],
        id_token_digest: digest("id-token-2"),
        ..claims.clone()
    };
    let second_token = digest("human-session-2");
    let second_session = runtime
        .issue_human_session(
            &changed_groups,
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: second_token,
                refresh_token_digest: Some(digest("human-refresh-2")),
                issued_at_unix_ms: 11_000,
                expires_at_unix_ms: 31_000,
                refresh_expires_at_unix_ms: Some(61_000),
            },
        )
        .await
        .expect("issue session after group-generation advance");
    assert!(second_session.group_generation > first_session.group_generation);
    assert!(
        runtime
            .authenticate_api_token(organization_id, session_token, 11_100)
            .await
            .is_err(),
        "group change must immediately fence the older session"
    );
    assert!(
        runtime
            .authenticate_api_token(second_organization_id, second_token, 11_100)
            .await
            .is_err(),
        "credential must not cross tenant boundaries"
    );

    let refreshed_token = digest("human-session-3");
    let refreshed_session = runtime
        .rotate_human_session(
            organization_id,
            digest("human-refresh-2"),
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: refreshed_token,
                refresh_token_digest: Some(digest("human-refresh-3")),
                issued_at_unix_ms: 12_000,
                expires_at_unix_ms: 32_000,
                refresh_expires_at_unix_ms: Some(62_000),
            },
        )
        .await
        .expect("rotate a live refresh credential exactly once");
    assert_eq!(
        refreshed_session.refresh_expires_at_unix_ms,
        Some(61_000),
        "refresh rotation preserves the original absolute refresh deadline"
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, second_token, 12_001)
            .await
            .is_err(),
        "refresh rotation must immediately revoke the replaced access token"
    );
    runtime
        .authenticate_api_token(organization_id, refreshed_token, 12_001)
        .await
        .expect("new access token authenticates after refresh rotation");
    assert!(
        runtime
            .rotate_human_session(
                organization_id,
                digest("human-refresh-2"),
                &SessionIssue {
                    session_id: Uuid::new_v4(),
                    token_digest: digest("refresh-replay-access"),
                    refresh_token_digest: Some(digest("refresh-replay-next")),
                    issued_at_unix_ms: 12_002,
                    expires_at_unix_ms: 32_002,
                    refresh_expires_at_unix_ms: Some(62_002),
                },
            )
            .await
            .is_err(),
        "a refresh credential must be one-time"
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, refreshed_token, 12_003)
            .await
            .is_err(),
        "refresh-token reuse revokes the active session family"
    );

    let service_id = Uuid::new_v4();
    let service_identity = NewServiceIdentity {
        organization_id,
        identity_id: service_id,
        subject: format!("service:{service_id}"),
        scopes: BTreeSet::from([ServiceScope::ProjectRead, ServiceScope::BuildSubmit]),
        actor_subject: "operator:identity".to_owned(),
    };
    admin
        .provision_service_identity(&service_identity)
        .await
        .expect("provision scoped service identity");
    admin
        .provision_service_identity(&service_identity)
        .await
        .expect("exact service identity provisioning is restart-idempotent");
    let service_token = digest("service-token-1");
    let service_credential = NewServiceCredential {
        organization_id,
        credential_id: Uuid::new_v4(),
        identity_id: service_id,
        generation: 1,
        token_digest: service_token,
        issued_at_unix_ms: 10_000,
        expires_at_unix_ms: Some(40_000),
        actor_subject: "operator:identity".to_owned(),
    };
    let credential = admin
        .provision_service_credential(&service_credential)
        .await
        .expect("provision independent service credential");
    assert_eq!(
        admin
            .provision_service_credential(&NewServiceCredential {
                issued_at_unix_ms: 10_500,
                ..service_credential.clone()
            })
            .await
            .expect("exact service credential provisioning is restart-idempotent"),
        credential
    );
    assert!(
        admin
            .provision_service_credential(&NewServiceCredential {
                credential_id: Uuid::new_v4(),
                token_digest: digest("same-generation-different-token"),
                ..service_credential.clone()
            })
            .await
            .is_err(),
        "a generation cannot silently accept a different token digest"
    );
    let service = runtime
        .authenticate_api_token(organization_id, service_token, 12_000)
        .await
        .expect("authenticate scoped service credential");
    assert_eq!(service.principal.kind, PrincipalKind::Service);
    assert_eq!(
        service.principal.service_scopes,
        BTreeSet::from([ServiceScope::ProjectRead, ServiceScope::BuildSubmit])
    );
    let rotated_service_token = digest("service-token-2");
    let rotated_credential = admin
        .provision_service_credential(&NewServiceCredential {
            credential_id: Uuid::new_v4(),
            generation: 2,
            token_digest: rotated_service_token,
            issued_at_unix_ms: 12_050,
            ..service_credential.clone()
        })
        .await
        .expect("rotate to the next service credential generation");
    assert!(
        runtime
            .authenticate_api_token(organization_id, service_token, 12_051)
            .await
            .is_err(),
        "a new credential generation immediately revokes the old generation"
    );
    runtime
        .authenticate_api_token(organization_id, rotated_service_token, 12_051)
        .await
        .expect("the new service credential generation authenticates");
    assert!(
        runtime
            .revoke_service_credential(
                organization_id,
                rotated_credential.credential_id,
                12_100,
                "rotation",
                "operator:identity",
            )
            .await
            .expect("revoke service credential")
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, rotated_service_token, 12_101)
            .await
            .is_err()
    );

    let lifecycle_generation = admin
        .transition_identity_lifecycle(
            organization_id,
            human_id,
            1,
            IdentityLifecycle::Disabled,
            "operator:identity",
        )
        .await
        .expect("disable human identity");
    assert_eq!(lifecycle_generation, 2);
    assert!(
        runtime
            .authenticate_api_token(organization_id, refreshed_token, 12_200)
            .await
            .is_err(),
        "identity disable must immediately fence every session"
    );
    let audit = admin
        .verify_audit_chain(organization_id)
        .await
        .expect("verify identity audit chain");
    for action in [
        "identity_provider_provisioned",
        "human_identity_provisioned",
        "oidc_session_issued",
        "oidc_session_refreshed",
        "service_identity_provisioned",
        "service_credential_provisioned",
        "service_credential_revoked",
        "identity_lifecycle_transitioned",
    ] {
        assert!(audit.events.iter().any(|event| event.action == action));
    }
}
