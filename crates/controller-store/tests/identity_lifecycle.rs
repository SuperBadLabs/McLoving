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
async fn controller_authentication_rollout_is_atomic() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            Uuid::new_v4(),
            "controller-authentication-atomicity",
        )
        .await
        .expect("create controller authentication test tenant");
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id: Uuid::new_v4(),
        issuer: "https://id.example.test".to_owned(),
        audience: "mcloving".to_owned(),
        authorization_endpoint: "https://id.example.test/authorize".to_owned(),
        token_endpoint: "https://id.example.test/token".to_owned(),
        jwks_uri: "https://id.example.test/jwks".to_owned(),
        client_id: "mcloving".to_owned(),
        group_claim: "groups".to_owned(),
        configuration_generation: 1,
        configuration_digest: digest("atomic-provider-v1"),
        jwks_generation: 1,
        jwks_digest: digest("atomic-jwks-v1"),
        enabled: true,
        actor_subject: "bootstrap:controller".to_owned(),
    };
    admin
        .provision_identity_provider(&provider)
        .await
        .expect("provision initial provider");
    let identity_id = Uuid::new_v4();
    admin
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id,
            subject: format!("service:public-api:{identity_id}"),
            scopes: BTreeSet::from([ServiceScope::ProjectRead]),
            actor_subject: "bootstrap:controller".to_owned(),
        })
        .await
        .expect("provision public API identity");
    let original_token = digest("atomic-api-token-v1");
    admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: Uuid::new_v4(),
            identity_id,
            generation: 1,
            token_digest: original_token,
            issued_at_unix_ms: 10_000,
            expires_at_unix_ms: None,
            actor_subject: "bootstrap:controller".to_owned(),
        })
        .await
        .expect("provision original public API credential");

    let rejected_token = digest("atomic-api-token-v2-rejected");
    assert!(
        admin
            .provision_controller_authentication(
                &NewServiceCredential {
                    organization_id,
                    credential_id: Uuid::new_v4(),
                    identity_id,
                    generation: 2,
                    token_digest: rejected_token,
                    issued_at_unix_ms: 10_100,
                    expires_at_unix_ms: None,
                    actor_subject: "bootstrap:controller".to_owned(),
                },
                &IdentityProviderWrite {
                    issuer: "https://replacement-id.example.test".to_owned(),
                    configuration_generation: 2,
                    configuration_digest: digest("atomic-provider-v2-rejected"),
                    ..provider.clone()
                },
                "agent-1",
                digest("atomic-artifact-agent-token"),
            )
            .await
            .is_err(),
        "an invalid provider rollout must reject the whole controller authentication bundle"
    );
    admin
        .authenticate_api_token(organization_id, original_token, 10_101)
        .await
        .expect("the original API credential survives a rejected provider rollout");
    assert!(
        admin
            .authenticate_api_token(organization_id, rejected_token, 10_101)
            .await
            .is_err(),
        "the rejected API credential must not be persisted"
    );
    assert_eq!(
        admin
            .identity_provider_config(organization_id, provider.provider_id)
            .await
            .expect("load provider after rejected rollout")
            .configuration_generation,
        1,
        "the provider generation must also remain unchanged"
    );

    assert!(
        admin
            .provision_controller_authentication(
                &NewServiceCredential {
                    organization_id,
                    credential_id: Uuid::new_v4(),
                    identity_id,
                    generation: 2,
                    token_digest: digest("atomic-api-token-v2-artifact-collision"),
                    issued_at_unix_ms: 10_200,
                    expires_at_unix_ms: None,
                    actor_subject: "bootstrap:controller".to_owned(),
                },
                &IdentityProviderWrite {
                    configuration_generation: 2,
                    configuration_digest: digest("atomic-provider-v2-artifact-collision"),
                    ..provider.clone()
                },
                "agent-1",
                original_token,
            )
            .await
            .is_err(),
        "an artifact-agent collision must roll back the whole authentication bundle"
    );
    admin
        .authenticate_api_token(organization_id, original_token, 10_201)
        .await
        .expect("the original API credential survives a rejected artifact reservation");
    assert_eq!(
        admin
            .identity_provider_config(organization_id, provider.provider_id)
            .await
            .expect("load provider after rejected artifact reservation")
            .configuration_generation,
        1,
        "the provider generation remains unchanged after reservation failure"
    );
}

#[tokio::test]
async fn concurrent_oidc_login_attempts_preserve_the_provider_cap() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            Uuid::new_v4(),
            "oidc-login-attempt-cap",
        )
        .await
        .expect("create OIDC attempt-cap test tenant");
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
            configuration_digest: digest("attempt-cap-provider-v1"),
            jwks_generation: 1,
            jwks_digest: digest("attempt-cap-jwks-v1"),
            enabled: true,
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("provision attempt-cap provider");
    sqlx::query(
        "INSERT INTO oidc_login_attempts(
             organization_id, attempt_id, provider_id, state_digest,
             nonce_digest, pkce_verifier, redirect_uri,
             provider_configuration_generation, expires_at_unix_ms
         )
         SELECT $1, md5($1::text || ':' || seed::text)::uuid, $2,
                decode(repeat(lpad(to_hex(seed), 8, '0'), 8), 'hex'),
                decode(repeat(lpad(to_hex(seed + 2048), 8, '0'), 8), 'hex'),
                repeat('A', 43), 'https://controller.example.test/callback', 1, $3
         FROM generate_series(1, 1023) AS seed",
    )
    .bind(organization_id)
    .bind(provider_id)
    .bind(i64::MAX - 1)
    .execute(admin.pool())
    .await
    .expect("seed one below the provider attempt cap");
    let first = LoginAttempt {
        organization_id,
        attempt_id: Uuid::new_v4(),
        provider_id,
        state_digest: digest("concurrent-attempt-state-a"),
        nonce_digest: digest("concurrent-attempt-nonce-a"),
        pkce_verifier: "B".repeat(43),
        redirect_uri: "https://controller.example.test/callback".to_owned(),
        provider_configuration_generation: 1,
        expires_at_unix_ms: i64::MAX - 1,
    };
    let second = LoginAttempt {
        attempt_id: Uuid::new_v4(),
        state_digest: digest("concurrent-attempt-state-b"),
        nonce_digest: digest("concurrent-attempt-nonce-b"),
        ..first.clone()
    };
    let (first_result, second_result) = tokio::join!(
        admin.record_oidc_login_attempt(&first),
        admin.record_oidc_login_attempt(&second),
    );
    first_result.expect("record first concurrent OIDC attempt");
    second_result.expect("record second concurrent OIDC attempt");
    let active = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM oidc_login_attempts
         WHERE organization_id = $1 AND provider_id = $2
           AND consumed_at_unix_ms IS NULL",
    )
    .bind(organization_id)
    .bind(provider_id)
    .fetch_one(admin.pool())
    .await
    .expect("count bounded OIDC attempts");
    assert_eq!(
        active, 1024,
        "concurrent starts must preserve the exact cap"
    );
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
                "reviewed-legacy-binding-required",
                "operator:identity",
            )
            .await
            .is_err(),
        "an unmapped legacy human must not be reactivated without a reviewed replacement binding"
    );

    let provider_id = Uuid::new_v4();
    let provider = IdentityProviderWrite {
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
    };
    let (first_provider, concurrent_provider) = tokio::join!(
        admin.provision_identity_provider(&provider),
        admin.provision_identity_provider(&provider),
    );
    assert_eq!(
        first_provider.expect("first concurrent provider provision"),
        concurrent_provider.expect("second concurrent provider provision")
    );
    assert!(
        admin
            .provision_identity_provider(&IdentityProviderWrite {
                issuer: "https://replacement-id.example.test".to_owned(),
                configuration_generation: 2,
                configuration_digest: digest("replacement-provider-v2"),
                ..provider.clone()
            })
            .await
            .is_err(),
        "an existing provider ID cannot be rebound to a replacement issuer"
    );
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
                "reviewed-legacy-binding-complete",
                "operator:identity",
            )
            .await
            .expect("activate the legacy human only after immutable binding"),
        3
    );

    let human_id = Uuid::new_v4();
    let human_identity = NewHumanIdentity {
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
    };
    admin
        .provision_human_identity(&human_identity)
        .await
        .expect("provision reviewed immutable human mapping");
    admin
        .provision_human_identity(&human_identity)
        .await
        .expect("an exact human-provisioning retry is idempotent");
    assert!(
        admin
            .provision_human_identity(&NewHumanIdentity {
                external_subject: "substituted-person-42".to_owned(),
                ..human_identity.clone()
            })
            .await
            .is_err(),
        "an idempotent retry must not permit an immutable binding substitution"
    );
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
    assert!(
        runtime
            .rotate_human_session(
                organization_id,
                digest("human-refresh-1"),
                &SessionIssue {
                    session_id: Uuid::new_v4(),
                    token_digest: digest("stale-group-refresh-session"),
                    refresh_token_digest: Some(digest("stale-group-refresh-token")),
                    issued_at_unix_ms: 11_101,
                    expires_at_unix_ms: 31_101,
                    refresh_expires_at_unix_ms: Some(61_101),
                },
            )
            .await
            .is_err(),
        "a refresh token from a stale group generation must be rejected"
    );
    runtime
        .authenticate_api_token(organization_id, second_token, 11_102)
        .await
        .expect("a stale-group refresh must not revoke a newer session");

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
                    issued_at_unix_ms: 11_900,
                    expires_at_unix_ms: 31_900,
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
    let refresh_reuse_audits = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM audit_events
         WHERE organization_id = $1 AND action = 'oidc_refresh_reuse_detected'",
    )
    .bind(organization_id)
    .fetch_one(admin.pool())
    .await
    .expect("count initial refresh-reuse audit event");
    for now_unix_ms in [12_004, 12_005] {
        assert!(
            runtime
                .refresh_session_provider(organization_id, digest("human-refresh-2"), now_unix_ms,)
                .await
                .is_err(),
            "an already-handled refresh replay remains rejected"
        );
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM audit_events
             WHERE organization_id = $1 AND action = 'oidc_refresh_reuse_detected'",
        )
        .bind(organization_id)
        .fetch_one(admin.pool())
        .await
        .expect("count deduplicated refresh-reuse audit events"),
        refresh_reuse_audits,
        "repeated replay after family revocation must not grow the audit chain"
    );

    let independent_session_token = digest("independent-device-access");
    runtime
        .issue_human_session(
            &OidcIdentityClaims {
                id_token_digest: digest("id-token-independent-device"),
                ..changed_groups.clone()
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: independent_session_token,
                refresh_token_digest: Some(digest("independent-device-refresh")),
                issued_at_unix_ms: 12_900,
                expires_at_unix_ms: 32_900,
                refresh_expires_at_unix_ms: Some(62_900),
            },
        )
        .await
        .expect("issue an independent device session");

    let logout_predecessor = runtime
        .issue_human_session(
            &OidcIdentityClaims {
                id_token_digest: digest("id-token-logout-race"),
                ..changed_groups.clone()
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: digest("logout-race-access-before-refresh"),
                refresh_token_digest: Some(digest("logout-race-refresh-before-refresh")),
                issued_at_unix_ms: 13_000,
                expires_at_unix_ms: 33_000,
                refresh_expires_at_unix_ms: Some(63_000),
            },
        )
        .await
        .expect("issue session for logout-versus-refresh race");
    let logout_successor_token = digest("logout-race-access-after-refresh");
    let logout_successor = runtime
        .rotate_human_session(
            organization_id,
            digest("logout-race-refresh-before-refresh"),
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: logout_successor_token,
                refresh_token_digest: Some(digest("logout-race-refresh-after-refresh")),
                issued_at_unix_ms: 13_100,
                expires_at_unix_ms: 33_100,
                refresh_expires_at_unix_ms: Some(63_100),
            },
        )
        .await
        .expect("commit refresh before delayed logout reaches the predecessor lock");
    let logout_final_token = digest("logout-race-access-after-second-refresh");
    let logout_final = runtime
        .rotate_human_session(
            organization_id,
            digest("logout-race-refresh-after-refresh"),
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: logout_final_token,
                refresh_token_digest: Some(digest("logout-race-final-refresh")),
                issued_at_unix_ms: 13_050,
                expires_at_unix_ms: 33_050,
                refresh_expires_at_unix_ms: Some(63_100),
            },
        )
        .await
        .expect("commit a second refresh in the same lineage");
    assert!(
        runtime
            .revoke_session(
                organization_id,
                logout_predecessor.session_id,
                12_900,
                "logout",
                &human_identity.subject,
            )
            .await
            .expect("logout through the rotated predecessor"),
        "logout must revoke the successor when refresh wins the race"
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, logout_successor_token, 13_102)
            .await
            .is_err(),
        "a refresh successor must not survive a racing logout"
    );
    assert_eq!(logout_successor.identity_id, human_identity.identity_id);
    assert!(
        runtime
            .authenticate_api_token(organization_id, logout_final_token, 13_102)
            .await
            .is_err(),
        "the newest descendant must not survive logout through its root"
    );
    runtime
        .authenticate_api_token(organization_id, independent_session_token, 13_102)
        .await
        .expect("racing logout must preserve an independent device session");

    let service_id = Uuid::new_v4();
    let service_identity = NewServiceIdentity {
        organization_id,
        identity_id: service_id,
        subject: format!("service:{service_id}"),
        scopes: BTreeSet::from([ServiceScope::ProjectRead, ServiceScope::BuildSubmit]),
        actor_subject: "operator:identity".to_owned(),
    };
    let (first_service, concurrent_service) = tokio::join!(
        admin.provision_service_identity(&service_identity),
        admin.provision_service_identity(&service_identity),
    );
    first_service.expect("first concurrent service-identity provision");
    concurrent_service.expect("second concurrent service-identity provision");
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
    let (first_credential, concurrent_credential) = tokio::join!(
        admin.provision_service_credential(&service_credential),
        admin.provision_service_credential(&service_credential),
    );
    let credential = first_credential.expect("first concurrent service-credential provision");
    assert_eq!(
        credential,
        concurrent_credential.expect("second concurrent service-credential provision")
    );
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
    let _rotated_credential = admin
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
        admin
            .transition_identity_lifecycle(
                organization_id,
                service_id,
                1,
                IdentityLifecycle::Disabled,
                "",
                "operator:identity",
            )
            .await
            .is_err(),
        "a lifecycle transition without a canonical operational reason must fail closed"
    );
    assert_eq!(
        admin
            .transition_identity_lifecycle(
                organization_id,
                service_id,
                1,
                IdentityLifecycle::Disabled,
                "service-identity-emergency-disable",
                "operator:identity",
            )
            .await
            .expect("disable service identity"),
        2
    );
    assert_eq!(
        admin
            .transition_identity_lifecycle(
                organization_id,
                service_id,
                2,
                IdentityLifecycle::Active,
                "reviewed-service-reactivation",
                "operator:identity",
            )
            .await
            .expect("reactivate service identity"),
        3
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, rotated_service_token, 12_100)
            .await
            .is_err(),
        "reactivation must not resurrect a credential revoked by disable"
    );
    let final_service_token = digest("service-token-3");
    let final_credential = admin
        .provision_service_credential(&NewServiceCredential {
            credential_id: Uuid::new_v4(),
            generation: 3,
            token_digest: final_service_token,
            issued_at_unix_ms: 12_101,
            ..service_credential.clone()
        })
        .await
        .expect("issue a fresh credential after reviewed reactivation");
    runtime
        .authenticate_api_token(organization_id, final_service_token, 12_102)
        .await
        .expect("fresh post-reactivation credential authenticates");
    assert!(
        admin
            .revoke_service_credential(
                organization_id,
                final_credential.credential_id,
                12_103,
                "rotation",
                "operator:identity",
            )
            .await
            .expect("revoke fresh service credential")
    );

    let future_service_id = Uuid::new_v4();
    admin
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id: future_service_id,
            subject: format!("service:{future_service_id}"),
            scopes: BTreeSet::from([ServiceScope::ProjectRead]),
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("provision service identity for clock-skew revocation");
    let future_first_credential = admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: Uuid::new_v4(),
            identity_id: future_service_id,
            generation: 1,
            token_digest: digest("future-issued-service-token"),
            issued_at_unix_ms: i64::MAX - 3,
            expires_at_unix_ms: None,
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("issue a credential ahead of the database clock");
    let future_second_credential = admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: Uuid::new_v4(),
            identity_id: future_service_id,
            generation: 2,
            token_digest: digest("behind-clock-service-token"),
            issued_at_unix_ms: i64::MAX - 10,
            expires_at_unix_ms: None,
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("rotate despite a caller clock behind the previous issuer");
    assert!(
        admin
            .revoke_service_credential(
                organization_id,
                future_second_credential.credential_id,
                0,
                "clock-skew-test",
                "operator:identity",
            )
            .await
            .expect("standalone revocation must clamp a behind-clock timestamp")
    );
    assert_ne!(
        future_first_credential.credential_id,
        future_second_credential.credential_id
    );
    admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: Uuid::new_v4(),
            identity_id: future_service_id,
            generation: 3,
            token_digest: digest("future-lifecycle-service-token"),
            issued_at_unix_ms: i64::MAX - 1,
            expires_at_unix_ms: None,
            actor_subject: "operator:identity".to_owned(),
        })
        .await
        .expect("issue a live future credential for lifecycle revocation");
    assert_eq!(
        admin
            .transition_identity_lifecycle(
                organization_id,
                future_service_id,
                1,
                IdentityLifecycle::Disabled,
                "future-clock-emergency-disable",
                "operator:identity",
            )
            .await
            .expect("emergency disable must tolerate a future-issued credential"),
        2
    );

    let provider_fenced_token = digest("provider-fenced-session");
    runtime
        .issue_human_session(
            &OidcIdentityClaims {
                id_token_digest: digest("id-token-provider-fence"),
                ..claims.clone()
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: provider_fenced_token,
                refresh_token_digest: None,
                issued_at_unix_ms: 12_104,
                expires_at_unix_ms: 32_104,
                refresh_expires_at_unix_ms: None,
            },
        )
        .await
        .expect("issue a session before emergency provider shutdown");
    runtime
        .authenticate_api_token(organization_id, provider_fenced_token, 12_105)
        .await
        .expect("pre-shutdown provider session authenticates");
    assert_eq!(
        admin
            .transition_identity_provider_enabled(
                organization_id,
                provider_id,
                1,
                false,
                "emergency identity-provider shutdown",
                "operator:identity",
            )
            .await
            .expect("disable identity provider through the supported operator path"),
        2
    );
    let disabled_provider = admin
        .identity_provider_config(organization_id, provider_id)
        .await
        .expect("read disabled identity provider");
    assert!(!disabled_provider.enabled);
    assert_eq!(disabled_provider.configuration_generation, 2);
    let disabled_rollout_input = IdentityProviderWrite {
        configuration_generation: 3,
        configuration_digest: digest("provider-v3-while-disabled"),
        jwks_generation: 2,
        jwks_digest: digest("jwks-v2-while-disabled"),
        enabled: true,
        ..provider.clone()
    };
    let disabled_rollout = admin
        .provision_identity_provider(&disabled_rollout_input)
        .await
        .expect("roll out provider configuration while emergency-disabled");
    assert!(
        !disabled_rollout.enabled,
        "configuration rollout must preserve the explicit disabled state"
    );
    assert_eq!(
        admin
            .provision_identity_provider(&disabled_rollout_input)
            .await
            .expect("a second replica retries the same disabled-provider rollout"),
        disabled_rollout,
        "preserved status must remain exact-retry idempotent across replicas"
    );
    assert!(
        !admin
            .identity_provider_config(organization_id, provider_id)
            .await
            .expect("reload provider after disabled rollout")
            .enabled,
        "only the explicit status transition may reenable a provider"
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, provider_fenced_token, 12_106)
            .await
            .is_err(),
        "provider disable must immediately fence every session"
    );
    assert_eq!(
        admin
            .transition_identity_provider_enabled(
                organization_id,
                provider_id,
                3,
                true,
                "reviewed identity-provider recovery",
                "operator:identity",
            )
            .await
            .expect("reenable identity provider through the supported operator path"),
        4
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, provider_fenced_token, 12_107)
            .await
            .is_err(),
        "provider reenable must not resurrect a session from an older trust generation"
    );
    let lifecycle_fenced_token = digest("lifecycle-fenced-session");
    runtime
        .issue_human_session(
            &OidcIdentityClaims {
                provider_configuration_generation: 4,
                provider_jwks_generation: 2,
                id_token_digest: digest("id-token-lifecycle-fence"),
                ..claims.clone()
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: lifecycle_fenced_token,
                refresh_token_digest: None,
                issued_at_unix_ms: 12_108,
                expires_at_unix_ms: 32_108,
                refresh_expires_at_unix_ms: None,
            },
        )
        .await
        .expect("issue a session after reviewed provider recovery");
    runtime
        .authenticate_api_token(organization_id, lifecycle_fenced_token, 12_109)
        .await
        .expect("post-recovery provider session authenticates");
    let lifecycle_generation = admin
        .transition_identity_lifecycle(
            organization_id,
            human_id,
            1,
            IdentityLifecycle::Disabled,
            "suspected-account-compromise",
            "operator:identity",
        )
        .await
        .expect("disable human identity");
    assert_eq!(lifecycle_generation, 2);
    assert!(
        runtime
            .authenticate_api_token(organization_id, lifecycle_fenced_token, 12_110)
            .await
            .is_err(),
        "identity disable must immediately fence every session"
    );
    let audit = admin
        .verify_audit_chain(organization_id)
        .await
        .expect("verify identity audit chain");
    let future_revocation = audit
        .events
        .iter()
        .find(|event| {
            event.action == "service_credential_revoked"
                && event.subject == format!("credential:{}", future_second_credential.credential_id)
        })
        .expect("clock-skewed service revocation audit event");
    assert_eq!(
        future_revocation.payload["revoked_at_unix_ms"],
        i64::MAX - 10,
        "audit must record the effective durable revocation timestamp"
    );
    assert_eq!(
        future_revocation.payload["requested_revoked_at_unix_ms"], 0,
        "audit must retain the caller-requested revocation timestamp"
    );
    let skewed_service_rotation = audit
        .events
        .iter()
        .find(|event| {
            event.action == "service_credential_provisioned"
                && event.subject
                    == format!(
                        "service-credential:{}",
                        future_second_credential.credential_id
                    )
        })
        .expect("clock-skewed service rotation audit event");
    assert_eq!(
        skewed_service_rotation.payload["requested_superseded_at_unix_ms"],
        i64::MAX - 10
    );
    assert_eq!(
        skewed_service_rotation.payload["effective_superseded_at_unix_ms_min"],
        i64::MAX - 3
    );
    assert_eq!(
        skewed_service_rotation.payload["effective_superseded_at_unix_ms_max"],
        i64::MAX - 3
    );
    let skewed_refresh_rotation = audit
        .events
        .iter()
        .find(|event| {
            event.action == "oidc_session_refreshed"
                && event.subject == format!("identity-session:{}", logout_final.session_id)
        })
        .expect("clock-skewed refresh rotation audit event");
    assert_eq!(
        skewed_refresh_rotation.payload["requested_replaced_at_unix_ms"],
        13_050
    );
    assert_eq!(
        skewed_refresh_rotation.payload["effective_replaced_at_unix_ms"],
        13_100
    );
    let logout = audit
        .events
        .iter()
        .find(|event| {
            event.action == "oidc_session_revoked"
                && event.subject == format!("credential:{}", logout_predecessor.session_id)
        })
        .expect("rotated-family logout audit event");
    assert_eq!(logout.payload["requested_at_unix_ms"], 12_900);
    assert_eq!(
        logout.payload["effective_revoked_at_unix_ms_min"], 13_050,
        "logout audit must expose the earliest effective durable family timestamp"
    );
    assert_eq!(
        logout.payload["effective_revoked_at_unix_ms_max"], 13_050,
        "logout audit must expose the latest effective durable family timestamp"
    );
    assert_eq!(
        logout.payload["revoked_sessions"], 1,
        "the already refresh-revoked predecessor is not a logout mutation"
    );
    let human_disable = audit
        .events
        .iter()
        .find(|event| {
            event.action == "identity_lifecycle_transitioned"
                && event.subject == format!("identity:{human_id}")
        })
        .expect("human lifecycle audit event");
    assert_eq!(
        human_disable.payload["reason"], "suspected-account-compromise",
        "lifecycle audit must preserve the canonical operational reason"
    );
    let future_lifecycle_disable = audit
        .events
        .iter()
        .find(|event| {
            event.action == "identity_lifecycle_transitioned"
                && event.subject == format!("identity:{future_service_id}")
        })
        .expect("future-issued service lifecycle audit event");
    assert_eq!(
        future_lifecycle_disable.payload["effective_revoked_at_unix_ms_min"],
        i64::MAX - 1
    );
    assert_eq!(
        future_lifecycle_disable.payload["effective_revoked_at_unix_ms_max"],
        i64::MAX - 1
    );
    assert!(
        future_lifecycle_disable.payload["revocation_clock_unix_ms"]
            .as_i64()
            .is_some_and(|clock| clock < i64::MAX - 1),
        "lifecycle audit must distinguish its database clock from the effective future timestamp"
    );
    for action in [
        "identity_provider_provisioned",
        "identity_provider_status_transitioned",
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
