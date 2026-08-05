use std::collections::BTreeMap;

use mcloving_controller_store::{
    AuthorizationPolicyWrite, AuthorizationPrincipalMappingWrite, IdentityProviderWrite,
    NewHumanIdentity, NewServiceCredential, NewServiceIdentity, OidcIdentityClaims, SessionIssue,
    Store, StoreError,
    authz::{Action, GrantDecision, ServiceScope, authorize},
    compute_authorization_policy_digest,
};
use serde_json::json;
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
            .expect("connect as constrained runtime role"),
    )
}

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn policy(
    organization_id: Uuid,
    project_id: Uuid,
    generation: i64,
    expected_current_generation: Option<i64>,
    restored_from_generation: Option<i64>,
    mappings: Vec<AuthorizationPrincipalMappingWrite>,
) -> AuthorizationPolicyWrite {
    let mut write = AuthorizationPolicyWrite {
        organization_id,
        project_id,
        generation,
        expected_current_generation,
        source_realm_implementation: "jenkins.security.HudsonPrivateSecurityRealm".to_owned(),
        source_realm_digest: digest("authz-source-realm-v1"),
        source_inventory_digest: digest("authz-mig000-inventory-epoch-7"),
        reviewer: "reviewer:authz-owner".to_owned(),
        actor_subject: "service:authz-importer".to_owned(),
        restored_from_generation,
        mappings,
        expected_policy_digest: [0; 32],
    };
    write.expected_policy_digest =
        compute_authorization_policy_digest(&write).expect("canonical policy digest");
    write
}

fn human_mapping(
    mapping_id: Uuid,
    identity_id: Uuid,
    group_generation: i64,
    decisions: BTreeMap<Action, GrantDecision>,
) -> AuthorizationPrincipalMappingWrite {
    AuthorizationPrincipalMappingWrite {
        mapping_id,
        target_identity_id: identity_id,
        source_identity_id: "jenkins-user-immutable-1042".to_owned(),
        source_alias_history: json!(["alice", "alice.legacy"]),
        source_membership_generation: 19,
        source_lifecycle_state: "active".to_owned(),
        source_acl_entry_id: "folder/release:user/jenkins-user-immutable-1042".to_owned(),
        source_acl_scope: "folder/release/job/deploy".to_owned(),
        source_acl_generation: "acl-generation-12".to_owned(),
        source_permissions: [
            "job.read",
            "job.build",
            "job.cancel",
            "job.configure",
            "input.approve",
            "run.replay",
            "run.artifacts",
            "artifact.write",
            "run.tests",
            "run.logs",
            "credentials.use",
            "audit.read",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        target_provider_id: Some(Uuid::from_u128(0x4d63_4c6f_7669_6e67_2000_0000_0000_0003)),
        target_external_subject: Some("jenkins-user-immutable-1042".to_owned()),
        target_lifecycle_generation: 1,
        target_group_generation: group_generation,
        target_provenance_digest: digest("authz-mig000-principal-provenance"),
        resulting_role: "custom".to_owned(),
        decisions,
    }
}

fn service_mapping(
    mapping_id: Uuid,
    identity_id: Uuid,
    decisions: BTreeMap<Action, GrantDecision>,
) -> AuthorizationPrincipalMappingWrite {
    AuthorizationPrincipalMappingWrite {
        mapping_id,
        target_identity_id: identity_id,
        source_identity_id: "jenkins-service-seed-immutable".to_owned(),
        source_alias_history: json!([]),
        source_membership_generation: 7,
        source_lifecycle_state: "active".to_owned(),
        source_acl_entry_id: "folder/release:service/seed".to_owned(),
        source_acl_scope: "folder/release".to_owned(),
        source_acl_generation: "acl-generation-service-4".to_owned(),
        source_permissions: ["job.read", "job.build", "job.cancel"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        target_provider_id: None,
        target_external_subject: None,
        target_lifecycle_generation: 1,
        target_group_generation: 1,
        target_provenance_digest: [0; 32],
        resulting_role: "custom".to_owned(),
        decisions,
    }
}

fn authz001_recovery_ids() -> (Uuid, Uuid, Uuid, Uuid, Uuid) {
    (
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_2100_0000_0000_0001),
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_2100_0000_0000_0002),
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_2100_0000_0000_0003),
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_2100_0000_0000_0004),
        Uuid::from_u128(0x4d63_4c6f_7669_6e67_2100_0000_0000_0005),
    )
}

#[tokio::test]
#[ignore = "run only by scripts/test-backup-restore.sh against an isolated source"]
async fn authz001_backup_restore_seed() {
    let admin = test_store().await.expect("isolated source database URL");
    let (organization_id, project_id, service_id, credential_id, mapping_id) =
        authz001_recovery_ids();
    admin
        .create_project(
            organization_id,
            "authz001-recovery",
            project_id,
            "authorization-restore",
        )
        .await
        .expect("create AUTHZ-001 recovery tenant");
    admin
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id: service_id,
            subject: "service:authz001-restore".to_owned(),
            scopes: [ServiceScope::ProjectAdmin].into(),
            actor_subject: "reviewer:authz001-restore".to_owned(),
        })
        .await
        .expect("provision recovery service identity");
    admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id,
            identity_id: service_id,
            generation: 1,
            token_digest: digest("authz001-restore-service-token"),
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: Some(100_000),
            actor_subject: "reviewer:authz001-restore".to_owned(),
        })
        .await
        .expect("provision recovery service credential");
    let recovery_policy = policy(
        organization_id,
        project_id,
        1,
        None,
        None,
        vec![service_mapping(
            mapping_id,
            service_id,
            [
                (Action::ProjectView, GrantDecision::Allow),
                (Action::BuildTrigger, GrantDecision::Allow),
                (Action::BuildCancel, GrantDecision::Deny),
            ]
            .into(),
        )],
    );
    admin
        .install_authorization_policy(&recovery_policy)
        .await
        .expect("install recovery policy generation");
}

#[tokio::test]
#[ignore = "run only by scripts/test-backup-restore.sh against an isolated restore"]
async fn authz001_backup_restore_verify() {
    let admin = test_store().await.expect("isolated restore database URL");
    let (organization_id, project_id, _, _, _) = authz001_recovery_ids();
    let runtime = unprivileged_store(&admin).await;
    let principal = runtime
        .authenticate_api_token(
            organization_id,
            digest("authz001-restore-service-token"),
            2_000,
        )
        .await
        .expect("restored service credential remains current")
        .principal;
    assert!(
        authorize(
            &principal,
            organization_id,
            Some(project_id),
            Action::ProjectView
        )
        .is_ok()
    );
    for action in [Action::BuildCancel, Action::ProjectConfigure] {
        assert!(authorize(&principal, organization_id, Some(project_id), action).is_err());
    }
    let current_generation: i64 = sqlx::query_scalar(
        "SELECT current_generation FROM authorization_project_policies
         WHERE organization_id = $1 AND project_id = $2",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(admin.pool())
    .await
    .expect("read restored policy pointer");
    assert_eq!(current_generation, 1);
    let audit = admin
        .verify_audit_chain(organization_id)
        .await
        .expect("restored authorization audit chain is valid");
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "policy_installed")
    );
}

#[tokio::test]
async fn concurrent_first_generation_install_has_one_domain_conflict() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    admin
        .create_project(
            organization_id,
            "authz-install-race",
            project_id,
            "authorization-install-race",
        )
        .await
        .expect("create authorization race test tenant");

    let first = policy(organization_id, project_id, 1, None, None, Vec::new());
    let second = first.clone();
    let first_store = admin.clone();
    let second_store = admin.clone();
    let (first_result, second_result) = tokio::join!(
        first_store.install_authorization_policy(&first),
        second_store.install_authorization_policy(&second),
    );

    let outcomes = [first_result, second_result];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(StoreError::AuthorizationConflict(_))))
            .count(),
        1,
        "the losing writer receives the stable authorization conflict contract"
    );
}

#[tokio::test]
async fn imported_policy_is_exact_stale_safe_versioned_and_rollback_capable() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::from_u128(0x4d63_4c6f_7669_6e67_2000_0000_0000_0001);
    let project_id = Uuid::from_u128(0x4d63_4c6f_7669_6e67_2000_0000_0000_0002);
    let provider_id = Uuid::from_u128(0x4d63_4c6f_7669_6e67_2000_0000_0000_0003);
    let identity_id = Uuid::from_u128(0x4d63_4c6f_7669_6e67_2000_0000_0000_0004);
    admin
        .create_project(
            organization_id,
            "authz-contract",
            project_id,
            "release-deploy",
        )
        .await
        .expect("create authorization test tenant");
    let provider = IdentityProviderWrite {
        organization_id,
        provider_id,
        issuer: "https://idp.authz.test".to_owned(),
        audience: "mcloving-authz".to_owned(),
        authorization_endpoint: "https://idp.authz.test/authorize".to_owned(),
        token_endpoint: "https://idp.authz.test/token".to_owned(),
        jwks_uri: "https://idp.authz.test/jwks".to_owned(),
        client_id: "mcloving-authz".to_owned(),
        group_claim: "groups".to_owned(),
        configuration_generation: 1,
        configuration_digest: digest("authz-idp-config"),
        jwks_generation: 1,
        jwks_digest: digest("authz-idp-jwks"),
        enabled: true,
        actor_subject: "reviewer:authz-owner".to_owned(),
    };
    admin
        .provision_identity_provider(&provider)
        .await
        .expect("provision exact target provider");
    admin
        .provision_human_identity(&NewHumanIdentity {
            organization_id,
            identity_id,
            subject: "principal:authz-alice".to_owned(),
            provider_id,
            external_subject: "jenkins-user-immutable-1042".to_owned(),
            source_realm_digest: digest("authz-source-realm-v1"),
            source_identity_id: "jenkins-user-immutable-1042".to_owned(),
            source_membership_generation: 19,
            alias_history: vec!["alice".to_owned(), "alice.legacy".to_owned()],
            provenance_digest: digest("authz-mig000-principal-provenance"),
            actor_subject: "reviewer:authz-owner".to_owned(),
        })
        .await
        .expect("bind immutable source principal");
    sqlx::query(
        "INSERT INTO project_memberships(identity_id, organization_id, project_id, role)
         VALUES ($1, $2, $3, 'owner')",
    )
    .bind(identity_id)
    .bind(organization_id)
    .bind(project_id)
    .execute(admin.pool())
    .await
    .expect("seed a deliberately broader legacy role");

    let runtime = unprivileged_store(&admin).await;
    let first_token = digest("authz-human-token-generation-1");
    let first_session = runtime
        .issue_human_session(
            &OidcIdentityClaims {
                organization_id,
                provider_id,
                issuer: provider.issuer.clone(),
                external_subject: "jenkins-user-immutable-1042".to_owned(),
                groups: vec!["release-viewers".to_owned()],
                provider_configuration_generation: 1,
                provider_jwks_generation: 1,
                id_token_digest: digest("authz-id-token-generation-1"),
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: first_token,
                refresh_token_digest: None,
                issued_at_unix_ms: 10_000,
                expires_at_unix_ms: 100_000,
                refresh_expires_at_unix_ms: None,
            },
        )
        .await
        .expect("issue first exact-generation session");

    let allow_mapping = human_mapping(
        Uuid::new_v4(),
        identity_id,
        first_session.group_generation,
        [
            (Action::ProjectView, GrantDecision::Allow),
            (Action::BuildTrigger, GrantDecision::Allow),
            (Action::BuildCancel, GrantDecision::Deny),
        ]
        .into(),
    );
    let deny_mapping = human_mapping(
        Uuid::new_v4(),
        identity_id,
        first_session.group_generation,
        [(Action::BuildTrigger, GrantDecision::Deny)].into(),
    );
    let generation_one = policy(
        organization_id,
        project_id,
        1,
        None,
        None,
        vec![allow_mapping, deny_mapping],
    );
    let receipt = admin
        .install_authorization_policy(&generation_one)
        .await
        .expect("install exact first policy generation");
    assert_eq!(receipt.mapping_count, 2);
    assert_eq!(receipt.grant_count, 4);

    let principal = runtime
        .authenticate_api_token(organization_id, first_token, 20_000)
        .await
        .expect("authenticate first mapped session")
        .principal;
    assert!(
        authorize(
            &principal,
            organization_id,
            Some(project_id),
            Action::ProjectView
        )
        .is_ok(),
        "explicit view grant is preserved"
    );
    for action in [
        Action::BuildTrigger,
        Action::BuildCancel,
        Action::ProjectConfigure,
    ] {
        assert!(
            authorize(&principal, organization_id, Some(project_id), action).is_err(),
            "deny wins and a broader legacy owner role cannot fill missing mapped permission"
        );
    }

    let mut substituted = policy(
        organization_id,
        project_id,
        2,
        Some(1),
        None,
        vec![human_mapping(
            Uuid::new_v4(),
            identity_id,
            first_session.group_generation,
            [(Action::ProjectView, GrantDecision::Allow)].into(),
        )],
    );
    substituted.source_realm_digest = digest("substituted-source-realm");
    substituted.expected_policy_digest =
        compute_authorization_policy_digest(&substituted).expect("substituted digest");
    assert!(matches!(
        admin.install_authorization_policy(&substituted).await,
        Err(StoreError::InvalidAuthorizationOperation(_))
    ));

    let second_token = digest("authz-human-token-generation-2");
    let second_session = runtime
        .issue_human_session(
            &OidcIdentityClaims {
                groups: vec!["release-operators".to_owned()],
                id_token_digest: digest("authz-id-token-generation-2"),
                ..OidcIdentityClaims {
                    organization_id,
                    provider_id,
                    issuer: provider.issuer.clone(),
                    external_subject: "jenkins-user-immutable-1042".to_owned(),
                    groups: Vec::new(),
                    provider_configuration_generation: 1,
                    provider_jwks_generation: 1,
                    id_token_digest: [0; 32],
                }
            },
            &SessionIssue {
                session_id: Uuid::new_v4(),
                token_digest: second_token,
                refresh_token_digest: None,
                issued_at_unix_ms: 30_000,
                expires_at_unix_ms: 100_000,
                refresh_expires_at_unix_ms: None,
            },
        )
        .await
        .expect("advance live group membership generation");
    assert!(
        runtime
            .authenticate_api_token(organization_id, first_token, 31_000)
            .await
            .is_err(),
        "group change invalidates the old session"
    );
    let stale_policy_principal = runtime
        .authenticate_api_token(organization_id, second_token, 31_000)
        .await
        .expect("new identity session remains valid")
        .principal;
    assert!(
        authorize(
            &stale_policy_principal,
            organization_id,
            Some(project_id),
            Action::ProjectView
        )
        .is_err(),
        "stale mapping generation produces no grants and does not fall back"
    );

    let generation_two_mapping = human_mapping(
        Uuid::new_v4(),
        identity_id,
        second_session.group_generation,
        [
            (Action::ProjectView, GrantDecision::Allow),
            (Action::BuildTrigger, GrantDecision::Allow),
            (Action::BuildCancel, GrantDecision::Allow),
        ]
        .into(),
    );
    let generation_two = policy(
        organization_id,
        project_id,
        2,
        Some(1),
        None,
        vec![generation_two_mapping.clone()],
    );
    admin
        .install_authorization_policy(&generation_two)
        .await
        .expect("install reviewed group-generation update");
    let current_principal = runtime
        .authenticate_api_token(organization_id, second_token, 32_000)
        .await
        .expect("reload current policy generation")
        .principal;
    for action in [
        Action::ProjectView,
        Action::BuildTrigger,
        Action::BuildCancel,
    ] {
        assert!(
            authorize(
                &current_principal,
                organization_id,
                Some(project_id),
                action
            )
            .is_ok()
        );
    }

    let stale_update = policy(
        organization_id,
        project_id,
        3,
        Some(1),
        None,
        vec![generation_two_mapping.clone()],
    );
    assert!(matches!(
        admin.install_authorization_policy(&stale_update).await,
        Err(StoreError::AuthorizationConflict(_))
    ));

    let revoked = policy(organization_id, project_id, 3, Some(2), None, Vec::new());
    admin
        .install_authorization_policy(&revoked)
        .await
        .expect("install complete revocation generation");
    let revoked_principal = runtime
        .authenticate_api_token(organization_id, second_token, 33_000)
        .await
        .expect("identity remains authenticated after policy revocation")
        .principal;
    assert!(
        authorize(
            &revoked_principal,
            organization_id,
            Some(project_id),
            Action::ProjectView
        )
        .is_err()
    );

    let restored = policy(
        organization_id,
        project_id,
        4,
        Some(3),
        Some(2),
        vec![generation_two_mapping],
    );
    admin
        .install_authorization_policy(&restored)
        .await
        .expect("restore a retained reviewed policy as a new monotonic generation");
    let restored_principal = runtime
        .authenticate_api_token(organization_id, second_token, 34_000)
        .await
        .expect("reload restored policy")
        .principal;
    assert!(
        authorize(
            &restored_principal,
            organization_id,
            Some(project_id),
            Action::BuildCancel
        )
        .is_ok()
    );

    let audit = admin
        .verify_audit_chain(organization_id)
        .await
        .expect("authorization changes preserve the audit chain");
    assert_eq!(
        audit
            .events
            .iter()
            .filter(|event| event.action == "policy_installed")
            .count(),
        3
    );
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "policy_rolled_back")
    );

    for table in [
        "authorization_policy_versions",
        "authorization_principal_mappings",
        "authorization_action_grants",
        "authorization_project_policies",
    ] {
        let can_write: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('mcloving_tenant', $1, 'INSERT')
                    OR has_table_privilege('mcloving_tenant', $1, 'UPDATE')
                    OR has_table_privilege('mcloving_tenant', $1, 'DELETE')",
        )
        .bind(table)
        .fetch_one(admin.pool())
        .await
        .expect("inspect authorization table privilege");
        assert!(!can_write, "runtime role must not mutate {table}");
    }
}

#[tokio::test]
async fn service_policy_survives_rotation_and_denies_revoked_credentials() {
    let Some(admin) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    admin
        .create_project(organization_id, "authz-service", project_id, "seed-project")
        .await
        .expect("create service authorization tenant");
    admin
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id: service_id,
            subject: "service:jenkins-seed".to_owned(),
            scopes: [ServiceScope::ProjectAdmin].into(),
            actor_subject: "reviewer:service-owner".to_owned(),
        })
        .await
        .expect("provision mapped service identity");
    let first_credential_id = Uuid::new_v4();
    let first_token = digest("authz-service-token-1");
    admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: first_credential_id,
            identity_id: service_id,
            generation: 1,
            token_digest: first_token,
            issued_at_unix_ms: 1_000,
            expires_at_unix_ms: None,
            actor_subject: "reviewer:service-owner".to_owned(),
        })
        .await
        .expect("provision first service credential");
    let mapped_policy = policy(
        organization_id,
        project_id,
        1,
        None,
        None,
        vec![service_mapping(
            Uuid::new_v4(),
            service_id,
            [(Action::BuildTrigger, GrantDecision::Allow)].into(),
        )],
    );
    admin
        .install_authorization_policy(&mapped_policy)
        .await
        .expect("install service mapping");
    let runtime = unprivileged_store(&admin).await;
    let first_principal = runtime
        .authenticate_api_token(organization_id, first_token, 2_000)
        .await
        .expect("authenticate first service credential")
        .principal;
    assert!(
        authorize(
            &first_principal,
            organization_id,
            Some(project_id),
            Action::BuildTrigger
        )
        .is_ok()
    );
    assert!(
        authorize(
            &first_principal,
            organization_id,
            Some(project_id),
            Action::ProjectConfigure
        )
        .is_err()
    );

    let second_credential_id = Uuid::new_v4();
    let second_token = digest("authz-service-token-2");
    admin
        .provision_service_credential(&NewServiceCredential {
            organization_id,
            credential_id: second_credential_id,
            identity_id: service_id,
            generation: 2,
            token_digest: second_token,
            issued_at_unix_ms: 3_000,
            expires_at_unix_ms: None,
            actor_subject: "reviewer:service-owner".to_owned(),
        })
        .await
        .expect("rotate service credential");
    assert!(
        runtime
            .authenticate_api_token(organization_id, first_token, 4_000)
            .await
            .is_err(),
        "rotation revokes the superseded service token"
    );
    let rotated_principal = runtime
        .authenticate_api_token(organization_id, second_token, 4_000)
        .await
        .expect("authenticate rotated credential")
        .principal;
    assert!(
        authorize(
            &rotated_principal,
            organization_id,
            Some(project_id),
            Action::BuildTrigger
        )
        .is_ok()
    );
    assert!(
        admin
            .revoke_service_credential(
                organization_id,
                second_credential_id,
                5_000,
                "emergency revocation",
                "reviewer:service-owner",
            )
            .await
            .expect("revoke rotated credential")
    );
    assert!(
        runtime
            .authenticate_api_token(organization_id, second_token, 6_000)
            .await
            .is_err(),
        "revocation removes service authority immediately"
    );
}

#[tokio::test]
async fn mapping_rejects_broadened_and_scheduler_authority() {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let mut mapping = human_mapping(
        Uuid::new_v4(),
        identity_id,
        1,
        [(Action::ArtifactWrite, GrantDecision::Allow)].into(),
    );
    mapping.source_permissions = ["job.read".to_owned()].into();
    let broadened = policy(organization_id, project_id, 1, None, None, vec![mapping]);
    let pool = PgPoolOptions::new()
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("construct lazy store");
    let store = Store::new(pool);
    assert!(matches!(
        store.install_authorization_policy(&broadened).await,
        Err(StoreError::InvalidAuthorizationOperation(_))
    ));

    let scheduler = human_mapping(
        Uuid::new_v4(),
        identity_id,
        1,
        [(Action::SchedulerControl, GrantDecision::Deny)].into(),
    );
    let scheduler_policy = policy(organization_id, project_id, 1, None, None, vec![scheduler]);
    assert!(matches!(
        store.install_authorization_policy(&scheduler_policy).await,
        Err(StoreError::InvalidAuthorizationOperation(_))
    ));
}
