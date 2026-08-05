use std::collections::BTreeMap;
use std::time::Duration;

use mcloving_controller_store::{
    ExternalReadAuthority, ExternalReadConsumerWrite, ExternalReadEndpointContract,
    ExternalReadResource, IdentityLifecycle, NewServiceIdentity, Store, StoreError,
    authz::ServiceScope, compute_external_read_consumer_digest,
};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
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

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn contracts() -> Vec<ExternalReadEndpointContract> {
    vec![
        ExternalReadEndpointContract {
            resource: ExternalReadResource::BuildStatus,
            endpoint: "/api/v1/organizations/{organization}/projects/{project}/builds/{build}"
                .to_owned(),
            query: BTreeMap::new(),
            pagination: "single immutable build view; no pagination".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::BuildGraph,
            endpoint:
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/graph"
                    .to_owned(),
            query: BTreeMap::new(),
            pagination: "single graph snapshot; no pagination".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::Log,
            endpoint: "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/logs"
                .to_owned(),
            query: BTreeMap::from([
                (
                    "after_attempt_id".to_owned(),
                    "UUID cursor component".to_owned(),
                ),
                (
                    "after_fence".to_owned(),
                    "signed 64-bit cursor component".to_owned(),
                ),
                (
                    "after_sequence".to_owned(),
                    "signed 64-bit cursor component".to_owned(),
                ),
                ("after_stream".to_owned(), "bounded stream name".to_owned()),
                ("limit".to_owned(), "1..1000".to_owned()),
            ]),
            pagination: "all four after_* values form one exclusive resumable cursor".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::TestResult,
            endpoint:
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/tests"
                    .to_owned(),
            query: BTreeMap::new(),
            pagination: "bounded complete report set; no pagination".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::Artifact,
            endpoint:
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/artifacts"
                    .to_owned(),
            query: BTreeMap::new(),
            pagination: "bounded metadata set; no pagination".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::ArtifactContent,
            endpoint: "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/artifacts/content"
                .to_owned(),
            query: BTreeMap::from([
                (
                    "attempt_id".to_owned(),
                    "required producer attempt UUID".to_owned(),
                ),
                ("name".to_owned(), "required exact artifact name".to_owned()),
            ]),
            pagination: "single authenticated immutable content response; no pagination".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::Queue,
            endpoint: "/api/v1/organizations/{organization}/projects/{project}/builds".to_owned(),
            query: BTreeMap::from([
                ("status".to_owned(), "exact value queued".to_owned()),
                (
                    "after_created_micros".to_owned(),
                    "signed 64-bit paired cursor component".to_owned(),
                ),
                (
                    "after_id".to_owned(),
                    "UUID paired cursor component".to_owned(),
                ),
                ("limit".to_owned(), "1..1000".to_owned()),
            ]),
            pagination: "created_at microseconds plus build UUID, supplied together".to_owned(),
        },
        ExternalReadEndpointContract {
            resource: ExternalReadResource::JobMetadata,
            endpoint: "/api/v1/organizations/{organization}/projects/{project}/pipelines"
                .to_owned(),
            query: BTreeMap::from([
                ("after".to_owned(), "exclusive pipeline slug".to_owned()),
                ("limit".to_owned(), "1..1000".to_owned()),
            ]),
            pagination: "stable lexical slug cursor".to_owned(),
        },
    ]
}

fn consumer(
    organization_id: Uuid,
    project_id: Uuid,
    identity_id: Uuid,
    generation: i64,
    expected_current_generation: Option<i64>,
    authority: ExternalReadAuthority,
) -> ExternalReadConsumerWrite {
    let mut write = ExternalReadConsumerWrite {
        organization_id,
        project_id,
        consumer_id: "owner-operator".to_owned(),
        generation,
        expected_current_generation,
        authority,
        source_inventory_digest: digest("mario-identity-clients-r2"),
        source_inventory_generation: "identity-clients-r2".to_owned(),
        source_endpoint: "http://100.127.170.90:18080".to_owned(),
        source_caller: "jenkins-principal:oracle-admin".to_owned(),
        target_identity_id: identity_id,
        target_subject: "service:owner-operator".to_owned(),
        target_api_base: "https://mcloving.example/api/v1".to_owned(),
        target_api_version: "v1".to_owned(),
        endpoint_contracts: contracts(),
        retention_semantics: "metadata follows controller retention; immutable objects return gone only after the retained metadata deadline".to_owned(),
        url_semantics: "all URLs are McLoving-relative authenticated v1 resources; Jenkins URLs are never returned".to_owned(),
        rate_limit_per_minute: 600,
        observation_started_unix_ms: 1_785_896_400_000,
        observation_ended_unix_ms: 1_785_900_000_000,
        source_reads_observed: if authority == ExternalReadAuthority::JenkinsSource { 7 } else { 0 },
        positive_authorization_digest: digest("positive-authz"),
        negative_authorization_digest: digest("negative-authz"),
        equivalence_digest: digest("historical-live-equivalence"),
        artifact_retrieval_digest: digest("artifact-retrieval"),
        pagination_resume_digest: digest("pagination-resume"),
        outage_behavior_digest: digest("outage-behavior"),
        rollback_from_generation: None,
        rollback_evidence_digest: None,
        reviewer: "reviewer:consumer-owner".to_owned(),
        actor_subject: "service:consumer-migrator".to_owned(),
        expected_contract_digest: [0; 32],
    };
    write.expected_contract_digest =
        compute_external_read_consumer_digest(&write).expect("canonical consumer digest");
    write
}

async fn fixture(store: &Store, slug: &str) -> (Uuid, Uuid, Uuid) {
    fixture_with_scopes(store, slug, [ServiceScope::ProjectRead].into()).await
}

async fn fixture_with_scopes(
    store: &Store,
    slug: &str,
    scopes: std::collections::BTreeSet<ServiceScope>,
) -> (Uuid, Uuid, Uuid) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            slug,
            project_id,
            "consumer migration fixture",
        )
        .await
        .expect("create consumer migration tenant");
    store
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id,
            subject: "service:owner-operator".to_owned(),
            scopes,
            actor_subject: "reviewer:consumer-owner".to_owned(),
        })
        .await
        .expect("provision target read identity");
    (organization_id, project_id, identity_id)
}

#[tokio::test]
async fn cutover_requires_zero_source_reads_and_rollback_restores_exact_authority() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (unauthorized_organization_id, unauthorized_project_id, unauthorized_identity_id) =
        fixture_with_scopes(
            &store,
            "consumer-unauthorized",
            [ServiceScope::BuildSubmit].into(),
        )
        .await;
    let unauthorized_source = consumer(
        unauthorized_organization_id,
        unauthorized_project_id,
        unauthorized_identity_id,
        1,
        None,
        ExternalReadAuthority::JenkinsSource,
    );
    store
        .install_external_read_consumer(&unauthorized_source)
        .await
        .expect("register source authority for an active but read-ineligible target");
    let unauthorized_target = consumer(
        unauthorized_organization_id,
        unauthorized_project_id,
        unauthorized_identity_id,
        2,
        Some(1),
        ExternalReadAuthority::McLovingTarget,
    );
    assert!(matches!(
        store
            .install_external_read_consumer(&unauthorized_target)
            .await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("lacks required project_view authority")
    ));

    let (organization_id, project_id, identity_id) = fixture(&store, "consumer-flow").await;

    let source = consumer(
        organization_id,
        project_id,
        identity_id,
        1,
        None,
        ExternalReadAuthority::JenkinsSource,
    );
    let source_receipt = store
        .install_external_read_consumer(&source)
        .await
        .expect("register retained Jenkins source authority");

    let mut lifecycle_tx = store.pool().begin().await.expect("begin lifecycle race");
    sqlx::query(
        "SELECT lifecycle_state FROM identities
         WHERE organization_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(identity_id)
    .fetch_one(&mut *lifecycle_tx)
    .await
    .expect("lock target identity before lifecycle transition");
    let raced_target = consumer(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalReadAuthority::McLovingTarget,
    );
    let raced_install = store.install_external_read_consumer(&raced_target);
    tokio::pin!(raced_install);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), raced_install.as_mut())
            .await
            .is_err(),
        "cutover must wait for an in-flight target lifecycle transition"
    );
    sqlx::query(
        "UPDATE identities
         SET lifecycle_state = 'disabled', lifecycle_generation = lifecycle_generation + 1
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id)
    .bind(identity_id)
    .execute(&mut *lifecycle_tx)
    .await
    .expect("disable the identity while holding its lifecycle lock");
    lifecycle_tx
        .commit()
        .await
        .expect("commit lifecycle transition");
    assert!(matches!(
        raced_install.await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("target identity is inactive")
    ));
    store
        .transition_identity_lifecycle(
            organization_id,
            identity_id,
            2,
            IdentityLifecycle::Active,
            "restore-target-after-contained-lifecycle-race",
            "operator:consumer-migration-test",
        )
        .await
        .expect("restore target identity after lifecycle race");

    let mut rebound = consumer(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalReadAuthority::McLovingTarget,
    );
    rebound.source_endpoint = "https://substituted.invalid/jenkins".to_owned();
    rebound.expected_contract_digest =
        compute_external_read_consumer_digest(&rebound).expect("rebound contract digest");
    assert!(matches!(
        store.install_external_read_consumer(&rebound).await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("binding changed")
    ));

    let mut residual = consumer(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalReadAuthority::McLovingTarget,
    );
    residual.source_reads_observed = 1;
    residual.expected_contract_digest =
        compute_external_read_consumer_digest(&residual).expect("residual digest");
    assert!(matches!(
        store.install_external_read_consumer(&residual).await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("zero residual Jenkins reads")
    ));

    let target = consumer(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalReadAuthority::McLovingTarget,
    );
    let target_receipt = store
        .install_external_read_consumer(&target)
        .await
        .expect("cut over read authority");
    assert_eq!(
        target_receipt.binding_digest, source_receipt.binding_digest,
        "an authority transition preserves the exact caller and endpoint binding"
    );
    store
        .transition_identity_lifecycle(
            organization_id,
            identity_id,
            3,
            IdentityLifecycle::Disabled,
            "contained-target-outage-before-source-restoration",
            "operator:consumer-rollback",
        )
        .await
        .expect("disable target identity to model a target-side outage");

    let mut invalid_rollback = consumer(
        organization_id,
        project_id,
        identity_id,
        3,
        Some(2),
        ExternalReadAuthority::JenkinsSource,
    );
    invalid_rollback.rollback_from_generation = Some(1);
    invalid_rollback.rollback_evidence_digest = Some(digest("rollback-drill"));
    invalid_rollback.expected_contract_digest =
        compute_external_read_consumer_digest(&invalid_rollback).expect("bad rollback digest");
    assert!(matches!(
        store
            .install_external_read_consumer(&invalid_rollback)
            .await,
        Err(StoreError::InvalidConsumerMigration(_))
    ));

    let mut rollback = invalid_rollback;
    rollback.rollback_from_generation = Some(2);
    rollback.expected_contract_digest =
        compute_external_read_consumer_digest(&rollback).expect("rollback digest");
    let receipt = store
        .install_external_read_consumer(&rollback)
        .await
        .expect("restore the exact source authority");
    assert_eq!(receipt.authority, ExternalReadAuthority::JenkinsSource);
    assert_eq!(receipt.generation, 3);
    assert_eq!(receipt.binding_digest, source_receipt.binding_digest);

    let current: (i64, String) = sqlx::query_as(
        "SELECT current.current_generation, version.authority
         FROM external_read_consumer_current AS current
         JOIN external_read_consumer_versions AS version
           ON version.organization_id = current.organization_id
          AND version.project_id = current.project_id
          AND version.consumer_id = current.consumer_id
          AND version.generation = current.current_generation
         WHERE current.organization_id = $1 AND current.project_id = $2
           AND current.consumer_id = 'owner-operator'",
    )
    .bind(organization_id)
    .bind(project_id)
    .fetch_one(store.pool())
    .await
    .expect("read current authority");
    assert_eq!(current, (3, "jenkins_source".to_owned()));

    let audit = store
        .verify_audit_chain(organization_id)
        .await
        .expect("consumer transitions preserve audit chain");
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "external_read_consumer.cut_over")
    );
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "external_read_consumer.rolled_back")
    );
}

#[tokio::test]
async fn contract_substitution_tenant_crossing_and_concurrent_first_generation_fail_closed() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, identity_id) = fixture(&store, "consumer-races").await;
    let source = consumer(
        organization_id,
        project_id,
        identity_id,
        1,
        None,
        ExternalReadAuthority::JenkinsSource,
    );
    let mut substituted = source.clone();
    substituted.source_endpoint = "https://attacker.invalid/jenkins".to_owned();
    assert!(matches!(
        store.install_external_read_consumer(&substituted).await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("digest does not match")
    ));

    let mut mislabeled_endpoint = source.clone();
    mislabeled_endpoint
        .endpoint_contracts
        .iter_mut()
        .find(|contract| contract.resource == ExternalReadResource::BuildStatus)
        .expect("build-status contract")
        .endpoint =
        "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/artifacts"
            .to_owned();
    assert!(matches!(
        compute_external_read_consumer_digest(&mislabeled_endpoint),
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("endpoint does not match its resource")
    ));

    let mut incomplete_artifact_content = source.clone();
    incomplete_artifact_content
        .endpoint_contracts
        .iter_mut()
        .find(|contract| contract.resource == ExternalReadResource::ArtifactContent)
        .expect("artifact-content contract")
        .query
        .remove("attempt_id");
    assert!(matches!(
        compute_external_read_consumer_digest(&incomplete_artifact_content),
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("query contract does not match its resource")
    ));

    let mut wrong_tenant = source.clone();
    wrong_tenant.organization_id = Uuid::new_v4();
    wrong_tenant.expected_contract_digest =
        compute_external_read_consumer_digest(&wrong_tenant).expect("cross-tenant digest");
    assert!(matches!(
        store.install_external_read_consumer(&wrong_tenant).await,
        Err(StoreError::InvalidConsumerMigration(message))
            if message.contains("project does not exist")
    ));

    let first = store.install_external_read_consumer(&source);
    let second = store.install_external_read_consumer(&source);
    let (left, right) = tokio::join!(first, second);
    let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
    assert_eq!(successes, 1, "only one first generation may commit");
    let conflict = if left.is_err() { left } else { right };
    assert!(matches!(
        conflict,
        Err(StoreError::ConsumerMigrationConflict(_))
    ));

    for table in [
        "external_read_consumer_versions",
        "external_read_consumer_current",
    ] {
        let can_write: bool = sqlx::query_scalar(
            "SELECT has_table_privilege('mcloving_tenant', $1, 'INSERT')
                    OR has_table_privilege('mcloving_tenant', $1, 'UPDATE')
                    OR has_table_privilege('mcloving_tenant', $1, 'DELETE')",
        )
        .bind(table)
        .fetch_one(store.pool())
        .await
        .expect("inspect runtime consumer-ledger privilege");
        assert!(!can_write, "runtime role must not mutate {table}");
    }
}
