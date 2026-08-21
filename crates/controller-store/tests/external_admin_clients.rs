#[path = "../../test-support/diff003.rs"]
mod diff003;

use std::collections::BTreeSet;
use std::time::Duration;

use mcloving_controller_store::{
    ExternalAdminAuthority, ExternalAdminClientWrite, ExternalAdminDisposition,
    ExternalAdminOperation, ExternalAdminOperationContract, IdentityLifecycle, NewServiceIdentity,
    Store, StoreError, authz::ServiceScope, compute_external_admin_client_digest,
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

fn inventory_digest() -> [u8; 32] {
    let bytes = hex::decode("a4227af8021c7d5fb6f7cc72be84af756ce1f95d33cd2ec9bad721beab587549")
        .expect("sealed inventory digest is valid hex");
    bytes
        .try_into()
        .expect("sealed inventory digest is SHA-256")
}

fn mapped_contract(
    operation: ExternalAdminOperation,
    method: &str,
    endpoint: &str,
    precondition: &str,
    idempotency: &str,
) -> ExternalAdminOperationContract {
    ExternalAdminOperationContract {
        operation,
        disposition: ExternalAdminDisposition::McLovingV1,
        method: Some(method.to_owned()),
        endpoint: Some(endpoint.to_owned()),
        precondition: Some(precondition.to_owned()),
        idempotency: Some(idempotency.to_owned()),
        desired_state_schema: Some("mcloving.public-api/v1".to_owned()),
        retirement_evidence_digest: None,
    }
}

fn contracts(retire_unsupported: bool) -> Vec<ExternalAdminOperationContract> {
    ExternalAdminOperation::ALL
        .into_iter()
        .map(|operation| match operation {
            ExternalAdminOperation::PipelinePut => mapped_contract(
                operation,
                "PUT",
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}",
                "if_match_revision",
                "desired_state_digest+revision",
            ),
            ExternalAdminOperation::BuildSubmit => mapped_contract(
                operation,
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/builds",
                "saved_revision+enabled_operational_generation",
                "parameters+idempotency_key",
            ),
            ExternalAdminOperation::PipelineDisable => mapped_contract(
                operation,
                "PUT",
                "/api/v1/organizations/{organization}/projects/{project}/pipelines/{pipeline}/state",
                "if_match_operational_generation",
                "transition_provenance+idempotency_key",
            ),
            ExternalAdminOperation::BuildCancel => mapped_contract(
                operation,
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/cancel",
                "build_state_fence",
                "build_id+cancel_state",
            ),
            ExternalAdminOperation::BuildRetry => mapped_contract(
                operation,
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/attempts/{attempt}/retry",
                "attempt_fence",
                "attempt_id+request_digest",
            ),
            ExternalAdminOperation::ApprovalCreate => mapped_contract(
                operation,
                "POST",
                "/api/v1/organizations/{organization}/projects/{project}/builds/{build}/approvals",
                "environment+action+expiry",
                "approval_id",
            ),
            _ if retire_unsupported => ExternalAdminOperationContract {
                operation,
                disposition: ExternalAdminDisposition::OwnerRetired,
                method: None,
                endpoint: None,
                precondition: None,
                idempotency: None,
                desired_state_schema: None,
                retirement_evidence_digest: Some(digest(operation_label(operation))),
            },
            _ => ExternalAdminOperationContract {
                operation,
                disposition: ExternalAdminDisposition::Pending,
                method: None,
                endpoint: None,
                precondition: None,
                idempotency: None,
                desired_state_schema: None,
                retirement_evidence_digest: None,
            },
        })
        .collect()
}

fn operation_label(operation: ExternalAdminOperation) -> &'static str {
    match operation {
        ExternalAdminOperation::ApprovalCreate => "approval-create-retired",
        ExternalAdminOperation::BuildCancel => "build-cancel-retired",
        ExternalAdminOperation::BuildPauseResume => "build-pause-resume-retired",
        ExternalAdminOperation::BuildRetry => "build-retry-retired",
        ExternalAdminOperation::BuildSubmit => "build-submit-retired",
        ExternalAdminOperation::BuildTerminate => "build-terminate-retired",
        ExternalAdminOperation::ControllerGlobalMutate => "controller-global-retired",
        ExternalAdminOperation::CredentialReferenceMutate => "credential-reference-retired",
        ExternalAdminOperation::FolderMutate => "folder-mutate-retired",
        ExternalAdminOperation::InputSubmit => "input-submit-retired",
        ExternalAdminOperation::NodeMutate => "node-mutate-retired",
        ExternalAdminOperation::PipelineDelete => "pipeline-delete-retired",
        ExternalAdminOperation::PipelineDisable => "pipeline-disable-retired",
        ExternalAdminOperation::PipelinePut => "pipeline-put-retired",
        ExternalAdminOperation::QueueReorder => "queue-reorder-retired",
    }
}

fn admin_client(
    organization_id: Uuid,
    project_id: Uuid,
    identity_id: Uuid,
    generation: i64,
    expected_current_generation: Option<i64>,
    authority: ExternalAdminAuthority,
    retire_unsupported: bool,
) -> ExternalAdminClientWrite {
    let mut write = ExternalAdminClientWrite {
        organization_id,
        project_id,
        client_id: "owner-operator".to_owned(),
        generation,
        expected_current_generation,
        authority,
        source_inventory_digest: inventory_digest(),
        source_inventory_generation: "inventory-20260731T064417Z-r2/identity-clients.yaml"
            .to_owned(),
        source_endpoint: "http://100.127.170.90:18080".to_owned(),
        source_caller: "jenkins-principal:oracle-admin".to_owned(),
        source_authentication: "jenkins-private-realm-session".to_owned(),
        source_scope: "owner-designated-oracle-controller".to_owned(),
        target_identity_id: identity_id,
        target_subject: "service:owner-operator-admin".to_owned(),
        target_api_base: "https://mcloving.example/api/v1".to_owned(),
        target_api_version: "v1".to_owned(),
        operation_contracts: contracts(retire_unsupported),
        observation_started_unix_ms: 1_785_896_400_000,
        observation_ended_unix_ms: 1_785_900_000_000,
        source_writes_observed: if authority == ExternalAdminAuthority::JenkinsSource {
            3
        } else {
            0
        },
        positive_authorization_digest: digest("admin-positive-authorization"),
        negative_authorization_digest: digest("admin-negative-authorization"),
        convergence_digest: digest("admin-create-update-delete-convergence"),
        ordering_idempotency_digest: digest("admin-duplicate-reordered-stale"),
        partial_failure_retry_digest: digest("admin-partial-failure-retry"),
        conflict_digest: digest("admin-conflict-denial"),
        rollback_from_generation: None,
        rollback_evidence_digest: None,
        reviewer: "reviewer:admin-owner".to_owned(),
        actor_subject: "service:admin-migrator".to_owned(),
        expected_contract_digest: [0; 32],
    };
    write.expected_contract_digest =
        compute_external_admin_client_digest(&write).expect("canonical admin client digest");
    write
}

async fn fixture(store: &Store, slug: &str, scopes: BTreeSet<ServiceScope>) -> (Uuid, Uuid, Uuid) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("{slug}-{organization_id}"),
            project_id,
            "admin migration fixture",
        )
        .await
        .expect("create admin migration tenant");
    store
        .provision_service_identity(&NewServiceIdentity {
            organization_id,
            identity_id,
            subject: "service:owner-operator-admin".to_owned(),
            scopes,
            actor_subject: "reviewer:admin-owner".to_owned(),
        })
        .await
        .expect("provision target admin identity");
    (organization_id, project_id, identity_id)
}

fn admin_scopes() -> BTreeSet<ServiceScope> {
    [
        ServiceScope::ProjectAdmin,
        ServiceScope::BuildSubmit,
        ServiceScope::BuildCancel,
    ]
    .into()
}

#[tokio::test]
async fn cutover_requires_zero_writes_complete_dispositions_and_exact_authority() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (pending_organization_id, pending_project_id, pending_identity_id) =
        fixture(&store, "admin-pending", admin_scopes()).await;
    let pending_source = admin_client(
        pending_organization_id,
        pending_project_id,
        pending_identity_id,
        1,
        None,
        ExternalAdminAuthority::JenkinsSource,
        false,
    );
    store
        .install_external_admin_client(&pending_source)
        .await
        .expect("register source authority with pending operations");
    let pending_target = admin_client(
        pending_organization_id,
        pending_project_id,
        pending_identity_id,
        2,
        Some(1),
        ExternalAdminAuthority::McLovingTarget,
        false,
    );
    assert!(matches!(
        store.install_external_admin_client(&pending_target).await,
        Err(StoreError::InvalidAdminMigration(message)) if message.contains("migrated or owner-retired")
    ));

    let (organization_id, project_id, identity_id) =
        fixture(&store, "admin-flow", admin_scopes()).await;
    let source = admin_client(
        organization_id,
        project_id,
        identity_id,
        1,
        None,
        ExternalAdminAuthority::JenkinsSource,
        false,
    );
    let source_receipt = store
        .install_external_admin_client(&source)
        .await
        .expect("register Jenkins admin authority");

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
    let raced_target = admin_client(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalAdminAuthority::McLovingTarget,
        true,
    );
    let raced_install = store.install_external_admin_client(&raced_target);
    tokio::pin!(raced_install);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), raced_install.as_mut())
            .await
            .is_err(),
        "admin cutover must wait for an in-flight target lifecycle transition"
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
    .expect("disable target identity while holding its row lock");
    lifecycle_tx
        .commit()
        .await
        .expect("commit lifecycle transition");
    assert!(matches!(
        raced_install.await,
        Err(StoreError::InvalidAdminMigration(message)) if message.contains("target identity is inactive")
    ));
    store
        .transition_identity_lifecycle(
            organization_id,
            identity_id,
            2,
            IdentityLifecycle::Active,
            "restore-target-after-contained-admin-race",
            "operator:admin-migration-test",
        )
        .await
        .expect("restore target identity after contained race");

    let mut pending = admin_client(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalAdminAuthority::McLovingTarget,
        true,
    );
    pending.source_writes_observed = 1;
    pending.expected_contract_digest =
        compute_external_admin_client_digest(&pending).expect("residual-write digest");
    let residual_result = store.install_external_admin_client(&pending).await;
    let residual_write_denied = matches!(
        residual_result,
        Err(StoreError::InvalidAdminMigration(message))
            if message.contains("zero residual Jenkins writes")
    );
    assert!(residual_write_denied);
    diff003::record_assertion(
        "admin_residual_jenkins_write_denied",
        "denied",
        serde_json::json!({
            "source_writes_observed": pending.source_writes_observed,
            "requested_authority": pending.authority,
            "result": "zero_residual_writes_required",
        }),
        residual_write_denied,
    );

    pending.source_writes_observed = 0;
    pending.expected_contract_digest =
        compute_external_admin_client_digest(&pending).expect("target digest");
    let target_receipt = store
        .install_external_admin_client(&pending)
        .await
        .expect("cut over the fully classified admin client");
    assert_eq!(target_receipt.binding_digest, source_receipt.binding_digest);

    let mut rollback = admin_client(
        organization_id,
        project_id,
        identity_id,
        3,
        Some(2),
        ExternalAdminAuthority::JenkinsSource,
        true,
    );
    rollback.rollback_from_generation = Some(2);
    rollback.rollback_evidence_digest = Some(digest("contained-admin-rollback"));
    rollback.expected_contract_digest =
        compute_external_admin_client_digest(&rollback).expect("rollback digest");
    let rollback_receipt = store
        .install_external_admin_client(&rollback)
        .await
        .expect("restore exact Jenkins admin authority");
    assert_eq!(
        rollback_receipt.binding_digest,
        source_receipt.binding_digest
    );
    assert_eq!(
        rollback_receipt.authority,
        ExternalAdminAuthority::JenkinsSource
    );
    let rollback_restored = rollback_receipt.authority == ExternalAdminAuthority::JenkinsSource
        && rollback_receipt.generation == 3
        && rollback_receipt.binding_digest == source_receipt.binding_digest;
    diff003::record_assertion(
        "admin_rollback_restored",
        "restored",
        serde_json::json!({
            "restored_generation": rollback_receipt.generation,
            "restored_authority": rollback_receipt.authority,
            "binding_preserved": rollback_receipt.binding_digest == source_receipt.binding_digest,
        }),
        rollback_restored,
    );

    let audit = store
        .verify_audit_chain(organization_id)
        .await
        .expect("admin transitions preserve the audit chain");
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "external_admin_client.cut_over")
    );
    assert!(
        audit
            .events
            .iter()
            .any(|event| event.action == "external_admin_client.rolled_back")
    );
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        let trigger_receipt = std::fs::read(std::path::Path::new(&root).join("TRIG-001.json"))
            .expect("read live DIFF-003 trigger receipt");
        let trigger: serde_json::Value =
            serde_json::from_slice(&trigger_receipt).expect("parse live DIFF-003 trigger receipt");
        std::fs::write(
            std::path::Path::new(&root).join("ADMIN-001.json"),
            diff003::receipt(
                "ADMIN-001",
                serde_json::json!({
                    "source": {
                        "client_id": source_receipt.client_id,
                        "generation": source_receipt.generation,
                        "authority": source_receipt.authority,
                        "binding_digest": source_receipt.binding_digest,
                        "contract_digest": source_receipt.contract_digest,
                    },
                    "target": {
                        "client_id": target_receipt.client_id,
                        "generation": target_receipt.generation,
                        "authority": target_receipt.authority,
                        "binding_digest": target_receipt.binding_digest,
                        "contract_digest": target_receipt.contract_digest,
                    },
                    "rollback": {
                        "client_id": rollback_receipt.client_id,
                        "generation": rollback_receipt.generation,
                        "authority": rollback_receipt.authority,
                        "binding_digest": rollback_receipt.binding_digest,
                        "contract_digest": rollback_receipt.contract_digest,
                    },
                    "trigger_receipt_sha256": format!("{:x}", Sha256::digest(&trigger_receipt)),
                    "trigger_id": trigger["trigger_id"],
                    "trigger_organization_id": trigger["organization_id"],
                    "trigger_project_id": trigger["project_id"],
                    "trigger_pipeline_id": trigger["pipeline_id"],
                }),
            ),
        )
        .expect("write DIFF-003 admin receipts");
    }
}

#[tokio::test]
async fn target_identity_must_hold_every_mapped_write_action() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, identity_id) = fixture(
        &store,
        "admin-least-authority",
        [ServiceScope::ProjectAdmin].into(),
    )
    .await;
    let source = admin_client(
        organization_id,
        project_id,
        identity_id,
        1,
        None,
        ExternalAdminAuthority::JenkinsSource,
        true,
    );
    store
        .install_external_admin_client(&source)
        .await
        .expect("register source authority");
    let target = admin_client(
        organization_id,
        project_id,
        identity_id,
        2,
        Some(1),
        ExternalAdminAuthority::McLovingTarget,
        true,
    );
    assert!(matches!(
        store.install_external_admin_client(&target).await,
        Err(StoreError::InvalidAdminMigration(message))
            if message.contains("lacks required build_trigger authority")
                || message.contains("lacks required build_cancel authority")
    ));
}

#[tokio::test]
async fn substitution_omission_stale_generation_and_cross_tenant_reads_fail_closed() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, identity_id) =
        fixture(&store, "admin-hardening", admin_scopes()).await;
    let source = admin_client(
        organization_id,
        project_id,
        identity_id,
        1,
        None,
        ExternalAdminAuthority::JenkinsSource,
        false,
    );
    let mut substituted = source.clone();
    substituted.source_endpoint = "https://substituted.invalid/jenkins".to_owned();
    let substitution_result = store.install_external_admin_client(&substituted).await;
    let target_substitution_denied = matches!(
        substitution_result,
        Err(StoreError::InvalidAdminMigration(message))
            if message.contains("digest does not match")
    );
    assert!(target_substitution_denied);
    diff003::record_assertion(
        "admin_target_substitution_denied",
        "denied",
        serde_json::json!({
            "presented_source_endpoint": substituted.source_endpoint,
            "expected_contract_digest": substituted.expected_contract_digest,
            "result": "contract_digest_mismatch",
        }),
        target_substitution_denied,
    );

    let mut omitted = source.clone();
    omitted.operation_contracts.pop();
    assert!(matches!(
        compute_external_admin_client_digest(&omitted),
        Err(StoreError::InvalidAdminMigration(message)) if message.contains("classify every canonical")
    ));

    let first = store.install_external_admin_client(&source);
    let second = store.install_external_admin_client(&source);
    let (left, right) = tokio::join!(first, second);
    assert_eq!(
        usize::from(left.is_ok()) + usize::from(right.is_ok()),
        1,
        "only one first admin generation may commit"
    );
    let conflict = if left.is_err() { left } else { right };
    assert!(matches!(
        conflict,
        Err(StoreError::AdminMigrationConflict(_))
    ));
    let stale = admin_client(
        organization_id,
        project_id,
        identity_id,
        2,
        None,
        ExternalAdminAuthority::McLovingTarget,
        true,
    );
    assert!(matches!(
        store.install_external_admin_client(&stale).await,
        Err(StoreError::AdminMigrationConflict(_))
    ));

    let foreign_organization = Uuid::new_v4();
    let foreign_project = Uuid::new_v4();
    store
        .create_project(
            foreign_organization,
            &format!("admin-foreign-{foreign_organization}"),
            foreign_project,
            "foreign admin migration tenant",
        )
        .await
        .expect("create foreign tenant");
    let mut tx = store
        .pool()
        .begin()
        .await
        .expect("open foreign tenant transaction");
    sqlx::query("SET LOCAL ROLE mcloving_tenant")
        .execute(&mut *tx)
        .await
        .expect("use the constrained runtime role");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(foreign_organization.to_string())
        .execute(&mut *tx)
        .await
        .expect("scope foreign tenant transaction");
    let visible: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM external_admin_client_versions WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&mut *tx)
    .await
    .expect("query forced-RLS admin history");
    assert_eq!(
        visible, 0,
        "foreign tenant cannot read admin migration history"
    );
    tx.rollback().await.expect("rollback foreign read");

    assert!(
        sqlx::query(
            "UPDATE external_admin_client_versions SET reviewer = 'tampered'
             WHERE organization_id = $1 AND project_id = $2 AND client_id = 'owner-operator'",
        )
        .bind(organization_id)
        .bind(project_id)
        .execute(store.pool())
        .await
        .is_err(),
        "admin migration history is immutable"
    );
}
