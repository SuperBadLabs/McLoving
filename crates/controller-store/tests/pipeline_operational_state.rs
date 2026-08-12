use std::str::FromStr;

use mcloving_controller_store::{
    AGENT_SESSIONS_V7, ARTIFACT_METADATA_V12, ATTEMPT_CREDENTIALS_V10, ATTEMPT_READINESS_V18,
    AUTHORIZATION_MAPPING_V24, CONTROLLER_SCHEMA_V1, CREDENTIAL_NAMESPACE_V22, ClaimRequest,
    DURABLE_RETRY_V4, DagNodeKind, EXTERNAL_ADMIN_CLIENTS_V26, EXTERNAL_READ_CONSUMERS_V25,
    EffectClass, EffectStatus, GLOBAL_LOG_ORDER_V16, IDENTITY_LIFECYCLE_V19,
    IDENTITY_SESSION_LINEAGE_V21, IDENTITY_SESSION_REFRESH_V20, NODE_TRUST_POOL_V8,
    NORMALIZED_TEST_RESULTS_V13, NewCredentialGrant, NewDagBuild, NewDagNode,
    NewEnvironmentApproval, OBJECT_PUBLICATION_FENCE_V14, OBJECT_REFERENCES_V5, PIPELINE_DAG_V9,
    PIPELINE_OPERATIONAL_STATE_V27, PRODUCT_SURFACE_V15, PUBLIC_API_V3, PipelineOperationalState,
    PipelineOperationalStateTransition, PipelineOperationalStateTransitionOutcome,
    PipelinePutOutcome, PipelineWrite, RECOVERY_OPERATIONS_V6, RUNTIME_FUNCTION_BOUNDARY_V23,
    RetryDecision, STATE_TRANSFER_V17, Store, StoreError, TENANT_AUDIT_V11, TENANT_SECURITY_V2,
    TerminalOutcome,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

const SOURCE: &str = r#"version: 1
name: state-test
stages:
  - id: run
    name: Run
    steps:
      - process:
          program: echo
          args: [ok]
"#;

async fn test_store() -> Option<Store> {
    let url = std::env::var("MCLOVING_TEST_DATABASE_URL").ok()?;
    let pool = PgPoolOptions::new()
        .max_connections(16)
        .connect(&url)
        .await
        .expect("connect to the explicitly configured PostgreSQL test database");
    let store = Store::new(pool);
    store.migrate().await.expect("install controller schema");
    Some(store)
}

fn pipeline_write(organization_id: Uuid, project_id: Uuid, pipeline_id: Uuid) -> PipelineWrite {
    PipelineWrite {
        organization_id,
        project_id,
        pipeline_id,
        slug: format!("pipeline-{pipeline_id}"),
        source: SOURCE.to_owned(),
        source_sha256: Sha256::digest(SOURCE.as_bytes()).into(),
        semantic_digest: Sha256::digest(b"pipeline-semantic-v1").into(),
        schema_major: 1,
        schema_minor: 0,
        parameter_schema: json!({}),
    }
}

fn transition(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    expected_generation: i64,
    state: PipelineOperationalState,
    idempotency_key: &str,
) -> PipelineOperationalStateTransition {
    PipelineOperationalStateTransition {
        organization_id,
        project_id,
        pipeline_id,
        expected_generation,
        state,
        reason: format!(
            "reviewed transition to {}",
            match state {
                PipelineOperationalState::Enabled => "enabled",
                PipelineOperationalState::Disabled => "disabled",
            }
        ),
        actor_subject: "operator@example.test".to_owned(),
        source_identity: "test:operator".to_owned(),
        source_generation: format!("source:{expected_generation}"),
        source_effective_at_unix_ms: 1_800_000_000_000 + expected_generation,
        source_provenance_sha256: Sha256::digest(idempotency_key.as_bytes()).into(),
        idempotency_key: idempotency_key.to_owned(),
    }
}

fn dag(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    generation: i64,
    idempotency_key: &str,
) -> NewDagBuild {
    NewDagBuild {
        organization_id,
        project_id,
        pipeline_id,
        pipeline_revision: 1,
        pipeline_operational_generation: generation,
        idempotency_key: idempotency_key.to_owned(),
        pipeline_digest: Sha256::digest(b"pipeline-semantic-v1").into(),
        priority: 0,
        nodes: vec![NewDagNode {
            node_key: "run".to_owned(),
            kind: DagNodeKind::Work,
            dependencies: Vec::new(),
            required_capabilities: Vec::new(),
            required_platform: "linux".to_owned(),
            required_trust_pool: "trusted-linux".to_owned(),
            priority: 0,
            execution_spec: json!({"process": "echo ok"}),
            fail_fast: true,
            max_attempts: 2,
        }],
    }
}

#[tokio::test]
async fn transitions_admission_scheduler_restart_and_audit_are_generation_fenced() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "jobstate",
        )
        .await
        .expect("create tenant and project");
    assert!(matches!(
        store
            .put_pipeline_as(
                &pipeline_write(organization_id, project_id, pipeline_id),
                Some(0),
                "creator@example.test",
            )
            .await
            .expect("create enabled pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    let initial = store
        .pipeline_operational_state(organization_id, project_id, pipeline_id)
        .await
        .expect("read initial state")
        .expect("initial state exists");
    assert_eq!(initial.state, PipelineOperationalState::Enabled);
    assert_eq!(initial.generation, 1);
    assert!(initial.audit_sequence.is_some());
    assert!(initial.audit_event_hash.is_some());
    let mut wrong_digest = dag(
        organization_id,
        project_id,
        pipeline_id,
        1,
        "wrong-saved-revision-digest",
    );
    wrong_digest.pipeline_digest = Sha256::digest(b"counterfeit semantic digest").into();
    assert!(matches!(
        store.admit_dag(&wrong_digest).await,
        Err(StoreError::PipelineStateConflict(_))
    ));

    let disable = transition(
        organization_id,
        project_id,
        pipeline_id,
        1,
        PipelineOperationalState::Disabled,
        "disable-1",
    );
    let mut disable = disable;
    disable.source_identity = "jenkins:jobstate-import".to_owned();
    disable.source_generation = "jenkins:42".to_owned();
    let disabled = match store
        .transition_pipeline_operational_state(&disable)
        .await
        .expect("disable pipeline")
    {
        PipelineOperationalStateTransitionOutcome::Applied(record) => record,
        other => panic!("unexpected disable outcome: {other:?}"),
    };
    assert_eq!(disabled.generation, 2);
    assert_eq!(disabled.state, PipelineOperationalState::Disabled);
    assert!(matches!(
        store
            .transition_pipeline_operational_state(&disable)
            .await
            .expect("replay exact disable"),
        PipelineOperationalStateTransitionOutcome::Idempotent(ref record)
            if record == &disabled
    ));

    let mut divergent = disable.clone();
    divergent.reason = "different reviewed reason".to_owned();
    assert!(matches!(
        store
            .transition_pipeline_operational_state(&divergent)
            .await,
        Err(StoreError::PipelineStateConflict(_))
    ));
    let stale = transition(
        organization_id,
        project_id,
        pipeline_id,
        1,
        PipelineOperationalState::Enabled,
        "stale-enable",
    );
    assert!(matches!(
        store
            .transition_pipeline_operational_state(&stale)
            .await
            .expect("stale transition is a typed outcome"),
        PipelineOperationalStateTransitionOutcome::PreconditionFailed {
            current_generation: 2
        }
    ));
    assert!(matches!(
        store
            .admit_dag(&dag(
                organization_id,
                project_id,
                pipeline_id,
                1,
                "disabled-admission",
            ))
            .await,
        Err(StoreError::PipelineDisabled {
            pipeline_id: denied_pipeline,
            generation: 2
        }) if denied_pipeline == pipeline_id
    ));

    let enable = transition(
        organization_id,
        project_id,
        pipeline_id,
        2,
        PipelineOperationalState::Enabled,
        "enable-2",
    );
    let mut enable = enable;
    enable.source_identity = "rollback:restore".to_owned();
    enable.source_generation = "rollback:receipt-7".to_owned();
    let enabled = match store
        .transition_pipeline_operational_state(&enable)
        .await
        .expect("re-enable pipeline")
    {
        PipelineOperationalStateTransitionOutcome::Applied(record) => record,
        other => panic!("unexpected enable outcome: {other:?}"),
    };
    assert_eq!(enabled.generation, 3);
    assert_eq!(enabled.source_identity, "rollback:restore");
    assert!(matches!(
        store
            .admit_dag(&dag(
                organization_id,
                project_id,
                pipeline_id,
                1,
                "stale-generation-admission",
            ))
            .await,
        Err(StoreError::PipelineStateConflict(_))
    ));
    let admission = store
        .admit_dag(&dag(
            organization_id,
            project_id,
            pipeline_id,
            3,
            "enabled-admission",
        ))
        .await
        .expect("admit exact enabled generation");
    assert!(admission.created);

    let disable_again = transition(
        organization_id,
        project_id,
        pipeline_id,
        3,
        PipelineOperationalState::Disabled,
        "disable-3",
    );
    assert!(matches!(
        store
            .transition_pipeline_operational_state(&disable_again)
            .await
            .expect("disable admitted pipeline"),
        PipelineOperationalStateTransitionOutcome::Applied(ref record)
            if record.generation == 4
    ));
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-a".to_owned(),
                agent_id: "agent-a".to_owned(),
                capabilities: vec!["platform:linux".to_owned()],
                trust_pool: "trusted-linux".to_owned(),
                lease_seconds: 30,
                fairness_seed: 0,
            })
            .await
            .expect("disabled scheduler query")
            .is_none()
    );

    let replica = Store::new(store.pool().clone());
    let replica_state = replica
        .pipeline_operational_state(organization_id, project_id, pipeline_id)
        .await
        .expect("active-active read")
        .expect("state exists on replica");
    assert_eq!(replica_state.generation, 4);
    assert_eq!(replica_state.state, PipelineOperationalState::Disabled);
    let audit = store
        .export_audit_events(organization_id)
        .await
        .expect("export audit");
    for state in [&initial, &disabled, &enabled, &replica_state] {
        let Some(sequence) = state.audit_sequence else {
            panic!("runtime state must link audit");
        };
        let event = audit
            .events
            .iter()
            .find(|event| event.sequence == sequence)
            .expect("state audit event exists");
        assert_eq!(Some(event.event_hash), state.audit_event_hash);
    }

    let immutable_error = sqlx::query(
        "UPDATE pipeline_operational_state_history
         SET reason = 'counterfeit'
         WHERE organization_id = $1 AND pipeline_id = $2 AND generation = 2",
    )
    .bind(organization_id)
    .bind(pipeline_id)
    .execute(store.pool())
    .await
    .expect_err("state history is immutable");
    assert_eq!(
        immutable_error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref(),
        Some("23514")
    );
}

#[tokio::test]
async fn trigger_disable_and_scheduler_disable_races_never_cross_the_committed_fence() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "jobstate-races",
        )
        .await
        .expect("create race tenant and project");
    assert!(matches!(
        store
            .put_pipeline(
                &pipeline_write(organization_id, project_id, pipeline_id),
                Some(0),
            )
            .await
            .expect("create race pipeline"),
        PipelinePutOutcome::Created(_)
    ));

    let racing_admission = dag(
        organization_id,
        project_id,
        pipeline_id,
        1,
        "trigger-disable-race",
    );
    let racing_disable = transition(
        organization_id,
        project_id,
        pipeline_id,
        1,
        PipelineOperationalState::Disabled,
        "trigger-disable-fence",
    );
    let (admission_result, disable_result) = tokio::join!(
        store.admit_dag(&racing_admission),
        store.transition_pipeline_operational_state(&racing_disable),
    );
    assert!(matches!(
        disable_result.expect("disable race commits"),
        PipelineOperationalStateTransitionOutcome::Applied(ref record)
            if record.generation == 2
    ));
    match admission_result {
        Ok(admission) => assert!(admission.created, "admission serialized before disable"),
        Err(StoreError::PipelineDisabled { generation: 2, .. }) => {}
        other => panic!("unexpected trigger/disable race result: {other:?}"),
    }
    assert!(
        store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-after-trigger-race".to_owned(),
                agent_id: "agent-after-trigger-race".to_owned(),
                capabilities: vec!["platform:linux".to_owned()],
                trust_pool: "trusted-linux".to_owned(),
                lease_seconds: 30,
                fairness_seed: 0,
            })
            .await
            .expect("post-fence scheduler query")
            .is_none(),
        "even a pre-fence admission cannot be scheduled after the disable commit"
    );

    let enabled = match store
        .transition_pipeline_operational_state(&transition(
            organization_id,
            project_id,
            pipeline_id,
            2,
            PipelineOperationalState::Enabled,
            "race-reenable",
        ))
        .await
        .expect("re-enable for scheduler race")
    {
        PipelineOperationalStateTransitionOutcome::Applied(record) => record,
        other => panic!("unexpected re-enable outcome: {other:?}"),
    };
    assert_eq!(enabled.generation, 3);
    store
        .admit_dag(&dag(
            organization_id,
            project_id,
            pipeline_id,
            3,
            "scheduler-disable-race",
        ))
        .await
        .expect("admit scheduler-race build");
    let claim_request = ClaimRequest {
        organization_id,
        scheduler_id: "scheduler-race".to_owned(),
        agent_id: "agent-race".to_owned(),
        capabilities: vec!["platform:linux".to_owned()],
        trust_pool: "trusted-linux".to_owned(),
        lease_seconds: 30,
        fairness_seed: 0,
    };
    let scheduler_disable = transition(
        organization_id,
        project_id,
        pipeline_id,
        3,
        PipelineOperationalState::Disabled,
        "scheduler-disable-fence",
    );
    let (claim_result, disable_result) = tokio::join!(
        store.claim_next(&claim_request),
        store.transition_pipeline_operational_state(&scheduler_disable),
    );
    assert!(matches!(
        disable_result.expect("scheduler disable commits"),
        PipelineOperationalStateTransitionOutcome::Applied(ref record)
            if record.generation == 4
    ));
    if let Some(claim) = claim_result.expect("scheduler race query") {
        assert!(
            !store
                .accept_offer(
                    organization_id,
                    claim.attempt_id,
                    claim.fence,
                    claim.restore_epoch,
                    &claim.agent_id,
                )
                .await
                .expect("post-fence offer acceptance"),
            "an offer serialized before disable must lose authority after disable commits"
        );
    }
}

#[tokio::test]
async fn disable_revokes_approval_grant_delivery_effect_and_retry_authority() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let agent_id = format!("agent-authority-fence-{organization_id}");
    let pipeline_digest: [u8; 32] = Sha256::digest(b"pipeline-semantic-v1").into();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            "jobstate-authority",
        )
        .await
        .expect("create authority tenant and project");
    assert!(matches!(
        store
            .put_pipeline(
                &pipeline_write(organization_id, project_id, pipeline_id),
                Some(0),
            )
            .await
            .expect("create authority pipeline"),
        PipelinePutOutcome::Created(_)
    ));
    store
        .configure_protected_environment(organization_id, project_id, "production", "deploy", 0)
        .await
        .expect("configure zero-approval protected environment");
    let admission = store
        .admit_dag(&dag(
            organization_id,
            project_id,
            pipeline_id,
            1,
            "authority-fence-build",
        ))
        .await
        .expect("admit authority-fence build");
    assert!(
        store
            .open_agent_session(
                &agent_id,
                "trusted-linux",
                1,
                3,
                &[
                    "work-delivery-v1".to_owned(),
                    "attempt-credentials-v1".to_owned(),
                ],
                &["platform:linux".to_owned()],
            )
            .await
            .expect("open authority-fence agent session")
    );
    let claim = store
        .claim_next(&ClaimRequest {
            organization_id,
            scheduler_id: "scheduler-authority-fence".to_owned(),
            agent_id: agent_id.clone(),
            capabilities: vec!["platform:linux".to_owned()],
            trust_pool: "trusted-linux".to_owned(),
            lease_seconds: 30,
            fairness_seed: 0,
        })
        .await
        .expect("claim authority-fence build")
        .expect("authority-fence claim exists");
    let pre_fence_grant = NewCredentialGrant {
        id: Uuid::new_v4(),
        organization_id,
        project_id,
        build_id: admission.build_id,
        attempt_id: claim.attempt_id,
        fence: claim.fence,
        pipeline_digest,
        environment: "production",
        action: "deploy",
        target_name: "DEPLOY_TOKEN",
        secret_value: b"pre-fence-secret",
        approval_ids: &[],
        ttl_seconds: 300,
    };
    assert!(
        store
            .issue_credential_grant(&pre_fence_grant)
            .await
            .expect("issue pre-fence grant")
    );
    assert!(
        store
            .accept_offer_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                1,
            )
            .await
            .expect("accept pre-fence offer")
    );
    assert!(matches!(
        store
            .transition_pipeline_operational_state(&transition(
                organization_id,
                project_id,
                pipeline_id,
                1,
                PipelineOperationalState::Disabled,
                "authority-disable-fence",
            ))
            .await
            .expect("commit authority disable"),
        PipelineOperationalStateTransitionOutcome::Applied(ref record)
            if record.generation == 2
    ));

    assert!(
        !store
            .approve_environment(&NewEnvironmentApproval {
                id: Uuid::new_v4(),
                organization_id,
                project_id,
                build_id: admission.build_id,
                pipeline_digest,
                environment: "production",
                action: "deploy",
                approver_subject: "operator@example.test",
                ttl_seconds: 300,
            })
            .await
            .expect("post-fence approval denial")
    );
    let post_fence_grant = NewCredentialGrant {
        id: Uuid::new_v4(),
        target_name: "SECOND_TOKEN",
        secret_value: b"post-fence-secret",
        ..pre_fence_grant
    };
    assert!(
        !store
            .issue_credential_grant(&post_fence_grant)
            .await
            .expect("post-fence grant denial")
    );
    assert!(
        store
            .redeem_credential_grants(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                1,
                &["DEPLOY_TOKEN".to_owned()],
            )
            .await
            .expect("post-fence credential delivery denial")
            .is_none()
    );
    assert!(
        !store
            .checkpoint_effect(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                "deploy:production",
                EffectClass::ExternallyIdempotent,
                EffectStatus::Prepared,
                &json!({"deployment": "blocked"}),
            )
            .await
            .expect("post-fence effect denial")
    );
    assert!(
        store
            .finalize_attempt_in_session(
                organization_id,
                claim.attempt_id,
                claim.fence,
                claim.restore_epoch,
                &claim.agent_id,
                1,
                TerminalOutcome::Failed,
                json!({"reason": "disabled"}),
            )
            .await
            .expect("terminal truth remains recordable after fence")
    );
    assert_eq!(
        store
            .schedule_retry(organization_id, claim.attempt_id, 3, "post-fence retry")
            .await
            .expect("post-fence retry denial"),
        RetryDecision::Ineligible
    );
}

#[tokio::test]
async fn migration_0027_backfills_existing_enabled_pipelines_and_freezes_unbound_builds() {
    let Ok(url) = std::env::var("MCLOVING_TEST_DATABASE_URL") else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let base_options = PgConnectOptions::from_str(&url).expect("parse PostgreSQL test URL");
    let database = format!("jobstate_{}", Uuid::new_v4().simple());
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(base_options.clone().database("postgres"))
        .await
        .expect("connect to PostgreSQL administrative database");
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .expect("create isolated previous-schema database");
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(base_options.clone().database(&database))
        .await
        .expect("connect to isolated previous-schema database");
    let migrations: &[(i32, &str)] = &[
        (1, CONTROLLER_SCHEMA_V1),
        (2, TENANT_SECURITY_V2),
        (3, PUBLIC_API_V3),
        (4, DURABLE_RETRY_V4),
        (5, OBJECT_REFERENCES_V5),
        (6, RECOVERY_OPERATIONS_V6),
        (7, AGENT_SESSIONS_V7),
        (8, NODE_TRUST_POOL_V8),
        (9, PIPELINE_DAG_V9),
        (10, ATTEMPT_CREDENTIALS_V10),
        (11, TENANT_AUDIT_V11),
        (12, ARTIFACT_METADATA_V12),
        (13, NORMALIZED_TEST_RESULTS_V13),
        (14, OBJECT_PUBLICATION_FENCE_V14),
        (15, PRODUCT_SURFACE_V15),
        (16, GLOBAL_LOG_ORDER_V16),
        (17, STATE_TRANSFER_V17),
        (18, ATTEMPT_READINESS_V18),
        (19, IDENTITY_LIFECYCLE_V19),
        (20, IDENTITY_SESSION_REFRESH_V20),
        (21, IDENTITY_SESSION_LINEAGE_V21),
        (22, CREDENTIAL_NAMESPACE_V22),
        (23, RUNTIME_FUNCTION_BOUNDARY_V23),
        (24, AUTHORIZATION_MAPPING_V24),
        (25, EXTERNAL_READ_CONSUMERS_V25),
        (26, EXTERNAL_ADMIN_CLIENTS_V26),
    ];
    let mut tx = pool.begin().await.expect("begin previous-schema migration");
    sqlx::query(
        "CREATE TABLE mcloving_schema_migrations (
             version integer PRIMARY KEY,
             installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
         )",
    )
    .execute(&mut *tx)
    .await
    .expect("create migration ledger");
    for (version, migration) in migrations {
        sqlx::raw_sql(migration)
            .execute(&mut *tx)
            .await
            .unwrap_or_else(|error| panic!("apply migration {version}: {error}"));
        sqlx::query("INSERT INTO mcloving_schema_migrations (version) VALUES ($1)")
            .bind(version)
            .execute(&mut *tx)
            .await
            .expect("record previous migration");
    }
    tx.commit().await.expect("commit previous schema");

    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let build_id = Uuid::new_v4();
    sqlx::query("INSERT INTO organizations (id, slug) VALUES ($1, $2)")
        .bind(organization_id)
        .bind(format!("org-{organization_id}"))
        .execute(&pool)
        .await
        .expect("insert previous organization");
    sqlx::query("INSERT INTO projects (id, organization_id, slug) VALUES ($1, $2, 'project')")
        .bind(project_id)
        .bind(organization_id)
        .execute(&pool)
        .await
        .expect("insert previous project");
    sqlx::query(
        "INSERT INTO pipeline_definitions (
             organization_id, project_id, pipeline_id, slug
         ) VALUES ($1, $2, $3, 'existing')",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(pipeline_id)
    .execute(&pool)
    .await
    .expect("insert previous pipeline definition");
    let source_digest = Sha256::digest(SOURCE.as_bytes());
    let semantic_digest = Sha256::digest(b"pipeline-semantic-v1");
    sqlx::query(
        "INSERT INTO pipeline_revisions (
             organization_id, project_id, pipeline_id, revision, source,
             source_sha256, semantic_digest, schema_major, schema_minor,
             parameter_schema
         ) VALUES ($1, $2, $3, 1, $4, $5, $6, 1, 0, '{}'::jsonb)",
    )
    .bind(organization_id)
    .bind(project_id)
    .bind(pipeline_id)
    .bind(SOURCE)
    .bind(source_digest.as_slice())
    .bind(semantic_digest.as_slice())
    .execute(&pool)
    .await
    .expect("insert previous pipeline revision");
    sqlx::query(
        "INSERT INTO builds (
             id, organization_id, project_id, idempotency_key,
             pipeline_digest, status, priority
         ) VALUES ($1, $2, $3, 'historic', $4, 'queued', 0)",
    )
    .bind(build_id)
    .bind(organization_id)
    .bind(project_id)
    .bind(semantic_digest.as_slice())
    .execute(&pool)
    .await
    .expect("insert previous unbound build");

    let mut tx = pool.begin().await.expect("begin v27 migration");
    sqlx::raw_sql(PIPELINE_OPERATIONAL_STATE_V27)
        .execute(&mut *tx)
        .await
        .expect("apply v27");
    sqlx::query("INSERT INTO mcloving_schema_migrations (version) VALUES (27)")
        .execute(&mut *tx)
        .await
        .expect("record v27");
    tx.commit().await.expect("commit v27");
    let backfilled = sqlx::query_as::<_, (i64, String, String, Option<i64>)>(
        "SELECT generation, state, source_identity, audit_sequence
         FROM pipeline_operational_state_history
         WHERE organization_id = $1 AND pipeline_id = $2",
    )
    .bind(organization_id)
    .bind(pipeline_id)
    .fetch_one(&pool)
    .await
    .expect("read v27 backfill");
    assert_eq!(
        backfilled,
        (1, "enabled".to_owned(), "migration:v27".to_owned(), None)
    );
    let binding = sqlx::query_as::<_, (Option<Uuid>, Option<i64>, Option<i64>)>(
        "SELECT pipeline_id, pipeline_revision, pipeline_operational_generation
         FROM builds WHERE id = $1",
    )
    .bind(build_id)
    .fetch_one(&pool)
    .await
    .expect("read historic build binding");
    assert_eq!(binding, (None, None, None));
    let migrated_store = Store::new(pool.clone());
    assert!(
        migrated_store
            .claim_next(&ClaimRequest {
                organization_id,
                scheduler_id: "scheduler-migration".to_owned(),
                agent_id: "agent-migration".to_owned(),
                capabilities: Vec::new(),
                trust_pool: "trusted-linux".to_owned(),
                lease_seconds: 30,
                fairness_seed: 0,
            })
            .await
            .expect("historic unbound scheduler query")
            .is_none()
    );

    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {database}"))
        .execute(&admin)
        .await
        .expect("drop isolated previous-schema database");
    admin.close().await;
}
