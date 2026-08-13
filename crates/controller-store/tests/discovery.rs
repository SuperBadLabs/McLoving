use mcloving_controller_store::{
    AuthorizationPolicyWrite, DiscoveredRefKind, DiscoveryChildState, DiscoveryObservationWrite,
    DiscoveryParentKind, DiscoveryParentPutOutcome, DiscoveryParentState, DiscoveryParentWrite,
    DiscoveryScanOutcome, DiscoveryScanSource, DiscoveryScanWrite, ForkTrustStrategy,
    MAX_DISCOVERY_CHILD_PAGE, OrphanPolicy, PipelinePutOutcome, PipelineTriggerState,
    PipelineTriggerWrite, PipelineWrite, PullRequestDiscoveryStrategy, Store, StoreError,
    TriggerKind, TriggerPutOutcome, compute_authorization_policy_digest,
    compute_discovery_parent_configuration_sha256, compute_discovery_scan_request_sha256,
    verify_discovery_transfer_snapshot,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const SOURCE: &str = r#"version: 1
name: discovery-test
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

fn digest(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

async fn assert_incremental_child_counts(store: &Store, organization_id: Uuid, parent_id: Uuid) {
    let recorded = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT result.active_count, result.quarantined_count, result.retired_count
         FROM discovery_scans AS scan
         JOIN discovery_scan_results AS result
           ON result.organization_id = scan.organization_id
          AND result.parent_id = scan.parent_id
          AND result.scan_id = scan.scan_id
         WHERE scan.organization_id = $1 AND scan.parent_id = $2
         ORDER BY scan.source_cursor DESC
         LIMIT 1",
    )
    .bind(organization_id)
    .bind(parent_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    let actual = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*) FILTER (WHERE state = 'active'),
                COUNT(*) FILTER (WHERE state = 'quarantined'),
                COUNT(*) FILTER (WHERE state = 'retired')
         FROM discovery_children
         WHERE organization_id = $1 AND parent_id = $2",
    )
    .bind(organization_id)
    .bind(parent_id)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(recorded, actual);
}

fn trigger_write(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    trigger_id: Uuid,
) -> PipelineTriggerWrite {
    let configuration = json!({
        "provider": "github",
        "repository_identity": "github:superbadlabs/mcloving",
        "filter": {
            "event_kinds": ["push", "pull_request"],
            "branches": [],
            "path_prefixes": []
        },
    });
    PipelineTriggerWrite {
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        expected_generation: 0,
        kind: TriggerKind::ScmWebhook,
        state: PipelineTriggerState::Enabled,
        implementation_sha256: digest("trigger-implementation-v1"),
        configuration_sha256: Sha256::digest(
            serde_json::to_vec(&configuration).unwrap().as_slice(),
        )
        .into(),
        filter_sha256: Sha256::digest(
            serde_json::to_vec(configuration.get("filter").unwrap())
                .unwrap()
                .as_slice(),
        )
        .into(),
        event_source_identity: "scm:github:installation:42".to_owned(),
        source_generation: "github-installation-generation-7".to_owned(),
        configuration,
        deduplication_window_seconds: 3_600,
        max_delivery_attempts: 3,
        delivery_ttl_seconds: 7_200,
        actor_subject: "operator@example.test".to_owned(),
        reason: "bind discovery webhook authority".to_owned(),
        idempotency_key: "discovery-trigger-v1".to_owned(),
    }
}

async fn fixture(store: &Store) -> (Uuid, Uuid, Uuid, Uuid, [u8; 32]) {
    let organization_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let pipeline_id = Uuid::new_v4();
    let trigger_id = Uuid::new_v4();
    store
        .create_project(
            organization_id,
            &format!("org-{organization_id}"),
            project_id,
            &format!("project-{project_id}"),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .put_pipeline_as(
                &PipelineWrite {
                    organization_id,
                    project_id,
                    pipeline_id,
                    slug: format!("pipeline-{pipeline_id}"),
                    source: SOURCE.to_owned(),
                    source_sha256: digest(SOURCE),
                    semantic_digest: digest("discovery-semantic-v1"),
                    schema_major: 1,
                    schema_minor: 0,
                    parameter_schema: json!({}),
                },
                Some(0),
                "creator@example.test",
            )
            .await
            .unwrap(),
        PipelinePutOutcome::Created(_)
    ));
    let mut policy = AuthorizationPolicyWrite {
        organization_id,
        project_id,
        generation: 1,
        expected_current_generation: None,
        source_realm_implementation: "jenkins.security.HudsonPrivateSecurityRealm".to_owned(),
        source_realm_digest: digest("realm-v1"),
        source_inventory_digest: digest("inventory-v1"),
        reviewer: "reviewer:discovery".to_owned(),
        actor_subject: "service:authorization-importer".to_owned(),
        restored_from_generation: None,
        mappings: Vec::new(),
        expected_policy_digest: [0; 32],
    };
    policy.expected_policy_digest = compute_authorization_policy_digest(&policy).unwrap();
    let policy_receipt = store.install_authorization_policy(&policy).await.unwrap();
    let trigger = trigger_write(organization_id, project_id, pipeline_id, trigger_id);
    assert!(matches!(
        store.put_pipeline_trigger(&trigger).await.unwrap(),
        TriggerPutOutcome::Created(_)
    ));
    (
        organization_id,
        project_id,
        pipeline_id,
        trigger_id,
        policy_receipt.policy_digest,
    )
}

fn parent_write(
    organization_id: Uuid,
    project_id: Uuid,
    pipeline_id: Uuid,
    parent_id: Uuid,
    trigger_id: Uuid,
    auth_digest: [u8; 32],
) -> DiscoveryParentWrite {
    let mut write = DiscoveryParentWrite {
        organization_id,
        project_id,
        pipeline_id,
        parent_id,
        expected_generation: 0,
        kind: DiscoveryParentKind::OrganizationFolder,
        state: DiscoveryParentState::Enabled,
        implementation_sha256: digest("discovery-implementation-v1"),
        protocol_version: "mcloving.discovery/v1".to_owned(),
        expected_configuration_sha256: [0; 32],
        provider: "github".to_owned(),
        provider_identity: "scm:github:installation:42".to_owned(),
        organization_identity: Some("github:superbadlabs".to_owned()),
        repositories: vec![
            "github:superbadlabs/fogell".to_owned(),
            "github:superbadlabs/mcloving".to_owned(),
        ],
        branch_includes: vec!["main".to_owned(), "release/".to_owned()],
        branch_excludes: vec!["release/private/".to_owned()],
        pull_request_strategy: PullRequestDiscoveryStrategy::OriginAndForks,
        fork_trust_strategy: ForkTrustStrategy::NamedRepositories,
        trusted_fork_repositories: vec!["github:trusted/fork".to_owned()],
        jenkinsfile_path: "ci/Jenkinsfile".to_owned(),
        child_configuration_policy_sha256: digest("child-policy-v1"),
        orphan_policy: OrphanPolicy::Retire,
        authorization_generation: 1,
        authorization_policy_sha256: auth_digest,
        trigger_id,
        trigger_generation: 1,
        trigger_configuration_sha256: trigger_write(
            organization_id,
            project_id,
            pipeline_id,
            trigger_id,
        )
        .configuration_sha256,
        source_implementation_sha256: digest("source-acquirer-v1"),
        source_protocol_version: "mcloving.source-acquisition/v1".to_owned(),
        source_configuration_sha256: digest("source-acquirer-config-v1"),
        restored_from_generation: None,
        actor_subject: "operator@example.test".to_owned(),
        reason: "reviewed organization discovery configuration".to_owned(),
        idempotency_key: "discovery-parent-v1".to_owned(),
    };
    write.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&write).unwrap();
    write
}

fn observation(
    child_key: &str,
    repository: &str,
    kind: DiscoveredRefKind,
    ref_name: &str,
    pr: Option<i64>,
    head_repository: &str,
    revision: &str,
) -> DiscoveryObservationWrite {
    DiscoveryObservationWrite {
        child_key: child_key.to_owned(),
        child_pipeline_id: Uuid::new_v4(),
        repository_identity: repository.to_owned(),
        ref_kind: kind,
        ref_name: ref_name.to_owned(),
        pull_request_number: pr,
        head_repository_identity: head_repository.to_owned(),
        present: true,
        revision: revision.to_owned(),
        provenance_sha256: digest(&format!("provenance:{child_key}:{revision}")),
        jenkinsfile_path: "ci/Jenkinsfile".to_owned(),
        jenkinsfile_sha256: digest(&format!("jenkinsfile:{child_key}:{revision}")),
        child_configuration_sha256: digest(&format!("child-config:{child_key}")),
    }
}

fn scan(
    parent: &DiscoveryParentWrite,
    scan_id: &str,
    source: DiscoveryScanSource,
    event_id: Option<&str>,
    cursor: i64,
    observations: Vec<DiscoveryObservationWrite>,
) -> DiscoveryScanWrite {
    let mut write = DiscoveryScanWrite {
        organization_id: parent.organization_id,
        project_id: parent.project_id,
        pipeline_id: parent.pipeline_id,
        parent_id: parent.parent_id,
        expected_parent_generation: parent.expected_generation + 1,
        scan_id: scan_id.to_owned(),
        source,
        source_event_id: event_id.map(str::to_owned),
        source_cursor: cursor,
        complete_snapshot: source != DiscoveryScanSource::Webhook,
        provider_snapshot_sha256: digest(&format!("provider-snapshot:{scan_id}")),
        observations,
        expected_request_sha256: [0; 32],
        actor_subject: "service:discovery-indexer".to_owned(),
    };
    write.expected_request_sha256 = compute_discovery_scan_request_sha256(&write).unwrap();
    write
}

#[tokio::test]
async fn organization_discovery_reconciles_filters_forks_replay_and_orphans() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id, trigger_id, auth_digest) = fixture(&store).await;
    let parent_id = Uuid::new_v4();
    let parent = parent_write(
        organization_id,
        project_id,
        pipeline_id,
        parent_id,
        trigger_id,
        auth_digest,
    );
    assert!(matches!(
        store.put_discovery_parent(&parent).await.unwrap(),
        DiscoveryParentPutOutcome::Created(_)
    ));
    assert!(matches!(
        store.put_discovery_parent(&parent).await.unwrap(),
        DiscoveryParentPutOutcome::Replayed(_)
    ));
    let mut divergent_parent_replay = parent.clone();
    divergent_parent_replay.reason = "substituted audit reason".to_owned();
    assert!(matches!(
        store.put_discovery_parent(&divergent_parent_replay).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let branch = observation(
        "mcloving:branch:main",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::Branch,
        "main",
        None,
        "github:superbadlabs/mcloving",
        "1111111111111111111111111111111111111111",
    );
    let origin_pr = observation(
        "mcloving:pr:7",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::PullRequest,
        "main",
        Some(7),
        "github:superbadlabs/mcloving",
        "2222222222222222222222222222222222222222",
    );
    let trusted_fork = observation(
        "mcloving:pr:8",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::PullRequest,
        "main",
        Some(8),
        "github:trusted/fork",
        "3333333333333333333333333333333333333333",
    );
    let untrusted_fork = observation(
        "mcloving:pr:9",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::PullRequest,
        "main",
        Some(9),
        "github:unknown/fork",
        "4444444444444444444444444444444444444444",
    );
    let filtered = observation(
        "mcloving:branch:private",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::Branch,
        "release/private/secret",
        None,
        "github:superbadlabs/mcloving",
        "5555555555555555555555555555555555555555",
    );
    let initial = scan(
        &parent,
        "scan-periodic-1",
        DiscoveryScanSource::Periodic,
        None,
        1,
        vec![
            branch.clone(),
            origin_pr,
            trusted_fork,
            untrusted_fork,
            filtered.clone(),
        ],
    );
    let (left, right) = tokio::join!(
        store.reconcile_discovery_scan(&initial),
        store.reconcile_discovery_scan(&initial)
    );
    let outcomes = [left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, DiscoveryScanOutcome::Reconciled(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, DiscoveryScanOutcome::Replayed(_)))
            .count(),
        1
    );
    let receipt = outcomes
        .iter()
        .find_map(|outcome| match outcome {
            DiscoveryScanOutcome::Reconciled(receipt) => Some(receipt),
            DiscoveryScanOutcome::Replayed(_) => None,
        })
        .unwrap();
    assert_eq!(receipt.observation_count, 5);
    assert_eq!(receipt.selected_count, 4);
    assert_eq!(receipt.active_count, 3);
    assert_eq!(receipt.quarantined_count, 1);
    assert_eq!(receipt.retired_count, 0);
    assert_incremental_child_counts(&store, organization_id, parent_id).await;
    assert!(
        store
            .discovery_children(
                organization_id,
                Uuid::new_v4(),
                pipeline_id,
                parent_id,
                None,
                MAX_DISCOVERY_CHILD_PAGE,
            )
            .await
            .unwrap()
            .items
            .is_empty(),
        "a same-organization project-path substitution must not expose children"
    );
    assert!(
        store
            .discovery_children(
                organization_id,
                project_id,
                Uuid::new_v4(),
                parent_id,
                None,
                MAX_DISCOVERY_CHILD_PAGE,
            )
            .await
            .unwrap()
            .items
            .is_empty(),
        "a same-project pipeline-path substitution must not expose children"
    );
    assert!(matches!(
        store
            .discovery_children(organization_id, project_id, pipeline_id, parent_id, None, 0)
            .await,
        Err(StoreError::InvalidDiscovery(_))
    ));
    let first_page = store
        .discovery_children(organization_id, project_id, pipeline_id, parent_id, None, 2)
        .await
        .unwrap();
    assert_eq!(first_page.items.len(), 2);
    let first_cursor = first_page.next_after.expect("a second page exists");
    assert_eq!(first_cursor, first_page.items[1].child_key);
    let second_page = store
        .discovery_children(
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            Some(&first_cursor),
            2,
        )
        .await
        .unwrap();
    assert_eq!(second_page.items.len(), 2);
    assert!(second_page.next_after.is_none());
    assert!(first_page.items[1].child_key < second_page.items[0].child_key);

    let mut runtime = store.pool().begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE mcloving_tenant")
        .execute(&mut *runtime)
        .await
        .expect("assume constrained runtime role");
    sqlx::query("SELECT set_config('mcloving.organization_id', $1, true)")
        .bind(organization_id.to_string())
        .execute(&mut *runtime)
        .await
        .expect("bind discovery tenant context");
    let runtime_identities = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT child_key, child_pipeline_id
         FROM discovery_child_identities
         WHERE organization_id = $1 AND parent_id = $2
           AND (child_key = $3 OR child_pipeline_id = $4)",
    )
    .bind(organization_id)
    .bind(parent_id)
    .bind(&initial.observations[0].child_key)
    .bind(initial.observations[0].child_pipeline_id)
    .fetch_all(&mut *runtime)
    .await
    .expect("immutable identity lookup uses only the runtime role's SELECT grant");
    assert_eq!(runtime_identities.len(), 1);
    let can_update_identity_registry: bool = sqlx::query_scalar(
        "SELECT has_table_privilege(
             'mcloving_tenant', 'discovery_child_identities', 'UPDATE'
         )",
    )
    .fetch_one(&mut *runtime)
    .await
    .unwrap();
    assert!(!can_update_identity_registry);
    runtime.rollback().await.unwrap();
    let dispositions = sqlx::query_as::<_, (String, String, bool, bool)>(
        r#"
        SELECT child_key, disposition, trusted, authorized
          FROM discovery_observations
         WHERE organization_id = $1
           AND parent_id = $2
           AND scan_id = $3
         ORDER BY child_key
        "#,
    )
    .bind(organization_id)
    .bind(parent_id)
    .bind(&initial.scan_id)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(
        dispositions,
        vec![
            (
                "mcloving:branch:main".to_owned(),
                "active".to_owned(),
                true,
                true,
            ),
            (
                "mcloving:branch:private".to_owned(),
                "filtered".to_owned(),
                false,
                false,
            ),
            ("mcloving:pr:7".to_owned(), "active".to_owned(), true, true,),
            ("mcloving:pr:8".to_owned(), "active".to_owned(), true, true,),
            (
                "mcloving:pr:9".to_owned(),
                "quarantined".to_owned(),
                false,
                false,
            ),
        ]
    );
    let mut malformed_filtered_branch = filtered.clone();
    malformed_filtered_branch.head_repository_identity = "github:attacker/fork".to_owned();
    let malformed_filtered_scan = scan(
        &parent,
        "scan-malformed-filtered-branch",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-malformed-filtered-branch"),
        2,
        vec![malformed_filtered_branch],
    );
    assert!(matches!(
        store
            .reconcile_discovery_scan(&malformed_filtered_scan)
            .await,
        Err(StoreError::InvalidDiscovery(_))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM discovery_observations
             WHERE organization_id = $1 AND parent_id = $2 AND scan_id = $3",
        )
        .bind(organization_id)
        .bind(parent_id)
        .bind(&malformed_filtered_scan.scan_id)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0,
        "a malformed filtered branch must not reserve retained identity"
    );
    let mut divergent = initial.clone();
    divergent.provider_snapshot_sha256 = digest("substituted-provider-snapshot");
    divergent.expected_request_sha256 = compute_discovery_scan_request_sha256(&divergent).unwrap();
    assert!(matches!(
        store.reconcile_discovery_scan(&divergent).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut substituted_identity = branch.clone();
    substituted_identity.child_pipeline_id = Uuid::new_v4();
    let identity_substitution = scan(
        &parent,
        "scan-identity-substitution",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-identity-substitution"),
        2,
        vec![substituted_identity],
    );
    assert!(matches!(
        store.reconcile_discovery_scan(&identity_substitution).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut pipeline_identity_reuse = branch.clone();
    pipeline_identity_reuse.child_key = "mcloving:branch:alias".to_owned();
    let pipeline_identity_substitution = scan(
        &parent,
        "scan-pipeline-identity-substitution",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-pipeline-identity-substitution"),
        2,
        vec![pipeline_identity_reuse],
    );
    assert!(matches!(
        store
            .reconcile_discovery_scan(&pipeline_identity_substitution)
            .await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut filtered_key_reuse = filtered.clone();
    filtered_key_reuse.child_pipeline_id = Uuid::new_v4();
    filtered_key_reuse.ref_name = "main".to_owned();
    let filtered_key_substitution = scan(
        &parent,
        "scan-filtered-key-substitution",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-filtered-key-substitution"),
        2,
        vec![filtered_key_reuse],
    );
    assert!(matches!(
        store
            .reconcile_discovery_scan(&filtered_key_substitution)
            .await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut filtered_pipeline_reuse = filtered;
    filtered_pipeline_reuse.child_key = "mcloving:branch:private-alias".to_owned();
    filtered_pipeline_reuse.ref_name = "main".to_owned();
    let filtered_pipeline_substitution = scan(
        &parent,
        "scan-filtered-pipeline-substitution",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-filtered-pipeline-substitution"),
        2,
        vec![filtered_pipeline_reuse],
    );
    assert!(matches!(
        store
            .reconcile_discovery_scan(&filtered_pipeline_substitution)
            .await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut updated_branch = branch.clone();
    updated_branch.revision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned();
    updated_branch.provenance_sha256 = digest("updated-provenance");
    updated_branch.jenkinsfile_sha256 = digest("updated-jenkinsfile");
    let webhook = scan(
        &parent,
        "scan-webhook-2",
        DiscoveryScanSource::Webhook,
        Some("github-delivery-2"),
        2,
        vec![updated_branch],
    );
    store.reconcile_discovery_scan(&webhook).await.unwrap();
    let children = store
        .discovery_children(
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            None,
            MAX_DISCOVERY_CHILD_PAGE,
        )
        .await
        .unwrap()
        .items;
    assert_eq!(
        children
            .iter()
            .find(|child| child.child_key == branch.child_key)
            .unwrap()
            .revision,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let reordered = scan(
        &parent,
        "scan-reordered",
        DiscoveryScanSource::Periodic,
        None,
        1,
        vec![branch.clone()],
    );
    assert!(matches!(
        store.reconcile_discovery_scan(&reordered).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let catch_up = scan(
        &parent,
        "scan-recovery-3",
        DiscoveryScanSource::Recovery,
        None,
        3,
        vec![branch],
    );
    store.reconcile_discovery_scan(&catch_up).await.unwrap();
    let children = store
        .discovery_children(
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            None,
            MAX_DISCOVERY_CHILD_PAGE,
        )
        .await
        .unwrap()
        .items;
    assert_eq!(
        children
            .iter()
            .filter(|child| child.state == DiscoveryChildState::Retired)
            .count(),
        3
    );
    assert_incremental_child_counts(&store, organization_id, parent_id).await;
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM discovery_children
             WHERE organization_id = $1 AND parent_id = $2
               AND state = 'retired' AND last_scan_id = $3",
        )
        .bind(organization_id)
        .bind(parent_id)
        .bind(&catch_up.scan_id)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        3,
        "one complete snapshot must retire every omitted current child"
    );
    assert_eq!(
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE child_key = $3)
             FROM discovery_child_identities
             WHERE organization_id = $1 AND parent_id = $2",
        )
        .bind(organization_id)
        .bind(parent_id)
        .bind(&catch_up.observations[0].child_key)
        .fetch_one(store.pool())
        .await
        .unwrap(),
        (5, 1),
        "repeated sightings must retain one bounded identity row per child"
    );
    let DiscoveryScanOutcome::Replayed(historical) =
        store.reconcile_discovery_scan(&initial).await.unwrap()
    else {
        panic!("historical scan must replay");
    };
    assert_eq!(
        (
            historical.active_count,
            historical.quarantined_count,
            historical.retired_count
        ),
        (3, 1, 0),
        "exact replay must return the original result, not current child counts"
    );
    let mut reconfigured = parent.clone();
    reconfigured.expected_generation = 1;
    reconfigured.branch_includes = vec!["release/".to_owned()];
    reconfigured.orphan_policy = OrphanPolicy::Retain;
    reconfigured.idempotency_key = "discovery-parent-filter-v2".to_owned();
    reconfigured.reason = "narrow discovery to release branches".to_owned();
    reconfigured.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&reconfigured).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&reconfigured).await.unwrap(),
        DiscoveryParentPutOutcome::Revised(_)
    ));
    let mut reconfigured_main = initial.observations[0].clone();
    reconfigured_main.revision = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned();
    reconfigured_main.provenance_sha256 = digest("reconfigured-main-provenance");
    reconfigured_main.jenkinsfile_sha256 = digest("reconfigured-main-jenkinsfile");
    let reconfigured_scan = scan(
        &reconfigured,
        "scan-reconfigured-4",
        DiscoveryScanSource::Periodic,
        None,
        4,
        vec![reconfigured_main],
    );
    let DiscoveryScanOutcome::Reconciled(reconfigured_receipt) = store
        .reconcile_discovery_scan(&reconfigured_scan)
        .await
        .unwrap()
    else {
        panic!("reconfigured scan must reconcile");
    };
    assert_eq!(reconfigured_receipt.observation_count, 1);
    assert_eq!(reconfigured_receipt.selected_count, 0);
    assert_eq!(reconfigured_receipt.retired_count, 4);
}

#[tokio::test]
async fn discovery_fails_closed_on_configuration_authority_and_quiescence_drift() {
    let Some(store) = test_store().await else {
        eprintln!("skipped: MCLOVING_TEST_DATABASE_URL is not configured");
        return;
    };
    let (organization_id, project_id, pipeline_id, trigger_id, auth_digest) = fixture(&store).await;
    let parent_id = Uuid::new_v4();
    let parent = parent_write(
        organization_id,
        project_id,
        pipeline_id,
        parent_id,
        trigger_id,
        auth_digest,
    );
    let mut substituted = parent.clone();
    substituted.implementation_sha256 = digest("substituted-implementation");
    assert!(matches!(
        store.put_discovery_parent(&substituted).await,
        Err(StoreError::InvalidDiscovery(_))
    ));

    let mut oversized = parent.clone();
    oversized.repositories = (0..130)
        .map(|index| format!("{index:04}-{}", "x".repeat(507)))
        .collect();
    oversized.idempotency_key = "discovery-parent-oversized-repositories".to_owned();
    oversized.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&oversized).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&oversized).await,
        Err(StoreError::InvalidDiscovery(_))
    ));

    let mut provider_substituted = parent.clone();
    provider_substituted.provider = "gitlab".to_owned();
    provider_substituted.idempotency_key = "discovery-parent-provider-substitution".to_owned();
    provider_substituted.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&provider_substituted).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&provider_substituted).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    store.put_discovery_parent(&parent).await.unwrap();

    let seeded_observation = observation(
        "mcloving:branch:main",
        "github:superbadlabs/mcloving",
        DiscoveredRefKind::Branch,
        "main",
        None,
        "github:superbadlabs/mcloving",
        "1111111111111111111111111111111111111111",
    );
    let seeded_scan = scan(
        &parent,
        "scan-before-authority-drift",
        DiscoveryScanSource::Periodic,
        None,
        1,
        vec![seeded_observation.clone()],
    );
    store.reconcile_discovery_scan(&seeded_scan).await.unwrap();

    let mut policy_two = AuthorizationPolicyWrite {
        organization_id,
        project_id,
        generation: 2,
        expected_current_generation: Some(1),
        source_realm_implementation: "jenkins.security.HudsonPrivateSecurityRealm".to_owned(),
        source_realm_digest: digest("realm-v2"),
        source_inventory_digest: digest("inventory-v2"),
        reviewer: "reviewer:discovery".to_owned(),
        actor_subject: "service:authorization-importer".to_owned(),
        restored_from_generation: None,
        mappings: Vec::new(),
        expected_policy_digest: [0; 32],
    };
    policy_two.expected_policy_digest = compute_authorization_policy_digest(&policy_two).unwrap();
    store
        .install_authorization_policy(&policy_two)
        .await
        .unwrap();
    assert!(matches!(
        store.put_discovery_parent(&parent).await.unwrap(),
        DiscoveryParentPutOutcome::Replayed(_)
    ));
    let stale_scan = scan(
        &parent,
        "scan-stale-authz",
        DiscoveryScanSource::Periodic,
        None,
        2,
        Vec::new(),
    );
    assert!(matches!(
        store.reconcile_discovery_scan(&stale_scan).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut rebound = parent.clone();
    rebound.expected_generation = 1;
    rebound.authorization_generation = 2;
    rebound.authorization_policy_sha256 = policy_two.expected_policy_digest;
    rebound.idempotency_key = "discovery-parent-authority-v2".to_owned();
    rebound.reason = "bind current reviewed authorization".to_owned();
    rebound.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&rebound).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&rebound).await.unwrap(),
        DiscoveryParentPutOutcome::Revised(_)
    ));

    let mut unreconciled_quiescence = rebound.clone();
    unreconciled_quiescence.expected_generation = 2;
    unreconciled_quiescence.state = DiscoveryParentState::Quiesced;
    unreconciled_quiescence.idempotency_key = "discovery-parent-unreconciled-quiescence".to_owned();
    unreconciled_quiescence.reason = "invalid quiescence before reconciliation".to_owned();
    unreconciled_quiescence.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&unreconciled_quiescence).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&unreconciled_quiescence).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut premature_quiescence = unreconciled_quiescence;
    premature_quiescence.expected_generation = 2;
    premature_quiescence.branch_includes = vec!["release/".to_owned()];
    premature_quiescence.idempotency_key = "discovery-parent-invalid-quiescence".to_owned();
    premature_quiescence.reason = "invalid combined reconfiguration and quiescence".to_owned();
    premature_quiescence.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&premature_quiescence).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&premature_quiescence).await,
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut rebound_observation = seeded_observation;
    rebound_observation.revision = "2222222222222222222222222222222222222222".to_owned();
    rebound_observation.provenance_sha256 = digest("rebound-provenance");
    rebound_observation.jenkinsfile_sha256 = digest("rebound-jenkinsfile");
    let rebound_scan = scan(
        &rebound,
        "scan-after-authority-rebind",
        DiscoveryScanSource::Recovery,
        None,
        2,
        vec![rebound_observation],
    );
    store.reconcile_discovery_scan(&rebound_scan).await.unwrap();

    let mut quiesced = rebound.clone();
    quiesced.expected_generation = 2;
    quiesced.state = DiscoveryParentState::Quiesced;
    quiesced.idempotency_key = "discovery-parent-quiesced-v3".to_owned();
    quiesced.reason = "quiesce for authority handoff".to_owned();
    quiesced.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&quiesced).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&quiesced).await.unwrap(),
        DiscoveryParentPutOutcome::Revised(_)
    ));
    let quiesced_scan = scan(
        &quiesced,
        "scan-while-quiesced",
        DiscoveryScanSource::Recovery,
        None,
        3,
        Vec::new(),
    );
    assert!(matches!(
        store.reconcile_discovery_scan(&quiesced_scan).await,
        Err(StoreError::DiscoveryQuiesced { generation: 3, .. })
    ));
    let transfer = store
        .export_quiesced_discovery_state(
            organization_id,
            project_id,
            pipeline_id,
            parent_id,
            "operator:handoff-reviewer",
        )
        .await
        .unwrap();
    verify_discovery_transfer_snapshot(&transfer, transfer.audit_event_hash).unwrap();
    assert_eq!(transfer.scans.len(), 2);
    assert_eq!(transfer.observations.len(), 2);
    assert_eq!(transfer.children.len(), 1);
    let mut substituted_transfer = transfer.clone();
    substituted_transfer.observations[0].revision =
        "ffffffffffffffffffffffffffffffffffffffff".to_owned();
    assert!(matches!(
        verify_discovery_transfer_snapshot(&substituted_transfer, transfer.audit_event_hash),
        Err(StoreError::DiscoveryConflict(_))
    ));
    let mut malformed_audit_commitment = transfer.clone();
    malformed_audit_commitment.handoff_audit_event.payload["ledger_sha256"] = json!(null);
    assert!(matches!(
        verify_discovery_transfer_snapshot(&malformed_audit_commitment, transfer.audit_event_hash),
        Err(StoreError::DiscoveryConflict(_))
    ));
    assert!(matches!(
        verify_discovery_transfer_snapshot(&transfer, digest("wrong-audit-anchor")),
        Err(StoreError::DiscoveryConflict(_))
    ));

    let mut restored = quiesced.clone();
    restored.expected_generation = 3;
    restored.state = DiscoveryParentState::Enabled;
    restored.restored_from_generation = Some(1);
    restored.idempotency_key = "discovery-parent-rollback-v4".to_owned();
    restored.reason = "restore reviewed discovery behavior".to_owned();
    restored.expected_configuration_sha256 =
        compute_discovery_parent_configuration_sha256(&restored).unwrap();
    assert!(matches!(
        store.put_discovery_parent(&restored).await.unwrap(),
        DiscoveryParentPutOutcome::Revised(_)
    ));
    let recovery = scan(
        &restored,
        "scan-after-rollback",
        DiscoveryScanSource::Recovery,
        None,
        4,
        Vec::new(),
    );
    assert!(matches!(
        store.reconcile_discovery_scan(&recovery).await.unwrap(),
        DiscoveryScanOutcome::Reconciled(_)
    ));
}
