use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use mcloving_provisioner::{
    ActivationMode, AgentSpecification, CacheMode, CachePolicy, CancelRequest, CleanupReason,
    InstanceIdentity, InstanceIdentityPolicy, LifecycleOutcome, NetworkPolicy,
    ProviderCreateRequest, ProviderDeleteRequest, ProviderDeleteResult, ProviderInstance,
    ProviderInstanceState, ProviderInventory, ProviderLookup, ProvisionRequest, Provisioner,
    ProvisionerConfig, ProvisionerError, QuotaPolicy, ReconcileRequest, SignedProviderEnvelope,
    VolumeGrant, VolumePolicy, WorkspacePolicy, content_sha256, parse_json_no_duplicates,
    provider_attestation_message, sha256_file,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

const IMPLEMENTATION_SHA256: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const PROVIDER_TOKEN: &str = "contained-provider-token";
const RECEIPT_KEY: &[u8] = b"contained-receipt-signing-key-000000000000000000000000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureMode {
    Ready,
    PendingThenReady,
    PendingForever,
    StartupFailed,
    SubstituteTemplate,
    SubstituteIdentity,
    WrongProviderIdentity,
    StaleObservation,
    Unauthorized,
    MalformedCreateOnce,
    MalformedDeleteOnce,
    SubstituteFinalInventory,
    DuplicateFinalInventory,
}

struct Inner {
    mode: FixtureMode,
    instances: HashMap<Uuid, ProviderInstance>,
    creates: usize,
    deletes: usize,
    lookups: usize,
    malformed_create_sent: bool,
    malformed_delete_sent: bool,
    inventory_reads: usize,
}

#[derive(Clone)]
struct FixtureState {
    inner: Arc<Mutex<Inner>>,
    signing_key: Arc<Ed25519KeyPair>,
}

struct Fixture {
    endpoint: String,
    state: FixtureState,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Fixture {
    async fn start(mode: FixtureMode) -> Self {
        let signing_key = Arc::new(
            Ed25519KeyPair::from_seed_unchecked(&[7_u8; 32]).expect("fixture signing key"),
        );
        let state = FixtureState {
            inner: Arc::new(Mutex::new(Inner {
                mode,
                instances: HashMap::new(),
                creates: 0,
                deletes: 0,
                lookups: 0,
                malformed_create_sent: false,
                malformed_delete_sent: false,
                inventory_reads: 0,
            })),
            signing_key,
        };
        let app = Router::new()
            .route("/v1/instances", post(create_instance).get(list_instances))
            .route("/v1/requests/{request_id}", get(lookup_instance))
            .route("/v1/instances/{instance_id}", delete(delete_instance))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind provider fixture");
        let address = listener.local_addr().expect("fixture address");
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve provider fixture");
        });
        Self {
            endpoint: format!("http://{address}/"),
            state,
            task,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.state.signing_key.public_key().as_ref().to_vec()
    }

    fn counts(&self) -> (usize, usize, usize, usize) {
        let inner = self.state.inner.lock().expect("fixture state");
        (
            inner.creates,
            inner.deletes,
            inner.lookups,
            inner.instances.len(),
        )
    }

    fn inject_orphan(&self, create: ProviderCreateRequest) -> Uuid {
        let mut inner = self.state.inner.lock().expect("fixture state");
        let instance = make_instance(&create, ProviderInstanceState::Ready, false);
        let id = instance.instance_id;
        inner.instances.insert(create.request.request_id, instance);
        id
    }

    fn mark_agent_lost(&self, request_id: Uuid) {
        let mut inner = self.state.inner.lock().expect("fixture state");
        inner
            .instances
            .get_mut(&request_id)
            .expect("fixture instance")
            .state = ProviderInstanceState::AgentLost;
    }

    fn set_mode(&self, mode: FixtureMode) {
        self.state.inner.lock().expect("fixture state").mode = mode;
    }
}

async fn create_instance(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Json(request): Json<ProviderCreateRequest>,
) -> Response {
    if !authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = state.inner.lock().expect("fixture state");
    if inner.mode == FixtureMode::Unauthorized {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(existing) = inner.instances.get(&request.request.request_id) {
        if existing.create != request {
            return StatusCode::CONFLICT.into_response();
        }
        return signed_response(&state, existing.clone());
    }
    inner.creates += 1;
    let provider_state = match inner.mode {
        FixtureMode::PendingThenReady | FixtureMode::PendingForever => {
            ProviderInstanceState::Pending
        }
        FixtureMode::StartupFailed => ProviderInstanceState::StartupFailed,
        _ => ProviderInstanceState::Ready,
    };
    let substituted = inner.mode == FixtureMode::SubstituteTemplate;
    let mut instance = make_instance(&request, provider_state, substituted);
    if inner.mode == FixtureMode::SubstituteIdentity {
        instance.identity.role = "substituted-agent-role".to_owned();
    }
    if inner.mode == FixtureMode::StaleObservation {
        instance.observed_at_unix_ms -= 60_000;
    }
    inner
        .instances
        .insert(request.request.request_id, instance.clone());
    if inner.mode == FixtureMode::MalformedCreateOnce && !inner.malformed_create_sent {
        inner.malformed_create_sent = true;
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("{"))
            .expect("malformed fixture response");
    }
    if inner.mode == FixtureMode::WrongProviderIdentity {
        return signed_response_as(&state, instance, "substituted-provider");
    }
    signed_response(&state, instance)
}

async fn lookup_instance(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Path(request_id): Path<Uuid>,
) -> Response {
    if !authorized(&headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = state.inner.lock().expect("fixture state");
    inner.lookups += 1;
    let ready = inner.mode == FixtureMode::PendingThenReady && inner.lookups >= 2;
    if ready && let Some(instance) = inner.instances.get_mut(&request_id) {
        instance.state = ProviderInstanceState::Ready;
        instance.observed_at_unix_ms = now_ms();
    }
    let payload = ProviderLookup {
        request_id,
        observed_at_unix_ms: now_ms(),
        instance: inner.instances.get(&request_id).cloned(),
    };
    signed_response(&state, payload)
}

async fn list_instances(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if !authorized(&headers)
        || query.get("provisioner_id").map(String::as_str) != Some("contained-provisioner")
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = state.inner.lock().expect("fixture state");
    inner.inventory_reads += 1;
    let mut instances = inner.instances.values().cloned().collect::<Vec<_>>();
    if inner.mode == FixtureMode::SubstituteFinalInventory && inner.inventory_reads >= 2 {
        for instance in &mut instances {
            instance.effective_agent.template_sha256 = digest(b"substituted-final-template");
        }
    }
    if inner.mode == FixtureMode::DuplicateFinalInventory
        && inner.inventory_reads >= 2
        && let Some(instance) = instances.first().cloned()
    {
        instances.push(instance);
    }
    let payload = ProviderInventory {
        provisioner_id: "contained-provisioner".to_owned(),
        complete: true,
        observed_at_unix_ms: now_ms(),
        instances,
    };
    signed_response(&state, payload)
}

async fn delete_instance(
    State(state): State<FixtureState>,
    headers: HeaderMap,
    Path(instance_id): Path<Uuid>,
    Json(request): Json<ProviderDeleteRequest>,
) -> Response {
    if !authorized(&headers)
        || request.protocol_version != mcloving_provisioner::PROTOCOL_VERSION
        || request.provisioner_id != "contained-provisioner"
        || request.instance_id != instance_id
        || request.expires_at_unix_ms <= now_ms()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut inner = state.inner.lock().expect("fixture state");
    let Some(instance) = inner.instances.get(&request.request_id) else {
        return signed_response(
            &state,
            ProviderDeleteResult {
                request_id: request.request_id,
                instance_id,
                absent: true,
                observed_at_unix_ms: now_ms(),
            },
        );
    };
    if instance.instance_id != instance_id
        || instance.create.request.tenant_id != request.tenant_id
        || instance.create.request.project_id != request.project_id
        || instance.create.request.build_id != request.build_id
        || instance.create.request.attempt_id != request.attempt_id
        || instance.create.request.fence_token != request.fence_token
    {
        return StatusCode::CONFLICT.into_response();
    }
    inner.instances.remove(&request.request_id);
    inner.deletes += 1;
    if inner.mode == FixtureMode::MalformedDeleteOnce && !inner.malformed_delete_sent {
        inner.malformed_delete_sent = true;
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("{"))
            .expect("malformed fixture response");
    }
    signed_response(
        &state,
        ProviderDeleteResult {
            request_id: request.request_id,
            instance_id,
            absent: true,
            observed_at_unix_ms: now_ms(),
        },
    )
}

fn authorized(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some("Bearer contained-provider-token")
        && headers
            .get("x-mcloving-provisioner-id")
            .and_then(|value| value.to_str().ok())
            == Some("contained-provisioner")
        && headers
            .get("x-mcloving-provider-grant-id")
            .and_then(|value| value.to_str().ok())
            == Some("contained-provider-grant")
}

fn signed_response<T: Serialize>(state: &FixtureState, payload: T) -> Response {
    signed_response_as(state, payload, "contained-provider")
}

fn signed_response_as<T: Serialize>(
    state: &FixtureState,
    payload: T,
    provider_id: &str,
) -> Response {
    let mut envelope = SignedProviderEnvelope {
        protocol_version: mcloving_provisioner::PROTOCOL_VERSION.to_owned(),
        provider_id: provider_id.to_owned(),
        provider_endpoint_identity: "contained-provider-endpoint".to_owned(),
        provider_account_id: "contained-account".to_owned(),
        provider_region: "contained-region-1".to_owned(),
        provider_api_version: "contained-api-v1".to_owned(),
        attestation_key_id: "contained-provider-key".to_owned(),
        payload,
        signature: String::new(),
    };
    let message = provider_attestation_message(&envelope).expect("attestation message");
    envelope.signature = BASE64.encode(state.signing_key.sign(&message).as_ref());
    Json(envelope).into_response()
}

fn make_instance(
    create: &ProviderCreateRequest,
    state: ProviderInstanceState,
    substitute_template: bool,
) -> ProviderInstance {
    let now = now_ms();
    let mut effective_agent = create.request.agent.clone();
    if substitute_template {
        effective_agent.template_sha256 = digest(b"substituted-template");
    }
    ProviderInstance {
        instance_id: Uuid::new_v4(),
        create: create.clone(),
        effective_agent,
        identity: InstanceIdentity {
            instance_subject: format!("instance:{}", create.request.request_id),
            issuer: "contained-identity-issuer".to_owned(),
            audience: "mcloving-agent".to_owned(),
            role: "contained-agent-role".to_owned(),
            iam_policy_sha256: digest(b"contained-iam-policy"),
            grant_id: format!("instance-grant:{}", create.request.request_id),
            issued_at_unix_ms: now,
            expires_at_unix_ms: create.request.instance_expires_at_unix_ms,
        },
        state,
        created_at_unix_ms: now,
        observed_at_unix_ms: now,
    }
}

struct Context {
    _temporary: TempDir,
    fixture: Fixture,
    config: ProvisionerConfig,
    provisioner: Provisioner,
}

impl Context {
    async fn new(mode: FixtureMode) -> Self {
        Self::with_quota(mode, 4).await
    }

    async fn with_quota(mode: FixtureMode, maximum: u32) -> Self {
        let fixture = Fixture::start(mode).await;
        let temporary = tempfile::tempdir().expect("temporary directory");
        let config = configuration(
            &fixture,
            temporary.path().join("state"),
            IMPLEMENTATION_SHA256,
            maximum,
        );
        let provisioner = Provisioner::new(
            config.clone(),
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await
        .expect("construct provisioner");
        Self {
            _temporary: temporary,
            fixture,
            config,
            provisioner,
        }
    }

    fn request(&self) -> ProvisionRequest {
        provision_request(&self.config, IMPLEMENTATION_SHA256)
    }
}

fn configuration(
    fixture: &Fixture,
    state_dir: std::path::PathBuf,
    implementation_sha256: &str,
    maximum: u32,
) -> ProvisionerConfig {
    let public_key = fixture.public_key();
    let now = now_ms();
    let mut config = ProvisionerConfig {
        protocol_version: mcloving_provisioner::PROTOCOL_VERSION.to_owned(),
        provisioner_id: "contained-provisioner".to_owned(),
        implementation_id: "mcloving-provisioner-contained".to_owned(),
        deployment_identity: "contained-provisioner-deployment".to_owned(),
        operator_identity: "contained-provisioner-operator".to_owned(),
        generation: 7,
        provider_id: "contained-provider".to_owned(),
        provider_endpoint: fixture.endpoint.clone(),
        provider_endpoint_identity: "contained-provider-endpoint".to_owned(),
        provider_account_id: "contained-account".to_owned(),
        provider_region: "contained-region-1".to_owned(),
        provider_api_version: "contained-api-v1".to_owned(),
        provider_grant_id: "contained-provider-grant".to_owned(),
        provider_grant_scope: "compute:create,get,list,delete:contained-account".to_owned(),
        provider_grant_expires_unix_ms: now + 3_600_000,
        provider_token_sha256: digest(PROVIDER_TOKEN.as_bytes()),
        provider_attestation_key_id: "contained-provider-key".to_owned(),
        provider_attestation_key_sha256: digest(&public_key),
        receipt_signing_key_id: "contained-receipt-key".to_owned(),
        receipt_signing_key_sha256: digest(RECEIPT_KEY),
        agent: agent_specification(),
        instance_identity: InstanceIdentityPolicy {
            issuer: "contained-identity-issuer".to_owned(),
            audience: "mcloving-agent".to_owned(),
            role: "contained-agent-role".to_owned(),
            iam_policy_sha256: digest(b"contained-iam-policy"),
            max_ttl_ms: 120_000,
        },
        quotas: QuotaPolicy {
            max_active_global: maximum,
            max_active_per_tenant: maximum,
            max_active_per_project: maximum,
        },
        provider_timeout_ms: 300,
        startup_timeout_ms: 150,
        startup_poll_interval_ms: 10,
        max_instance_lifetime_ms: 120_000,
        state_dir,
        ca_bundle_path: None,
        ca_bundle_sha256: None,
        test_allow_http_loopback: true,
    };
    assert_eq!(implementation_sha256.len(), 64);
    config.implementation_id = format!("contained:{implementation_sha256}");
    config
}

fn agent_specification() -> AgentSpecification {
    AgentSpecification {
        agent_class_id: "linux-x86_64-contained".to_owned(),
        template_id: "contained-template-v1".to_owned(),
        template_sha256: digest(b"contained-template"),
        image_id: "contained-image-v1".to_owned(),
        image_sha256: digest(b"contained-image"),
        bootstrap_sha256: digest(b"contained-bootstrap"),
        toolchain_sha256: digest(b"contained-toolchain"),
        platform: "linux/amd64".to_owned(),
        capabilities: BTreeSet::from(["container".to_owned(), "git".to_owned(), "rust".to_owned()]),
        trust_pool: "trusted-contained".to_owned(),
        network: NetworkPolicy {
            policy_id: "contained-network-v1".to_owned(),
            policy_sha256: digest(b"contained-network-policy"),
            allow_ingress: false,
            allow_instance_metadata: false,
            egress_allowlist: BTreeSet::from([
                "controller.contained:443".to_owned(),
                "source.contained:443".to_owned(),
            ]),
        },
        volumes: VolumePolicy {
            policy_id: "contained-volumes-v1".to_owned(),
            policy_sha256: digest(b"contained-volume-policy"),
            allow_host_mounts: false,
            grants: vec![VolumeGrant {
                volume_class: "ephemeral-workspace".to_owned(),
                mount_path: "/workspace".to_owned(),
                read_only: false,
                max_bytes: 1_073_741_824,
                destroy_on_release: true,
            }],
        },
        workspace: WorkspacePolicy {
            policy_id: "contained-workspace-v1".to_owned(),
            policy_sha256: digest(b"contained-workspace-policy"),
            max_bytes: 1_073_741_824,
            encrypted: true,
            ephemeral: true,
            destroy_on_release: true,
        },
        cache: CachePolicy {
            policy_id: "contained-cache-disabled-v1".to_owned(),
            policy_sha256: digest(b"contained-cache-policy"),
            mode: CacheMode::Disabled,
            namespace: None,
            max_bytes: 0,
            trust_class: "trusted-contained".to_owned(),
        },
    }
}

fn provision_request(config: &ProvisionerConfig, implementation_sha256: &str) -> ProvisionRequest {
    let now = now_ms();
    ProvisionRequest {
        request_id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        project_id: Uuid::new_v4(),
        build_id: Uuid::new_v4(),
        attempt_id: Uuid::new_v4(),
        fence_token: 1,
        provisioner_id: config.provisioner_id.clone(),
        expected_implementation_sha256: implementation_sha256.to_owned(),
        expected_config_sha256: config.canonical_digest().expect("config digest"),
        expected_generation: config.generation,
        activation_mode: ActivationMode::Current,
        previous_generation: None,
        provider_id: config.provider_id.clone(),
        provider_endpoint_identity: config.provider_endpoint_identity.clone(),
        provider_account_id: config.provider_account_id.clone(),
        provider_region: config.provider_region.clone(),
        provider_grant_id: config.provider_grant_id.clone(),
        provider_grant_scope: config.provider_grant_scope.clone(),
        agent: config.agent.clone(),
        requested_at_unix_ms: now,
        expires_at_unix_ms: now + 120_000,
        instance_expires_at_unix_ms: now + 90_000,
        audit_lineage: format!("contained-audit:{}", Uuid::new_v4()),
    }
}

fn cancel_request(
    config: &ProvisionerConfig,
    request: &ProvisionRequest,
    implementation_sha256: &str,
) -> CancelRequest {
    let now = now_ms();
    CancelRequest {
        request_id: request.request_id,
        tenant_id: request.tenant_id,
        project_id: request.project_id,
        build_id: request.build_id,
        attempt_id: request.attempt_id,
        fence_token: request.fence_token,
        expected_request_sha256: digest(&serde_json::to_vec(request).expect("request JSON")),
        expected_implementation_sha256: implementation_sha256.to_owned(),
        expected_config_sha256: config.canonical_digest().expect("config digest"),
        expected_generation: config.generation,
        requested_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
        reason: "contained scale-down".to_owned(),
        audit_lineage: format!("contained-cancel-audit:{}", Uuid::new_v4()),
    }
}

fn reconcile_request(config: &ProvisionerConfig, implementation_sha256: &str) -> ReconcileRequest {
    let now = now_ms();
    ReconcileRequest {
        reconciliation_id: Uuid::new_v4(),
        expected_implementation_sha256: implementation_sha256.to_owned(),
        expected_config_sha256: config.canonical_digest().expect("config digest"),
        expected_generation: config.generation,
        requested_at_unix_ms: now,
        expires_at_unix_ms: now + 60_000,
        audit_lineage: format!("contained-reconcile-audit:{}", Uuid::new_v4()),
    }
}

#[tokio::test]
async fn ready_replay_cancel_and_fences_are_exact() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    let ready = context
        .provisioner
        .provision(&request)
        .await
        .expect("ready receipt");
    assert_eq!(ready.body.outcome, LifecycleOutcome::Ready);
    assert!(!ready.body.cleanup_confirmed);
    context
        .provisioner
        .verify_lifecycle_receipt(&ready)
        .expect("verify ready receipt");
    let replay = context
        .provisioner
        .provision(&request)
        .await
        .expect("replay ready receipt");
    assert_eq!(replay, ready);
    assert_eq!(context.fixture.counts().0, 1);

    let mut conflicting = request.clone();
    conflicting.audit_lineage.push_str(":different");
    assert!(matches!(
        context.provisioner.provision(&conflicting).await,
        Err(ProvisionerError::ReplayMismatch)
    ));
    let mut stale = request.clone();
    stale.request_id = Uuid::new_v4();
    assert!(matches!(
        context.provisioner.provision(&stale).await,
        Err(ProvisionerError::StaleFence)
    ));
    let mut newer = request.clone();
    newer.request_id = Uuid::new_v4();
    newer.fence_token = 2;
    assert!(matches!(
        context.provisioner.provision(&newer).await,
        Err(ProvisionerError::CleanupRequired)
    ));

    let cancelled = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("cancel receipt");
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().1, 1);

    newer.requested_at_unix_ms = now_ms();
    newer.expires_at_unix_ms = newer.requested_at_unix_ms + 120_000;
    newer.instance_expires_at_unix_ms = newer.requested_at_unix_ms + 90_000;
    newer.audit_lineage = "contained-newer-fence".to_owned();
    let next = context
        .provisioner
        .provision(&newer)
        .await
        .expect("newer fence after cleanup");
    assert_eq!(next.body.fence_token, 2);
    assert_eq!(context.fixture.counts().0, 2);
}

#[tokio::test]
async fn substitution_startup_failure_and_timeout_leave_no_compute() {
    for (mode, expected) in [
        (
            FixtureMode::SubstituteTemplate,
            LifecycleOutcome::SubstitutionDeniedCleaned,
        ),
        (
            FixtureMode::SubstituteIdentity,
            LifecycleOutcome::SubstitutionDeniedCleaned,
        ),
        (
            FixtureMode::StartupFailed,
            LifecycleOutcome::StartupFailedCleaned,
        ),
        (
            FixtureMode::PendingForever,
            LifecycleOutcome::StartupTimeoutCleaned,
        ),
    ] {
        let context = Context::new(mode).await;
        let receipt = context
            .provisioner
            .provision(&context.request())
            .await
            .expect("bounded failure receipt");
        assert_eq!(receipt.body.outcome, expected);
        assert!(receipt.body.cleanup_confirmed);
        assert!(!receipt.body.ambiguity);
        assert_eq!(context.fixture.counts().3, 0);
    }
}

#[tokio::test]
async fn stale_or_wrong_provider_attestation_never_becomes_ready() {
    for mode in [
        FixtureMode::StaleObservation,
        FixtureMode::WrongProviderIdentity,
    ] {
        let context = Context::new(mode).await;
        let receipt = context
            .provisioner
            .provision(&context.request())
            .await
            .expect("ambiguous attestation receipt");
        assert_eq!(receipt.body.outcome, LifecycleOutcome::CreateAmbiguous);
        assert!(receipt.body.ambiguity);
        assert!(!receipt.body.cleanup_confirmed);
        assert_eq!(context.fixture.counts().3, 1);
    }

    let denied = Context::new(FixtureMode::Unauthorized).await;
    assert!(matches!(
        denied.provisioner.provision(&denied.request()).await,
        Err(ProvisionerError::ProviderUnauthorized)
    ));
    assert_eq!(denied.fixture.counts().0, 0);
    assert_eq!(denied.fixture.counts().3, 0);
}

#[tokio::test]
async fn ambiguous_create_restart_orphan_and_agent_loss_reconcile() {
    let context = Context::new(FixtureMode::MalformedCreateOnce).await;
    let request = context.request();
    let ambiguous_receipt = context
        .provisioner
        .provision(&request)
        .await
        .expect("ambiguous create receipt");
    assert_eq!(
        ambiguous_receipt.body.outcome,
        LifecycleOutcome::CreateAmbiguous
    );
    assert!(ambiguous_receipt.body.ambiguity);
    assert_eq!(context.fixture.counts().3, 1);

    let restarted = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("restart provisioner");
    let first_reconcile = restarted
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("recover ambiguous create");
    assert_eq!(first_reconcile.body.recovered, 1);
    assert_eq!(first_reconcile.body.active_ready, 1);
    assert_eq!(first_reconcile.body.escaped_compute_remaining, 0);
    restarted
        .verify_reconcile_receipt(&first_reconcile)
        .expect("verify reconcile receipt");
    assert_eq!(first_reconcile.body.initial_inventory_sha256.len(), 64);
    assert_eq!(first_reconcile.body.final_inventory_sha256.len(), 64);

    let orphan_request = context.request();
    let orphan_create = ProviderCreateRequest {
        protocol_version: mcloving_provisioner::PROTOCOL_VERSION.to_owned(),
        provisioner_id: context.config.provisioner_id.clone(),
        provisioner_config_sha256: context.config.canonical_digest().expect("config digest"),
        request_sha256: digest(&serde_json::to_vec(&orphan_request).expect("request JSON")),
        request: orphan_request,
    };
    let orphan_instance_id = context.fixture.inject_orphan(orphan_create);
    let orphan_reconcile = restarted
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("clean orphan");
    assert_eq!(orphan_reconcile.body.orphan_cleaned, 1);
    assert!(
        orphan_reconcile
            .body
            .orphan_instance_ids
            .contains(&orphan_instance_id)
    );
    assert_eq!(orphan_reconcile.body.escaped_compute_remaining, 0);

    context.fixture.mark_agent_lost(request.request_id);
    let lost_reconcile = restarted
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("clean lost agent");
    assert_eq!(lost_reconcile.body.cleaned, 1);
    assert_eq!(lost_reconcile.body.active_ready, 0);
    assert_eq!(lost_reconcile.body.escaped_compute_remaining, 0);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn lost_delete_response_and_instance_expiry_reconcile_without_escaped_compute() {
    let delete_context = Context::new(FixtureMode::Ready).await;
    let delete_request = delete_context.request();
    delete_context
        .provisioner
        .provision(&delete_request)
        .await
        .expect("ready before delete response loss");
    delete_context
        .fixture
        .set_mode(FixtureMode::MalformedDeleteOnce);
    let ambiguous = delete_context
        .provisioner
        .cancel(&cancel_request(
            &delete_context.config,
            &delete_request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("retained ambiguous delete receipt");
    assert_eq!(
        ambiguous.body.outcome,
        LifecycleOutcome::ReconciliationRequired
    );
    assert!(ambiguous.body.ambiguity);
    assert!(!ambiguous.body.cleanup_confirmed);
    assert_eq!(delete_context.fixture.counts().3, 0);

    let recovered = delete_context
        .provisioner
        .reconcile(&reconcile_request(
            &delete_context.config,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("reconcile lost delete response");
    assert_eq!(recovered.body.cleaned, 1);
    assert_eq!(recovered.body.escaped_compute_remaining, 0);
    assert!(
        recovered
            .body
            .cleaned_request_ids
            .contains(&delete_request.request_id)
    );

    let expiry_context = Context::new(FixtureMode::Ready).await;
    let mut expiry_request = expiry_context.request();
    expiry_request.instance_expires_at_unix_ms = now_ms() + 500;
    let ready = expiry_context
        .provisioner
        .provision(&expiry_request)
        .await
        .expect("short-lived ready instance");
    assert_eq!(ready.body.outcome, LifecycleOutcome::Ready);
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    let expired = expiry_context
        .provisioner
        .reconcile(&reconcile_request(
            &expiry_context.config,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("reconcile expired instance");
    assert_eq!(expired.body.cleaned, 1);
    assert_eq!(expired.body.escaped_compute_remaining, 0);
    assert_eq!(expiry_context.fixture.counts().3, 0);
}

#[tokio::test]
async fn final_inventory_substitution_is_reported_as_escaped_compute() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before final inventory substitution");
    context
        .fixture
        .set_mode(FixtureMode::SubstituteFinalInventory);

    let receipt = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("retain escaped-compute truth");
    assert_eq!(receipt.body.active_ready, 0);
    assert_eq!(receipt.body.escaped_compute_remaining, 1);
    assert!(receipt.body.active_instance_ids.is_empty());
}

#[tokio::test]
async fn duplicate_final_inventory_identity_is_rejected() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before duplicate final inventory");
    context
        .fixture
        .set_mode(FixtureMode::DuplicateFinalInventory);

    assert!(matches!(
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await,
        Err(ProvisionerError::InvalidProviderResponse)
    ));
}

#[tokio::test]
async fn quota_and_all_certified_bindings_fail_before_provider_access() {
    let context = Context::with_quota(FixtureMode::Ready, 1).await;
    let first = context.request();
    context
        .provisioner
        .provision(&first)
        .await
        .expect("first instance");
    let second = context.request();
    assert!(matches!(
        context.provisioner.provision(&second).await,
        Err(ProvisionerError::CapacityExhausted)
    ));
    let creates = context.fixture.counts().0;
    for mutate in 0..8 {
        let mut denied = context.request();
        match mutate {
            0 => denied.provider_id.push_str("-substituted"),
            1 => denied.provider_account_id.push_str("-substituted"),
            2 => denied.provider_region.push_str("-substituted"),
            3 => denied.agent.template_sha256 = digest(b"other-template"),
            4 => denied.agent.image_sha256 = digest(b"other-image"),
            5 => denied.agent.bootstrap_sha256 = digest(b"other-bootstrap"),
            6 => denied.agent.network.allow_ingress = true,
            _ => denied.agent.volumes.allow_host_mounts = true,
        }
        assert!(matches!(
            context.provisioner.provision(&denied).await,
            Err(ProvisionerError::BindingMismatch)
        ));
    }
    assert_eq!(context.fixture.counts().0, creates);
}

#[tokio::test]
async fn pending_instance_becomes_ready_with_bounded_polling() {
    let context = Context::new(FixtureMode::PendingThenReady).await;
    let receipt = context
        .provisioner
        .provision(&context.request())
        .await
        .expect("eventual ready");
    assert_eq!(receipt.body.outcome, LifecycleOutcome::Ready);
    assert!(context.fixture.counts().2 >= 2);
}

#[tokio::test]
async fn concurrent_process_instances_converge_on_one_create_and_one_receipt() {
    let context = Context::new(FixtureMode::PendingThenReady).await;
    let peer = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("peer provisioner");
    let request = context.request();
    let (first, second) = tokio::join!(
        context.provisioner.provision(&request),
        peer.provision(&request)
    );
    let first = first.expect("first concurrent receipt");
    let second = second.expect("second concurrent receipt");
    assert_eq!(first, second);
    assert_eq!(first.body.outcome, LifecycleOutcome::Ready);
    assert_eq!(context.fixture.counts().0, 1);
}

#[tokio::test]
async fn cutover_and_rollback_generations_share_retained_cleanup_state() {
    let context = Context::new(FixtureMode::Ready).await;
    let mut cutover = context.request();
    cutover.activation_mode = ActivationMode::Cutover;
    cutover.previous_generation = Some(context.config.generation - 1);
    let cutover_receipt = context
        .provisioner
        .provision(&cutover)
        .await
        .expect("cutover generation");
    assert_eq!(
        cutover_receipt.body.activation_mode,
        ActivationMode::Cutover
    );
    context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &cutover,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("clean cutover generation");

    let mut rollback_config = context.config.clone();
    rollback_config.generation -= 1;
    let rollback = Provisioner::new(
        rollback_config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("rollback runtime generation");
    let mut rollback_request = provision_request(&rollback_config, IMPLEMENTATION_SHA256);
    rollback_request.activation_mode = ActivationMode::Rollback;
    rollback_request.previous_generation = Some(context.config.generation);
    let rollback_receipt = rollback
        .provision(&rollback_request)
        .await
        .expect("rollback generation");
    assert_eq!(
        rollback_receipt.body.activation_mode,
        ActivationMode::Rollback
    );
    assert_eq!(
        rollback_receipt.body.request_expected_generation,
        rollback_config.generation
    );
}

#[tokio::test]
async fn invalid_authority_configuration_fails_before_private_state_creation() {
    let fixture = Fixture::start(FixtureMode::Ready).await;
    let temporary = tempfile::tempdir().expect("temporary directory");
    let state_dir = temporary.path().join("must-not-exist");
    let mut config = configuration(&fixture, state_dir.clone(), IMPLEMENTATION_SHA256, 1);
    config.agent.network.allow_ingress = true;
    assert!(matches!(
        Provisioner::new(
            config,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await,
        Err(ProvisionerError::InvalidConfig)
    ));
    assert!(!state_dir.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_binary_is_bounded_and_does_not_disclose_authority_material() {
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::process::Stdio;
    use tokio::io::AsyncWriteExt as _;

    let fixture = Fixture::start(FixtureMode::Ready).await;
    let temporary = tempfile::tempdir().expect("temporary directory");
    let executable = std::path::PathBuf::from(env!("CARGO_BIN_EXE_mcloving-provisioner"));
    let implementation_sha256 = sha256_file(&executable).await.expect("binary digest");
    let config = configuration(
        &fixture,
        temporary.path().join("binary-state"),
        &implementation_sha256,
        1,
    );
    let request = provision_request(&config, &implementation_sha256);
    let config_path = temporary.path().join("config.json");
    let token_path = temporary.path().join("provider-token");
    let public_key_path = temporary.path().join("provider-public-key");
    let signing_key_path = temporary.path().join("receipt-signing-key");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&config).expect("config JSON"),
    )
    .expect("write config");
    let write_private = |path: &std::path::Path, bytes: &[u8]| {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .expect("create private fixture file");
        file.write_all(bytes).expect("write private fixture file");
        file.sync_all().expect("sync private fixture file");
    };
    write_private(&token_path, PROVIDER_TOKEN.as_bytes());
    std::fs::write(&public_key_path, fixture.public_key()).expect("write public key");
    write_private(&signing_key_path, RECEIPT_KEY);

    let mut child = tokio::process::Command::new(&executable)
        .env("MCLOVING_PROVISIONER_CONFIG", &config_path)
        .env("MCLOVING_PROVISIONER_PROVIDER_TOKEN_FILE", &token_path)
        .env(
            "MCLOVING_PROVISIONER_PROVIDER_PUBLIC_KEY_FILE",
            &public_key_path,
        )
        .env(
            "MCLOVING_PROVISIONER_RECEIPT_SIGNING_KEY_FILE",
            &signing_key_path,
        )
        .env("MCLOVING_PROVISIONER_TEST_MODE", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn provisioner binary");
    let command = mcloving_provisioner::Command::Provision {
        request: Box::new(request),
    };
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(&serde_json::to_vec(&command).expect("command JSON"))
        .await
        .expect("write command");
    stdin.write_all(b"\n").await.expect("write newline");
    stdin.shutdown().await.expect("close child stdin");
    drop(stdin);
    let output = child.wait_with_output().await.expect("wait for binary");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: serde_json::Value =
        parse_json_no_duplicates(&output.stdout).expect("bounded binary output");
    assert_eq!(
        response.get("ok").and_then(serde_json::Value::as_bool),
        Some(true)
    );
    assert!(
        !output
            .stdout
            .windows(PROVIDER_TOKEN.len())
            .any(|window| window == PROVIDER_TOKEN.as_bytes())
    );
    assert!(
        !output
            .stdout
            .windows(RECEIPT_KEY.len())
            .any(|window| window == RECEIPT_KEY)
    );
    assert_eq!(fixture.counts().0, 1);
}

#[test]
fn duplicate_json_members_are_denied_recursively() {
    assert!(
        parse_json_no_duplicates::<serde_json::Value>(br#"{"outer":{"id":1,"id":2}}"#).is_err()
    );
}

#[test]
fn cleanup_reason_is_a_closed_provider_protocol_enum() {
    let encoded = serde_json::to_string(&CleanupReason::Orphan).expect("serialize reason");
    assert_eq!(encoded, "\"orphan\"");
    assert!(serde_json::from_str::<CleanupReason>("\"arbitrary-effect\"").is_err());
}

fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn now_ms() -> i64 {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time");
    i64::try_from(duration.as_millis()).expect("milliseconds")
}

#[test]
fn public_content_digest_matches_test_helper() {
    assert_eq!(content_sha256(b"mcloving"), digest(b"mcloving"));
}
