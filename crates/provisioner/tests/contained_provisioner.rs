#[path = "../../test-support/diff003.rs"]
mod diff003;

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

/// Lifetime every `provision_request` grants its request and its instance.
///
/// Durations are `u64` milliseconds throughout this file; the protocol carries
/// timestamps as `i64`, so cross over with [`millis`] rather than casting.
const REQUEST_LIFETIME_MS: u64 = 120_000;
const REQUEST_INSTANCE_LIFETIME_MS: u64 = 90_000;

/// Ceiling the contained configuration puts on instance lifetime and identity
/// TTL. It has to cover `REQUEST_LIFETIME_MS`, because every request this
/// suite builds asks for exactly that much.
const POLICY_MAX_INSTANCE_LIFETIME_MS: u64 = REQUEST_LIFETIME_MS;

/// Startup budget for cases whose asserted outcome is *not* the startup
/// timeout.
///
/// `Provisioner::startup_deadline` anchors the budget to wall-clock time at
/// admission and charges the whole provision path against it — the ledger
/// write, the provider create round trip, instance validation and only then
/// the readiness polls. A short budget therefore races real I/O rather than
/// bounding startup, and on a loaded host `StartupTimeoutCleaned` preempts
/// whatever outcome the test meant to observe.
///
/// The deadline is also clamped to the request's own
/// `instance_expires_at_unix_ms`, so handing that same span to
/// `startup_timeout_ms` makes the request lifetime the binding deadline. The
/// startup budget then stops being a second, shorter clock that host load can
/// exhaust, and these tests assert their outcome against the only expiry they
/// actually care about.
const STARTUP_BUDGET_BEYOND_TEST_WORK_MS: u64 = REQUEST_INSTANCE_LIFETIME_MS;

/// Delay the fixture holds a delayed-create response open for before
/// answering. The startup budgets below are derived from it.
const FIXTURE_DELAYED_CREATE_MS: u64 = 200;

/// Delay the rendezvous-on-create cases ask the fixture to hold its create
/// response open for, via `Fixture::set_create_delay_ms`.
///
/// These cases are genuinely two-sided windows: something else — a deadline
/// expiry, a cancellation, a reconcile snapshot — has to land after the
/// create call opens yet before the fixture answers it. Widening the delay
/// well past the modes' own `FIXTURE_DELAYED_CREATE_MS` widens both margins
/// at once instead of splitting a couple of hundred milliseconds between
/// them.
const FIXTURE_RENDEZVOUS_CREATE_MS: u64 = 3_000;

/// Delay the fixture holds a raced response open for on the non-create paths
/// a concurrent peer has to win against: the empty final inventory a newer
/// reconcile must refresh the row inside, and the malformed delete a
/// concurrent confirmed cleanup must land inside. Sized like the rendezvous
/// create so the peer gets seconds, while staying under the default provider
/// timeout with the same headroom as the held-open pending snapshot.
const FIXTURE_RENDEZVOUS_HOLD_MS: u64 = 3_000;

/// Delay the two retains-a-ready-transition cases ask the fixture to hold the
/// raced inventory snapshot response open for.
///
/// The snapshot is captured when the inventory call arrives, before the hold,
/// so holding the response past the full rendezvous create guarantees the
/// create lands after the capture — and the extra margin gives the provision
/// a cushion to mark the row ready before the reconcile resumes and takes its
/// next ledger read. The provider timeout for those cases is derived to clear
/// this hold.
const FIXTURE_HELD_SNAPSHOT_MS: u64 = FIXTURE_RENDEZVOUS_CREATE_MS + 2_000;

/// Startup budget for the case whose deadline must expire *inside* the held
/// create: a third of the delay the fixture holds the create open. The
/// admission write would have to take a full second to miss
/// the create call, and the create would have to answer three times early for
/// the deadline not to have passed.
const STARTUP_BUDGET_DURING_CREATE_MS: u64 = FIXTURE_RENDEZVOUS_CREATE_MS / 3;

/// Startup budget for the cases where the startup timeout *is* the subject.
///
/// It must sit below the delay the fixture injects on the path under test —
/// `FIXTURE_DELAYED_CREATE_MS` for the delayed-create modes, 3 s for the
/// delayed lookup modes, and the backdated admission in the recovery-anchoring
/// test — so the deadline is already past when the observation lands. Host
/// load only pushes those delays further out, so firing stays deterministic in
/// the one direction these tests depend on.
const STARTUP_BUDGET_UNDER_TEST_MS: u64 = 50;

/// Provider round-trip budget for cases whose asserted outcome does not put
/// the provider timeout under test.
///
/// `provider_timeout_ms` bounds every loopback HTTP call to the fixture —
/// connect and full round trip — so the old 300 ms default made each provider
/// call a race against host load: a slow but *successful* create, lookup,
/// inventory or delete exhausts the budget, and the outcome under test
/// degrades into `ReconciliationRequired` or an unconfirmed cleanup.
///
/// Unlike the startup budget above, this figure cannot borrow the request
/// lifetime. It also feeds the observation-freshness window
/// (`provider_timeout_ms` plus clock skew), which the stale-observation case
/// must stay outside of with its 60 s backdate, and the configuration ceiling
/// rejects anything over 60 s. 5 s clears the longest delay the fixture
/// injects on a default-path call — the 3 s rendezvous holds on the pending
/// snapshot, the empty final inventory and the malformed delete — with
/// seconds of headroom while staying an order of magnitude inside both
/// ceilings. Cases that bound a specific fixture delay (the 5.1 s slow
/// inventory, the held-open rendezvous create, the held snapshot responses)
/// keep their own derived timeouts.
const PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS: u64 = 5_000;

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
    DelayedMalformedCreateOnce,
    DelayedMalformedLookupOnce,
    DelayedSnapshotPendingThenMalformed,
    MalformedDeleteOnce,
    DelayedMalformedDeleteOnce,
    DelayedCleanupAbsentThenLive,
    SubstituteFinalInventory,
    DuplicateFinalInventory,
    DisappearFromFinalInventory,
    DelayedReady,
    DelayedCreateReady,
    DelayedCreateAfterInitialSnapshot,
    DelayedCreateAfterFinalSnapshot,
    DelayedPendingRefreshAfterInitialSnapshot,
    DelayedAbsence,
    DelayedSnapshotAbsentThenPendingThenReady,
    DelayedEmptyFinalInventoryOnce,
    DelayedInitialInventoryResponse,
    DelayedSnapshotFinalInventory,
    SlowInitialInventory,
}

struct Inner {
    mode: FixtureMode,
    instances: HashMap<Uuid, ProviderInstance>,
    creates: usize,
    deletes: usize,
    lookups: usize,
    malformed_create_sent: bool,
    malformed_lookup_sent: bool,
    snapshot_pending_sent: bool,
    malformed_delete_sent: bool,
    inventory_reads: usize,
    inventory_started: usize,
    create_started: usize,
    lookup_started: usize,
    create_delay_override_ms: Option<u64>,
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
                malformed_lookup_sent: false,
                snapshot_pending_sent: false,
                malformed_delete_sent: false,
                inventory_reads: 0,
                inventory_started: 0,
                create_started: 0,
                lookup_started: 0,
                create_delay_override_ms: None,
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

    fn lookup_starts(&self) -> usize {
        self.state
            .inner
            .lock()
            .expect("fixture state")
            .lookup_started
    }

    fn inject_orphan(&self, create: ProviderCreateRequest) -> Uuid {
        let mut inner = self.state.inner.lock().expect("fixture state");
        let instance = make_instance(&create, ProviderInstanceState::Ready, false);
        let id = instance.instance_id;
        inner.instances.insert(create.request.request_id, instance);
        id
    }

    fn inject_orphan_with_instance_id(&self, create: ProviderCreateRequest, instance_id: Uuid) {
        let mut inner = self.state.inner.lock().expect("fixture state");
        let mut instance = make_instance(&create, ProviderInstanceState::Ready, false);
        instance.instance_id = instance_id;
        inner.instances.insert(create.request.request_id, instance);
    }

    fn substitute_lookup_instance(&self, request_id: Uuid) {
        let mut inner = self.state.inner.lock().expect("fixture state");
        let instance = inner
            .instances
            .get_mut(&request_id)
            .expect("fixture instance");
        instance.instance_id = Uuid::new_v4();
        instance.effective_agent.template_sha256 = digest(b"substituted-lookup-template");
    }

    fn mark_agent_lost(&self, request_id: Uuid) {
        let mut inner = self.state.inner.lock().expect("fixture state");
        inner
            .instances
            .get_mut(&request_id)
            .expect("fixture instance")
            .state = ProviderInstanceState::AgentLost;
    }

    fn mark_ready(&self, request_id: Uuid) {
        let mut inner = self.state.inner.lock().expect("fixture state");
        let instance = inner
            .instances
            .get_mut(&request_id)
            .expect("fixture instance");
        instance.state = ProviderInstanceState::Ready;
        instance.observed_at_unix_ms = now_ms();
    }

    fn remove_instance(&self, request_id: Uuid) {
        self.state
            .inner
            .lock()
            .expect("fixture state")
            .instances
            .remove(&request_id);
    }

    fn instance(&self, request_id: Uuid) -> ProviderInstance {
        self.state
            .inner
            .lock()
            .expect("fixture state")
            .instances
            .get(&request_id)
            .expect("fixture instance")
            .clone()
    }

    fn set_mode(&self, mode: FixtureMode) {
        self.state.inner.lock().expect("fixture state").mode = mode;
    }

    /// Hold the create response open for longer than the mode's own delay, so
    /// a test that rendezvouses on the create call has a wide window to work
    /// in rather than a few hundred milliseconds that host load can close.
    fn set_create_delay_ms(&self, delay_ms: u64) {
        self.state
            .inner
            .lock()
            .expect("fixture state")
            .create_delay_override_ms = Some(delay_ms);
    }

    async fn wait_for_create_start(&self) {
        for _ in 0..1_000 {
            if self
                .state
                .inner
                .lock()
                .expect("fixture state")
                .create_started
                != 0
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("provider create did not start");
    }

    async fn wait_for_lookup_start(&self) {
        self.wait_for_lookup_start_after(0).await;
    }

    async fn wait_for_lookup_start_after(&self, minimum: usize) {
        for _ in 0..1_000 {
            if self
                .state
                .inner
                .lock()
                .expect("fixture state")
                .lookup_started
                > minimum
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("provider lookup did not start");
    }

    async fn wait_for_inventory_start(&self, minimum: usize) {
        for _ in 0..1_000 {
            if self
                .state
                .inner
                .lock()
                .expect("fixture state")
                .inventory_started
                >= minimum
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        panic!("provider inventory did not start");
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
    let create_delay_ms = {
        let mut inner = state.inner.lock().expect("fixture state");
        inner.create_started += 1;
        if let Some(override_ms) = inner.create_delay_override_ms {
            override_ms
        } else {
            match inner.mode {
                FixtureMode::DelayedCreateAfterInitialSnapshot
                | FixtureMode::DelayedCreateAfterFinalSnapshot => 100,
                FixtureMode::DelayedCreateReady | FixtureMode::DelayedMalformedCreateOnce => {
                    FIXTURE_DELAYED_CREATE_MS
                }
                _ => 0,
            }
        }
    };
    if create_delay_ms != 0 {
        tokio::time::sleep(std::time::Duration::from_millis(create_delay_ms)).await;
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
        FixtureMode::PendingThenReady
        | FixtureMode::PendingForever
        | FixtureMode::DelayedMalformedLookupOnce
        | FixtureMode::DelayedSnapshotPendingThenMalformed
        | FixtureMode::DelayedPendingRefreshAfterInitialSnapshot
        | FixtureMode::DelayedSnapshotAbsentThenPendingThenReady
        | FixtureMode::DelayedReady
        | FixtureMode::DelayedAbsence => ProviderInstanceState::Pending,
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
    if matches!(
        inner.mode,
        FixtureMode::MalformedCreateOnce | FixtureMode::DelayedMalformedCreateOnce
    ) && !inner.malformed_create_sent
    {
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
    let (
        delayed_mode,
        malformed_lookup,
        snapshot_pending,
        snapshot_absent,
        malformed_after_snapshot,
    ) = {
        let mut inner = state.inner.lock().expect("fixture state");
        inner.lookup_started += 1;
        inner.lookups += 1;
        let malformed_lookup =
            inner.mode == FixtureMode::DelayedMalformedLookupOnce && !inner.malformed_lookup_sent;
        if malformed_lookup {
            inner.malformed_lookup_sent = true;
        }
        let snapshot_pending = if inner.mode == FixtureMode::DelayedSnapshotPendingThenMalformed
            && !inner.snapshot_pending_sent
        {
            inner.snapshot_pending_sent = true;
            Some(ProviderLookup {
                request_id,
                observed_at_unix_ms: now_ms(),
                instance: inner.instances.get(&request_id).cloned(),
            })
        } else {
            None
        };
        let snapshot_absent = matches!(
            inner.mode,
            FixtureMode::DelayedSnapshotAbsentThenPendingThenReady
                | FixtureMode::DelayedCleanupAbsentThenLive
        ) && !inner.snapshot_pending_sent;
        if snapshot_absent {
            inner.snapshot_pending_sent = true;
        }
        let malformed_after_snapshot = inner.mode
            == FixtureMode::DelayedSnapshotPendingThenMalformed
            && inner.lookups >= 3
            && !inner.malformed_lookup_sent;
        if malformed_after_snapshot {
            inner.malformed_lookup_sent = true;
        }
        (
            inner.mode,
            malformed_lookup,
            snapshot_pending,
            snapshot_absent,
            malformed_after_snapshot,
        )
    };
    if let Some(snapshot_pending) = snapshot_pending {
        tokio::time::sleep(std::time::Duration::from_millis(3_000)).await;
        return signed_response(&state, snapshot_pending);
    }
    if snapshot_absent {
        let snapshot = ProviderLookup {
            request_id,
            observed_at_unix_ms: now_ms(),
            instance: None,
        };
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        return signed_response(&state, snapshot);
    }
    if delayed_mode == FixtureMode::DelayedPendingRefreshAfterInitialSnapshot {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    } else if matches!(
        delayed_mode,
        FixtureMode::DelayedReady | FixtureMode::DelayedAbsence
    ) || malformed_lookup
    {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    if malformed_lookup || malformed_after_snapshot {
        return Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("{"))
            .expect("malformed lookup fixture response");
    }
    let mut inner = state.inner.lock().expect("fixture state");
    if inner.mode == FixtureMode::DelayedAbsence {
        inner.instances.remove(&request_id);
    }
    let ready = (inner.mode == FixtureMode::PendingThenReady && inner.lookups >= 2)
        || (inner.mode == FixtureMode::DelayedSnapshotAbsentThenPendingThenReady
            && inner.lookups >= 4)
        || inner.mode == FixtureMode::DelayedReady;
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
    let delayed_inventory_snapshot = {
        let mut inner = state.inner.lock().expect("fixture state");
        inner.inventory_started += 1;
        let delayed_initial = inner.mode == FixtureMode::DelayedCreateAfterInitialSnapshot
            && inner.inventory_started == 1;
        let delayed_initial_response = inner.mode == FixtureMode::DelayedInitialInventoryResponse
            && inner.inventory_started == 1;
        let delayed_pending_initial = inner.mode
            == FixtureMode::DelayedPendingRefreshAfterInitialSnapshot
            && inner.inventory_started == 1;
        let delayed_empty_final = inner.mode == FixtureMode::DelayedEmptyFinalInventoryOnce
            && inner.inventory_started == 2;
        let delayed_final = matches!(
            inner.mode,
            FixtureMode::DelayedSnapshotFinalInventory
                | FixtureMode::DelayedCreateAfterFinalSnapshot
        ) && inner.inventory_started == 2;
        if delayed_initial
            || delayed_initial_response
            || delayed_pending_initial
            || delayed_empty_final
            || delayed_final
        {
            inner.inventory_reads += 1;
            // The raced retains-a-ready-transition snapshots and the raced
            // empty final inventory are windows a concurrent peer has to win
            // against, so they get rendezvous-scale holds; the remaining
            // delayed snapshots only need to outlast their test's own
            // bookkeeping.
            let hold_ms = if delayed_initial
                || (delayed_final && inner.mode == FixtureMode::DelayedCreateAfterFinalSnapshot)
            {
                FIXTURE_HELD_SNAPSHOT_MS
            } else if delayed_empty_final {
                FIXTURE_RENDEZVOUS_HOLD_MS
            } else {
                200
            };
            Some((
                hold_ms,
                ProviderInventory {
                    provisioner_id: "contained-provisioner".to_owned(),
                    complete: true,
                    observed_at_unix_ms: if delayed_initial_response {
                        now_ms() + 4_000
                    } else {
                        now_ms()
                    },
                    instances: if delayed_empty_final || delayed_pending_initial {
                        Vec::new()
                    } else {
                        inner.instances.values().cloned().collect()
                    },
                },
            ))
        } else {
            None
        }
    };
    if let Some((hold_ms, snapshot)) = delayed_inventory_snapshot {
        tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;
        return signed_response(&state, snapshot);
    }
    let slow_initial = {
        let inner = state.inner.lock().expect("fixture state");
        inner.mode == FixtureMode::SlowInitialInventory && inner.inventory_reads == 0
    };
    if slow_initial {
        tokio::time::sleep(std::time::Duration::from_millis(5_100)).await;
    }
    let mut inner = state.inner.lock().expect("fixture state");
    inner.inventory_reads += 1;
    if inner.mode == FixtureMode::DisappearFromFinalInventory && inner.inventory_reads >= 2 {
        inner.instances.clear();
    }
    let mut instances = inner.instances.values().cloned().collect::<Vec<_>>();
    if slow_initial {
        let observed_at = now_ms();
        for instance in &mut instances {
            instance.observed_at_unix_ms = observed_at;
        }
    }
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
    let malformed_delay = {
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
        if inner.mode != FixtureMode::DelayedCleanupAbsentThenLive {
            inner.instances.remove(&request.request_id);
        }
        inner.deletes += 1;
        if matches!(
            inner.mode,
            FixtureMode::MalformedDeleteOnce | FixtureMode::DelayedMalformedDeleteOnce
        ) && !inner.malformed_delete_sent
        {
            inner.malformed_delete_sent = true;
            Some(inner.mode == FixtureMode::DelayedMalformedDeleteOnce)
        } else {
            None
        }
    };
    if let Some(delayed) = malformed_delay {
        if delayed {
            // A concurrent confirmed cleanup has to land while this delete is
            // held open, so the hold gets rendezvous scale rather than a
            // couple of hundred milliseconds host load can close.
            tokio::time::sleep(std::time::Duration::from_millis(FIXTURE_RENDEZVOUS_HOLD_MS)).await;
        }
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

    /// The default startup budget deliberately exceeds anything the contained
    /// harness can spend, so a test only observes `StartupTimeoutCleaned` when
    /// it asked for it. Tests that put the timeout itself under test opt in
    /// with [`Context::with_startup_timeout`]. The default provider timeout
    /// likewise clears every round trip the fixture serves on the default
    /// path; tests that bound a specific fixture delay opt in with
    /// [`Context::with_provider_timeout`] or [`Context::with_limits`].
    async fn with_quota(mode: FixtureMode, maximum: u32) -> Self {
        Self::with_limits(
            mode,
            maximum,
            PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
            STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        )
        .await
    }

    async fn with_provider_timeout(mode: FixtureMode, provider_timeout_ms: u64) -> Self {
        Self::with_limits(
            mode,
            4,
            provider_timeout_ms,
            STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        )
        .await
    }

    async fn with_startup_timeout(mode: FixtureMode, startup_timeout_ms: u64) -> Self {
        Self::with_limits(
            mode,
            4,
            PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
            startup_timeout_ms,
        )
        .await
    }

    async fn with_limits(
        mode: FixtureMode,
        maximum: u32,
        provider_timeout_ms: u64,
        startup_timeout_ms: u64,
    ) -> Self {
        let fixture = Fixture::start(mode).await;
        let temporary = tempfile::tempdir().expect("temporary directory");
        let mut config = configuration(
            &fixture,
            temporary.path().join("state"),
            IMPLEMENTATION_SHA256,
            maximum,
        );
        config.provider_timeout_ms = provider_timeout_ms;
        config.startup_timeout_ms = startup_timeout_ms;
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
            max_ttl_ms: POLICY_MAX_INSTANCE_LIFETIME_MS,
        },
        quotas: QuotaPolicy {
            max_active_global: maximum,
            max_active_per_tenant: maximum,
            max_active_per_project: maximum,
        },
        provider_timeout_ms: PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        startup_timeout_ms: STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        startup_poll_interval_ms: 10,
        max_instance_lifetime_ms: POLICY_MAX_INSTANCE_LIFETIME_MS,
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
    let source_transport =
        diff003_source_transport_authority().unwrap_or_else(|| "source.contained:443".to_owned());
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
                source_transport,
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

fn diff003_source_transport_authority() -> Option<String> {
    let root = std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR")?;
    let source: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&root).join("SCM-001.json")).ok()?,
    )
    .ok()?;
    source["initial"]["repository_trees"][0]["repository_url"]
        .as_str()
        .map(ToOwned::to_owned)
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
        expires_at_unix_ms: now + millis(REQUEST_LIFETIME_MS),
        instance_expires_at_unix_ms: now + millis(REQUEST_INSTANCE_LIFETIME_MS),
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
    let mut request = context.request();
    if let Some((tenant_id, project_id, build_id, attempt_id)) = diff003_source_workload() {
        request.tenant_id = tenant_id;
        request.project_id = project_id;
        request.build_id = build_id;
        request.attempt_id = attempt_id;
    }
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
    newer.expires_at_unix_ms = newer.requested_at_unix_ms + millis(REQUEST_LIFETIME_MS);
    newer.instance_expires_at_unix_ms =
        newer.requested_at_unix_ms + millis(REQUEST_INSTANCE_LIFETIME_MS);
    newer.audit_lineage = "contained-newer-fence".to_owned();
    let next = context
        .provisioner
        .provision(&newer)
        .await
        .expect("newer fence after cleanup");
    assert_eq!(next.body.fence_token, 2);
    assert_eq!(context.fixture.counts().0, 2);
    if let Ok(root) = std::env::var("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR") {
        let source_receipt = std::fs::read(std::path::Path::new(&root).join("SCM-001.json"))
            .expect("read live DIFF-003 source receipt");
        std::fs::write(
            std::path::Path::new(&root).join("PROV-001.json"),
            diff003::receipt(
                "PROV-001",
                serde_json::json!({
                    "ready": ready,
                    "cancelled": cancelled,
                    "next_generation": next,
                    "source_acquisition_receipt_sha256": digest(&source_receipt),
                }),
            ),
        )
        .expect("write DIFF-003 provisioner receipts");
    }
}

fn diff003_source_workload() -> Option<(Uuid, Uuid, Uuid, Uuid)> {
    let root = std::env::var_os("MCLOVING_DIFF003_RUNTIME_OUTPUT_DIR")?;
    let source: serde_json::Value = serde_json::from_slice(
        &std::fs::read(std::path::Path::new(&root).join("SCM-001.json")).ok()?,
    )
    .ok()?;
    Some((
        Uuid::parse_str(source["initial"]["organization_id"].as_str()?).ok()?,
        Uuid::parse_str(source["initial"]["project_id"].as_str()?).ok()?,
        Uuid::parse_str(source["initial"]["build_id"].as_str()?).ok()?,
        Uuid::parse_str(source["initial"]["attempt_id"].as_str()?).ok()?,
    ))
}

#[tokio::test]
async fn substitution_startup_failure_and_timeout_leave_no_compute() {
    let mut substitution_denials = 0;
    let mut cleaned_failures = 0;
    // Each case carries the startup budget its outcome depends on. The first
    // three are decided the moment the create response lands, so they must not
    // be preempted by a deadline; only the last one waits for the timeout.
    for (mode, expected, startup_timeout_ms) in [
        (
            FixtureMode::SubstituteTemplate,
            LifecycleOutcome::SubstitutionDeniedCleaned,
            STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        ),
        (
            FixtureMode::SubstituteIdentity,
            LifecycleOutcome::SubstitutionDeniedCleaned,
            STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        ),
        (
            FixtureMode::StartupFailed,
            LifecycleOutcome::StartupFailedCleaned,
            STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
        ),
        (
            FixtureMode::PendingForever,
            LifecycleOutcome::StartupTimeoutCleaned,
            STARTUP_BUDGET_UNDER_TEST_MS,
        ),
    ] {
        let context = Context::with_startup_timeout(mode, startup_timeout_ms).await;
        let receipt = context
            .provisioner
            .provision(&context.request())
            .await
            .expect("bounded failure receipt");
        assert_eq!(receipt.body.outcome, expected);
        assert!(receipt.body.cleanup_confirmed);
        assert!(!receipt.body.ambiguity);
        assert_eq!(context.fixture.counts().3, 0);
        substitution_denials += usize::from(
            matches!(
                mode,
                FixtureMode::SubstituteTemplate | FixtureMode::SubstituteIdentity
            ) && receipt.body.outcome == LifecycleOutcome::SubstitutionDeniedCleaned,
        );
        cleaned_failures +=
            usize::from(receipt.body.cleanup_confirmed && context.fixture.counts().3 == 0);
    }
    diff003::record_assertion(
        "provisioner_template_substitution_denied",
        "denied",
        serde_json::json!({
            "substitution_cases": 2,
            "substitution_denials": substitution_denials,
            "cleaned_failure_cases": cleaned_failures,
            "escaped_compute": 0,
        }),
        substitution_denials == 2 && cleaned_failures == 4,
    );
}

#[tokio::test]
async fn stale_or_wrong_provider_attestation_never_becomes_ready() {
    let mut ambiguous_attestations = 0;
    let mut cleaned_ambiguous_instances = 0;
    let mut cleanup_outcomes = Vec::new();
    for mode in [
        FixtureMode::StaleObservation,
        FixtureMode::WrongProviderIdentity,
    ] {
        let context = Context::new(mode).await;
        let request = context.request();
        let receipt = context
            .provisioner
            .provision(&request)
            .await
            .expect("ambiguous attestation receipt");
        assert_eq!(receipt.body.outcome, LifecycleOutcome::CreateAmbiguous);
        assert!(receipt.body.ambiguity);
        assert!(!receipt.body.cleanup_confirmed);
        assert_eq!(context.fixture.counts().3, 1);
        ambiguous_attestations += usize::from(
            receipt.body.outcome == LifecycleOutcome::CreateAmbiguous
                && receipt.body.ambiguity
                && context.fixture.counts().3 == 1,
        );
        let cancellation = context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
            .expect("clean ambiguous attestation instance");
        assert!(matches!(
            cancellation.body.outcome,
            LifecycleOutcome::Cancelled | LifecycleOutcome::SubstitutionDeniedCleaned
        ));
        assert!(cancellation.body.cleanup_confirmed);
        assert_eq!(context.fixture.counts().3, 0);
        cleanup_outcomes.push(format!("{:?}", cancellation.body.outcome));
        cleaned_ambiguous_instances += usize::from(
            matches!(
                cancellation.body.outcome,
                LifecycleOutcome::Cancelled | LifecycleOutcome::SubstitutionDeniedCleaned
            ) && cancellation.body.cleanup_confirmed
                && context.fixture.counts().3 == 0,
        );
    }

    let denied = Context::new(FixtureMode::Unauthorized).await;
    assert!(matches!(
        denied.provisioner.provision(&denied.request()).await,
        Err(ProvisionerError::ProviderUnauthorized)
    ));
    assert_eq!(denied.fixture.counts().0, 0);
    assert_eq!(denied.fixture.counts().3, 0);
    diff003::record_assertion(
        "provisioner_stale_instance_denied",
        "denied",
        serde_json::json!({
            "attestation_cases": 2,
            "ambiguous_not_ready": ambiguous_attestations,
            "ambiguous_instances_cleaned": cleaned_ambiguous_instances,
            "cleanup_outcomes": cleanup_outcomes,
            "unauthorized_provider_creates": denied.fixture.counts().0,
            "escaped_compute_remaining": 0,
        }),
        ambiguous_attestations == 2
            && cleaned_ambiguous_instances == 2
            && denied.fixture.counts().0 == 0,
    );
}

#[tokio::test]
async fn ambiguous_create_restart_orphan_and_agent_loss_reconcile() {
    let context = Context::with_startup_timeout(FixtureMode::MalformedCreateOnce, 5_000).await;
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
    let interruption_reconciled = first_reconcile.body.recovered == 1
        && first_reconcile.body.active_ready == 1
        && first_reconcile.body.escaped_compute_remaining == 0;
    diff003::record_assertion(
        "provisioner_interruption_reconciled",
        "reconciled",
        serde_json::json!({
            "recovered": first_reconcile.body.recovered,
            "active_ready": first_reconcile.body.active_ready,
            "escaped_compute_remaining": first_reconcile.body.escaped_compute_remaining,
        }),
        interruption_reconciled,
    );

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
    let orphan_cleaned = orphan_reconcile.body.orphan_cleaned == 1
        && orphan_reconcile
            .body
            .orphan_instance_ids
            .contains(&orphan_instance_id)
        && orphan_reconcile.body.escaped_compute_remaining == 0;
    diff003::record_assertion(
        "provisioner_orphan_cleaned",
        "cleaned",
        serde_json::json!({
            "orphan_instance_id": orphan_instance_id,
            "orphan_cleaned": orphan_reconcile.body.orphan_cleaned,
            "escaped_compute_remaining": orphan_reconcile.body.escaped_compute_remaining,
        }),
        orphan_cleaned,
    );

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
    let recovered_lifecycle = delete_context
        .provisioner
        .provision(&delete_request)
        .await
        .expect("replay recovered delete lifecycle");
    assert_eq!(
        recovered_lifecycle.body.outcome,
        LifecycleOutcome::Cancelled
    );
    assert!(recovered_lifecycle.body.cleanup_confirmed);

    let expiry_context = Context::new(FixtureMode::Ready).await;
    let mut expiry_request = expiry_context.request();
    expiry_request.instance_expires_at_unix_ms = now_ms() + 3_000;
    let ready = expiry_context
        .provisioner
        .provision(&expiry_request)
        .await
        .expect("short-lived ready instance");
    assert_eq!(ready.body.outcome, LifecycleOutcome::Ready);
    tokio::time::sleep(std::time::Duration::from_millis(3_100)).await;
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
async fn final_inventory_absence_closes_the_retained_ready_row() {
    let context = Context::new(FixtureMode::DisappearFromFinalInventory).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before final inventory disappearance");

    let reconciled = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("reconcile final signed absence");
    assert_eq!(reconciled.body.active_ready, 0);
    assert_eq!(reconciled.body.cleaned, 1);
    assert_eq!(reconciled.body.ambiguous, 0);
    assert_eq!(reconciled.body.escaped_compute_remaining, 0);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read reconciled state");
    assert_eq!(state, "deleted");
}

#[tokio::test]
async fn slow_initial_inventory_uses_post_response_validation_time() {
    let context = Context::with_provider_timeout(FixtureMode::SlowInitialInventory, 7_000).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before slow inventory");

    let receipt = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("slow signed inventory remains valid");
    assert_eq!(receipt.body.active_ready, 1);
    assert_eq!(receipt.body.cleaned, 0);
    assert_eq!(receipt.body.escaped_compute_remaining, 0);
    assert_eq!(context.fixture.counts().3, 1);
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
async fn duplicate_initial_inventory_instance_id_is_rejected_before_cleanup() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    let ready = context
        .provisioner
        .provision(&request)
        .await
        .expect("ready retained instance");
    let active_instance_id = ready.body.instance_id.expect("ready instance identity");
    let orphan_request = context.request();
    let orphan_create = ProviderCreateRequest {
        protocol_version: mcloving_provisioner::PROTOCOL_VERSION.to_owned(),
        provisioner_id: context.config.provisioner_id.clone(),
        provisioner_config_sha256: context.config.canonical_digest().expect("config digest"),
        request_sha256: digest(&serde_json::to_vec(&orphan_request).expect("request JSON")),
        request: orphan_request,
    };
    context
        .fixture
        .inject_orphan_with_instance_id(orphan_create, active_instance_id);

    assert!(matches!(
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256,))
            .await,
        Err(ProvisionerError::InvalidProviderResponse)
    ));
    assert_eq!(context.fixture.counts().1, 0);
    assert_eq!(context.fixture.counts().3, 2);
}

#[tokio::test]
async fn quota_and_all_certified_bindings_fail_before_provider_access() {
    let context = Context::with_limits(
        FixtureMode::Ready,
        1,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        5_000,
    )
    .await;
    let first = context.request();
    context
        .provisioner
        .provision(&first)
        .await
        .expect("first instance");
    let second = context.request();
    let exhaustion_result = context.provisioner.provision(&second).await;
    let exhaustion_denied = matches!(exhaustion_result, Err(ProvisionerError::CapacityExhausted));
    assert!(exhaustion_denied);
    let creates = context.fixture.counts().0;
    let mut binding_denials = 0;
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
        let binding_result = context.provisioner.provision(&denied).await;
        let binding_denied = matches!(binding_result, Err(ProvisionerError::BindingMismatch));
        assert!(binding_denied);
        binding_denials += usize::from(binding_denied);
    }
    assert_eq!(context.fixture.counts().0, creates);
    diff003::record_assertion(
        "provisioner_exhaustion_denied",
        "denied",
        serde_json::json!({
            "capacity_result": "capacity_exhausted",
            "binding_mutations_denied": binding_denials,
            "provider_creates_before": creates,
            "provider_creates_after": context.fixture.counts().0,
        }),
        exhaustion_denied && binding_denials == 8 && context.fixture.counts().0 == creates,
    );
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
async fn startup_absence_yields_to_a_newer_pending_revision() {
    let context = Context::with_startup_timeout(
        FixtureMode::DelayedSnapshotAbsentThenPendingThenReady,
        10_000,
    )
    .await;
    let request = context.request();
    let stale_absence = Box::pin(context.provisioner.provision(&request));
    let positive_peer = async {
        context.fixture.wait_for_lookup_start().await;
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger for positive startup peer");
        database
            .execute(
                "UPDATE requests SET state = state, instance_json = instance_json
                 WHERE request_id = ?1",
                [request.request_id.to_string()],
            )
            .expect("publish newer pending observation through legacy trigger");
        context.fixture.mark_ready(request.request_id);
        Box::pin(context.provisioner.provision(&request))
            .await
            .expect("positive startup peer publishes ready receipt")
    };
    let (stale_absence, positive_peer) = tokio::join!(stale_absence, positive_peer);
    let stale_absence = stale_absence.expect("stale startup absence converges on ready truth");
    assert_eq!(stale_absence.body.outcome, LifecycleOutcome::Ready);
    assert_eq!(positive_peer.body.outcome, LifecycleOutcome::Ready);
    assert!(!stale_absence.body.cleanup_confirmed);
    assert!(!positive_peer.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().1, 0);
    assert_eq!(context.fixture.counts().3, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let retained: (String, i64) = database
        .query_row(
            "SELECT state,
                    (SELECT count(*) FROM cleanup_intents WHERE request_id = ?1)
             FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read state and cleanup intent after startup race");
    assert_eq!(retained, ("ready".to_owned(), 0));
}

#[tokio::test]
async fn provider_ready_after_startup_deadline_is_cleaned_as_timeout() {
    let context =
        Context::with_startup_timeout(FixtureMode::DelayedReady, STARTUP_BUDGET_UNDER_TEST_MS)
            .await;
    let receipt = context
        .provisioner
        .provision(&context.request())
        .await
        .expect("late ready cleanup receipt");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn lookup_absence_after_startup_deadline_is_classified_as_timeout() {
    let context =
        Context::with_startup_timeout(FixtureMode::DelayedAbsence, STARTUP_BUDGET_UNDER_TEST_MS)
            .await;
    let receipt = context
        .provisioner
        .provision(&context.request())
        .await
        .expect("late absence cleanup receipt");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn terminal_cancel_state_survives_late_startup_lookup_failure() {
    let context =
        Context::with_startup_timeout(FixtureMode::DelayedMalformedLookupOnce, 1_000).await;
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_lookup_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };

    let (provisioned, cancelled) = tokio::join!(provision, cancel);
    let provisioned = provisioned.expect("late lookup failure converges on cancellation");
    let cancelled = cancelled.expect("concurrent cancellation receipt");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(provisioned.body.cleanup_confirmed);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read terminal state");
    assert_eq!(state, "deleted");
}

#[tokio::test]
async fn terminal_cancel_state_survives_late_recovery_lookup_failure() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before simulated recovery");
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "UPDATE requests SET state = 'pending', latest_receipt_json = NULL
             WHERE request_id = ?1",
            [request.request_id.to_string()],
        )
        .expect("simulate pending recovery boundary");
    drop(database);
    context
        .fixture
        .set_mode(FixtureMode::DelayedMalformedLookupOnce);

    let recovery = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_lookup_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };
    let (recovered, cancelled) = tokio::join!(recovery, cancel);
    let recovered = recovered.expect("late recovery failure converges on cancellation");
    let cancelled = cancelled.expect("concurrent cancellation receipt");
    assert_eq!(recovered.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(recovered.body.cleanup_confirmed);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read terminal state");
    assert_eq!(state, "deleted");
}

#[tokio::test]
async fn lookup_only_cancel_recovers_a_concurrent_concrete_cleanup() {
    let context = Context::new(FixtureMode::DelayedMalformedCreateOnce).await;
    let request = context.request();
    let ambiguous = context
        .provisioner
        .provision(&request)
        .await
        .expect("ambiguous create before lookup-only cancel");
    assert_eq!(ambiguous.body.outcome, LifecycleOutcome::CreateAmbiguous);
    let instance = context.fixture.instance(request.request_id);
    context.fixture.set_mode(FixtureMode::DelayedAbsence);

    let cancellation = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);
    let cancel = context.provisioner.cancel(&cancellation);
    let concurrent_cleanup = async {
        context.fixture.wait_for_lookup_start().await;
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger");
        database
            .execute(
                "UPDATE requests SET state = 'deleting', instance_json = ?2
                 WHERE request_id = ?1",
                rusqlite::params![
                    request.request_id.to_string(),
                    serde_json::to_vec(&instance).expect("instance JSON"),
                ],
            )
            .expect("publish concurrent concrete cleanup");
    };
    let (cancelled, ()) = tokio::join!(cancel, concurrent_cleanup);
    let cancelled = cancelled.expect("recover concurrent cleanup");
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().2, 2);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn lookup_only_cancel_retains_intent_when_create_wins_the_state_race() {
    let context = Context::new(FixtureMode::DelayedMalformedCreateOnce).await;
    let request = context.request();
    let ambiguous = context
        .provisioner
        .provision(&request)
        .await
        .expect("ambiguous create before lookup-only cancel");
    assert_eq!(ambiguous.body.outcome, LifecycleOutcome::CreateAmbiguous);
    let instance = context.fixture.instance(request.request_id);
    context
        .fixture
        .set_mode(FixtureMode::DelayedMalformedLookupOnce);

    let cancellation = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);
    let cancel = context.provisioner.cancel(&cancellation);
    let concurrent_create = async {
        context.fixture.wait_for_lookup_start().await;
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger");
        database
            .execute(
                "UPDATE requests SET state = 'pending', instance_json = ?2
                 WHERE request_id = ?1",
                rusqlite::params![
                    request.request_id.to_string(),
                    serde_json::to_vec(&instance).expect("instance JSON"),
                ],
            )
            .expect("publish concurrent create winner");
    };
    let (cancelled, ()) = tokio::join!(cancel, concurrent_create);
    let cancelled = cancelled.expect("retained cancellation intent cleans concurrent instance");
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn stale_pending_refresh_recovers_a_concurrent_ambiguous_winner() {
    let context = Context::with_limits(
        FixtureMode::DelayedSnapshotPendingThenMalformed,
        4,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        10_000,
    )
    .await;
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let concurrent_ambiguity = async {
        context.fixture.wait_for_lookup_start().await;
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger");
        database
            .execute(
                "UPDATE requests SET state = 'ambiguous' WHERE request_id = ?1",
                [request.request_id.to_string()],
            )
            .expect("publish concurrent ambiguity");
        context.fixture.mark_ready(request.request_id);
    };
    let (recovered, ()) = tokio::join!(provision, concurrent_ambiguity);
    let recovered = recovered.expect("stale ambiguity returns to normal recovery");
    assert_eq!(recovered.body.outcome, LifecycleOutcome::Ready);
    assert!(!recovered.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().1, 0);
    assert_eq!(context.fixture.counts().3, 1);
}

#[tokio::test]
async fn delayed_pending_refresh_cannot_reactivate_confirmed_cleanup() {
    let context = Context::with_limits(
        FixtureMode::DelayedSnapshotPendingThenMalformed,
        4,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        10_000,
    )
    .await;
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_lookup_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };
    let (provisioned, cancelled) = tokio::join!(provision, cancel);
    let provisioned = provisioned.expect("delayed pending converges on cancellation");
    let cancelled = cancelled.expect("concurrent cancellation receipt");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(provisioned.body.cleanup_confirmed);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().2, 2);
    assert_eq!(context.fixture.counts().3, 0);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read terminal state");
    assert_eq!(state, "deleted");
}

#[tokio::test]
async fn post_lookup_timeout_cannot_reactivate_confirmed_cleanup() {
    let context = Context::with_limits(
        FixtureMode::DelayedSnapshotPendingThenMalformed,
        4,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        2_000,
    )
    .await;
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_lookup_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };
    let (provisioned, cancelled) = tokio::join!(provision, cancel);
    let provisioned = provisioned.expect("late timeout converges on cancellation");
    let cancelled = cancelled.expect("concurrent cancellation receipt");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(provisioned.body.cleanup_confirmed);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read terminal state");
    assert_eq!(state, "deleted");
}

#[tokio::test]
async fn immediate_ready_after_startup_deadline_is_cleaned_as_timeout() {
    let context = Context::with_startup_timeout(
        FixtureMode::DelayedCreateReady,
        STARTUP_BUDGET_UNDER_TEST_MS,
    )
    .await;
    let receipt = context
        .provisioner
        .provision(&context.request())
        .await
        .expect("late create cleanup receipt");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn admission_deadline_is_rechecked_after_durable_intent_before_create() {
    let context =
        Context::with_startup_timeout(FixtureMode::Ready, STARTUP_BUDGET_UNDER_TEST_MS).await;
    let database_path = context.config.state_dir.join("provisioner.sqlite3");
    let (locked, receiver) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let database = rusqlite::Connection::open(database_path).expect("open blocking ledger");
        database
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold admission transaction");
        locked.send(()).expect("signal held transaction");
        std::thread::sleep(std::time::Duration::from_millis(100));
        database.execute_batch("COMMIT").expect("release ledger");
    });
    receiver.recv().expect("wait for held transaction");

    let receipt = context
        .provisioner
        .provision(&context.request())
        .await
        .expect("deadline terminal receipt");
    blocker.join().expect("blocking ledger thread");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().0, 0);
}

#[tokio::test]
async fn cancel_preserves_a_confirmed_failed_startup_receipt() {
    let context =
        Context::with_startup_timeout(FixtureMode::Ready, STARTUP_BUDGET_UNDER_TEST_MS).await;
    let request = context.request();
    let database_path = context.config.state_dir.join("provisioner.sqlite3");
    let (locked, receiver) = std::sync::mpsc::channel();
    let blocker = std::thread::spawn(move || {
        let database = rusqlite::Connection::open(database_path).expect("open blocking ledger");
        database
            .execute_batch("BEGIN IMMEDIATE")
            .expect("hold admission transaction");
        locked.send(()).expect("signal held transaction");
        std::thread::sleep(std::time::Duration::from_millis(100));
        database.execute_batch("COMMIT").expect("release ledger");
    });
    receiver.recv().expect("wait for held transaction");

    let failed = context
        .provisioner
        .provision(&request)
        .await
        .expect("confirmed startup timeout");
    blocker.join().expect("blocking ledger thread");
    assert_eq!(failed.body.outcome, LifecycleOutcome::StartupTimeoutCleaned);
    assert!(failed.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts(), (0, 0, 0, 0));

    let cancelled = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("return existing failed-startup receipt");
    assert_eq!(
        cancelled.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert_eq!(cancelled.signature, failed.signature);
    assert_eq!(context.fixture.counts(), (0, 0, 0, 0));
}

#[tokio::test]
async fn reconcile_does_not_close_an_in_flight_fresh_intent() {
    // This one needs the create call to be reached — it rendezvouses on
    // `wait_for_create_start` — and only then to blow its deadline while the
    // call is still open. Hold the create open far longer than the mode's own
    // delay so both sides of that window have room; the provider timeout has
    // to clear the held-open create as well.
    let context = Context::with_limits(
        FixtureMode::DelayedCreateReady,
        4,
        FIXTURE_RENDEZVOUS_CREATE_MS + 2_000,
        STARTUP_BUDGET_DURING_CREATE_MS,
    )
    .await;
    context
        .fixture
        .set_create_delay_ms(FIXTURE_RENDEZVOUS_CREATE_MS);
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let reconcile = async {
        context.fixture.wait_for_create_start().await;
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await
    };
    let (provisioned, reconciled) = tokio::join!(provision, reconcile);
    let provisioned = provisioned.expect("in-flight provision result");
    let reconciled = reconciled.expect("concurrent reconciliation receipt");
    assert_eq!(
        provisioned.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert_eq!(reconciled.body.cleaned, 0);
    assert_eq!(reconciled.body.ambiguous, 1);
    assert!(
        reconciled
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );
}

#[tokio::test]
async fn reconciliation_rejects_an_admission_after_its_initial_ledger_snapshot() {
    let context = Context::new(FixtureMode::DelayedSnapshotFinalInventory).await;
    let request = context.request();
    let reconcile_request = reconcile_request(&context.config, IMPLEMENTATION_SHA256);
    let reconciliation = context.provisioner.reconcile(&reconcile_request);
    let admission = async {
        context.fixture.wait_for_inventory_start(2).await;
        context.provisioner.provision(&request).await
    };
    let (reconciled, admitted) = tokio::join!(reconciliation, admission);
    let admitted = admitted.expect("concurrent admission succeeds");
    assert_eq!(admitted.body.outcome, LifecycleOutcome::Ready);
    assert!(matches!(
        reconciled,
        Err(ProvisionerError::ReconciliationRequired)
    ));

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let evidence: i64 = database
        .query_row(
            "SELECT count(*) FROM evidence WHERE evidence_kind = 'reconcile'",
            [],
            |row| row.get(0),
        )
        .expect("count reconciliation evidence");
    assert_eq!(evidence, 0);
}

#[tokio::test]
async fn reconciliation_uses_inventory_observation_for_the_create_peer_window() {
    let context = Context::new(FixtureMode::MalformedCreateOnce).await;
    let request = context.request();
    let provisioned = context
        .provisioner
        .provision(&request)
        .await
        .expect("malformed create response is retained as ambiguous");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::CreateAmbiguous);
    context.fixture.remove_instance(request.request_id);
    context
        .fixture
        .set_mode(FixtureMode::DelayedInitialInventoryResponse);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let created_at_unix_ms: i64 = database
        .query_row(
            "SELECT created_at_unix_ms FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read admission time");
    drop(database);
    let peer_deadline = created_at_unix_ms
        + i64::try_from(context.config.provider_timeout_ms).expect("provider timeout")
        + 1_000;
    let start_at = peer_deadline - 100;
    let delay_ms = start_at.saturating_sub(now_ms());
    tokio::time::sleep(std::time::Duration::from_millis(
        u64::try_from(delay_ms).expect("nonnegative delay"),
    ))
    .await;

    let reconciled = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("pre-deadline signed absence remains ambiguous");
    assert!(now_ms() >= peer_deadline);
    assert_eq!(reconciled.body.cleaned, 0);
    assert_eq!(reconciled.body.ambiguous, 1);
    assert!(
        reconciled
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("reopen retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read retained ambiguous state");
    assert_eq!(state, "ambiguous");
}

#[tokio::test]
async fn reconciliation_absence_yields_to_a_newer_concrete_pending_observation() {
    // The reconcile arm below sleeps out the create peer window — the
    // provider timeout plus one second — and must then observe the row while
    // it is still pending, so the startup budget is derived from the peer
    // window it has to outlive, with margin for the reconcile itself. The
    // provision arm's `StartupTimeoutCleaned` outcome only needs the deadline
    // to fire eventually.
    let context = Context::with_limits(
        FixtureMode::DelayedPendingRefreshAfterInitialSnapshot,
        4,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS,
        PROVIDER_TIMEOUT_BEYOND_TEST_WORK_MS + 5_000,
    )
    .await;
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let reconcile = async {
        context.fixture.wait_for_lookup_start().await;
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger");
        let created_at_unix_ms: i64 = database
            .query_row(
                "SELECT created_at_unix_ms FROM requests WHERE request_id = ?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .expect("read admission time");
        drop(database);
        let peer_deadline = created_at_unix_ms
            + i64::try_from(context.config.provider_timeout_ms).expect("provider timeout")
            + 1_000;
        let delay_ms = (peer_deadline + 50).saturating_sub(now_ms());
        tokio::time::sleep(std::time::Duration::from_millis(
            u64::try_from(delay_ms).expect("nonnegative delay"),
        ))
        .await;

        let observed_lookups = context.fixture.lookup_starts();
        context
            .fixture
            .wait_for_lookup_start_after(observed_lookups)
            .await;
        let reconciled = context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await
            .expect("newer concrete Pending observation wins");
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("reopen retained ledger");
        let state: String = database
            .query_row(
                "SELECT state FROM requests WHERE request_id = ?1",
                [request.request_id.to_string()],
                |row| row.get(0),
            )
            .expect("read retained Pending state");
        (reconciled, state, context.fixture.counts())
    };
    let (provisioned, (reconciled, state, counts)) = tokio::join!(provision, reconcile);
    let provisioned = provisioned.expect("eventual Pending startup timeout is cleaned");
    assert_eq!(
        provisioned.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert_eq!(reconciled.body.cleaned, 0);
    assert_eq!(reconciled.body.ambiguous, 1);
    assert!(
        reconciled
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );
    assert_eq!(state, "pending");
    assert_eq!(counts.1, 0);
    assert_eq!(counts.3, 1);
}

#[tokio::test]
async fn reconciliation_absence_yields_to_a_newer_same_instance_ready_observation() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    let provisioned = context
        .provisioner
        .provision(&request)
        .await
        .expect("provision retained ready instance");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Ready);
    context
        .fixture
        .set_mode(FixtureMode::DelayedEmptyFinalInventoryOnce);

    // The newer reconcile has to refresh the row revision while the stale
    // reconcile's empty final inventory is held open; the fixture holds that
    // response for `FIXTURE_RENDEZVOUS_HOLD_MS` so it gets seconds to do so.
    let stale_request = reconcile_request(&context.config, IMPLEMENTATION_SHA256);
    let stale_reconciliation = context.provisioner.reconcile(&stale_request);
    let newer_reconciliation = async {
        context.fixture.wait_for_inventory_start(2).await;
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await
    };
    let (stale, newer) = tokio::join!(stale_reconciliation, newer_reconciliation);
    let stale = stale.expect("stale absence is retained as ambiguous");
    let newer = newer.expect("newer live observation converges");
    assert_eq!(stale.body.active_ready, 0);
    assert_eq!(stale.body.cleaned, 0);
    assert_eq!(stale.body.ambiguous, 1);
    assert!(
        stale
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );
    assert_eq!(newer.body.active_ready, 1);
    assert_eq!(newer.body.ambiguous, 0);
    assert_eq!(context.fixture.counts().1, 0);
    assert_eq!(context.fixture.counts().3, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read retained ready state");
    assert_eq!(state, "ready");
}

#[tokio::test]
async fn reconciliation_cas_loss_rolls_back_tentative_absence_intent() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("provision retained ready instance");
    context
        .fixture
        .set_mode(FixtureMode::DelayedEmptyFinalInventoryOnce);

    let reconcile_request = reconcile_request(&context.config, IMPLEMENTATION_SHA256);
    let reconciliation = context.provisioner.reconcile(&reconcile_request);
    let newer_legacy_refresh = async {
        context.fixture.wait_for_inventory_start(2).await;
        let database_path = context.config.state_dir.join("provisioner.sqlite3");
        let request_id = request.request_id;
        tokio::task::spawn_blocking(move || {
            let database = rusqlite::Connection::open(database_path)
                .expect("open ledger for concurrent legacy refresh");
            database
                .execute_batch("BEGIN IMMEDIATE")
                .expect("hold revision write transaction");
            database
                .execute(
                    "UPDATE requests SET state = state, instance_json = instance_json
                     WHERE request_id = ?1",
                    [request_id.to_string()],
                )
                .expect("refresh same concrete instance through legacy trigger");
            std::thread::sleep(std::time::Duration::from_millis(300));
            database
                .execute_batch("COMMIT")
                .expect("publish newer concrete revision");
        })
        .await
        .expect("join concurrent legacy refresh");
    };
    let (reconciled, ()) = tokio::join!(reconciliation, newer_legacy_refresh);
    let reconciled = reconciled.expect("CAS loss is reported as ambiguous");
    assert_eq!(reconciled.body.cleaned, 0);
    assert_eq!(reconciled.body.ambiguous, 1);
    assert!(
        reconciled
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let retained: (String, i64) = database
        .query_row(
            "SELECT state,
                    (SELECT count(*) FROM cleanup_intents WHERE request_id = ?1)
             FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read state and cleanup intent after CAS loss");
    assert_eq!(retained, ("ready".to_owned(), 0));
    drop(database);

    let cancelled = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("later cancellation selects its own cleanup intent");
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().1, 1);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn reconciliation_retains_a_ready_transition_after_its_initial_inventory_snapshot() {
    // The reconcile has to capture its initial inventory snapshot while the
    // create is still open, and the create has to land — and be marked ready —
    // before the final inventory read. Rendezvous on a held-open create for
    // the first side; the fixture holds the captured initial snapshot
    // response past the whole create for the second, so both margins get
    // seconds instead of splitting the mode's own 100 ms. The provider
    // timeout is derived to clear the held snapshot, and the startup budget
    // has to outlast the held create.
    let context = Context::with_limits(
        FixtureMode::DelayedCreateAfterInitialSnapshot,
        4,
        FIXTURE_HELD_SNAPSHOT_MS + 2_000,
        STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
    )
    .await;
    context
        .fixture
        .set_create_delay_ms(FIXTURE_RENDEZVOUS_CREATE_MS);
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let reconcile = async {
        context.fixture.wait_for_create_start().await;
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await
    };
    let (provisioned, reconciled) = tokio::join!(provision, reconcile);
    let provisioned = provisioned.expect("in-flight create becomes ready");
    let reconciled = reconciled.expect("reconciliation preserves the live instance");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Ready);
    assert_eq!(reconciled.body.active_ready, 1);
    assert_eq!(reconciled.body.cleaned, 0);
    assert_eq!(reconciled.body.ambiguous, 0);
    assert!(reconciled.body.ambiguous_request_ids.is_empty());
    assert_eq!(context.fixture.counts().1, 0);
    assert_eq!(context.fixture.counts().3, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read retained ready state");
    assert_eq!(state, "ready");
}

#[tokio::test]
async fn reconciliation_retains_a_ready_transition_after_its_final_inventory_snapshot() {
    // Both of the reconcile's inventory captures have to land while the
    // create is still open, and the ready mark should then land inside the
    // held final snapshot so the reconcile's last ledger read observes it.
    // Rendezvous on a held-open create for the first side; the fixture holds
    // the captured final snapshot response past the whole create for the
    // second. The provider timeout is derived to clear the held snapshot,
    // and the startup budget has to outlast the held create.
    let context = Context::with_limits(
        FixtureMode::DelayedCreateAfterFinalSnapshot,
        4,
        FIXTURE_HELD_SNAPSHOT_MS + 2_000,
        STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
    )
    .await;
    context
        .fixture
        .set_create_delay_ms(FIXTURE_RENDEZVOUS_CREATE_MS);
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let reconcile = async {
        context.fixture.wait_for_create_start().await;
        context
            .provisioner
            .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
            .await
    };
    let (provisioned, reconciled) = tokio::join!(provision, reconcile);
    let provisioned = provisioned.expect("in-flight create becomes ready");
    let reconciled = reconciled.expect("reconciliation reports the snapshot race");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Ready);
    assert_eq!(reconciled.body.active_ready, 0);
    assert_eq!(reconciled.body.ambiguous, 1);
    assert!(
        reconciled
            .body
            .ambiguous_request_ids
            .contains(&request.request_id)
    );
    assert_eq!(context.fixture.counts().3, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read retained ready state");
    assert_eq!(state, "ready");
    drop(database);

    let converged = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("later reconciliation sees converged ready truth");
    assert_eq!(converged.body.active_ready, 1);
    assert_eq!(converged.body.ambiguous, 0);
    assert!(converged.body.ambiguous_request_ids.is_empty());
}

#[tokio::test]
async fn cancellation_wins_an_in_flight_create_and_cleans_returned_compute() {
    // The cancel has to land while the create is held open, so rendezvous on
    // a held-open create rather than racing the mode's own 200 ms delay. The
    // provider timeout has to clear the held create, and the startup budget
    // has to outlast it so the outcome stays Cancelled, not a preempting
    // startup timeout.
    let context = Context::with_limits(
        FixtureMode::DelayedCreateReady,
        4,
        FIXTURE_RENDEZVOUS_CREATE_MS + 2_000,
        STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
    )
    .await;
    context
        .fixture
        .set_create_delay_ms(FIXTURE_RENDEZVOUS_CREATE_MS);
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_create_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };

    let (provisioned, cancelled) = tokio::join!(provision, cancel);
    let provisioned = provisioned.expect("in-flight create converges on cancellation");
    let cancelled = cancelled.expect("concurrent cancellation receipt");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert!(provisioned.body.cleanup_confirmed);
    assert!(cancelled.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);

    let replay = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("terminal cancellation replay");
    assert_eq!(replay.body.outcome, LifecycleOutcome::Cancelled);
    assert!(replay.body.cleanup_confirmed);
}

#[tokio::test]
async fn instance_less_terminal_receipt_yields_to_late_create_ambiguity() {
    // The cancel's lookup has to complete while the malformed create is held
    // open, so rendezvous on a held-open create rather than racing the mode's
    // own 200 ms delay; the provider timeout is derived to clear the held
    // create. The assertion below also counts a *confirmed* cleanup, so the
    // reconciling delete has to complete inside `provider_timeout_ms` — which
    // the derived budget guarantees against host load.
    let context = Context::with_limits(
        FixtureMode::DelayedMalformedCreateOnce,
        4,
        FIXTURE_RENDEZVOUS_CREATE_MS + 2_000,
        STARTUP_BUDGET_BEYOND_TEST_WORK_MS,
    )
    .await;
    context
        .fixture
        .set_create_delay_ms(FIXTURE_RENDEZVOUS_CREATE_MS);
    let request = context.request();
    let provision = context.provisioner.provision(&request);
    let cancel = async {
        context.fixture.wait_for_create_start().await;
        context
            .provisioner
            .cancel(&cancel_request(
                &context.config,
                &request,
                IMPLEMENTATION_SHA256,
            ))
            .await
    };
    let (provisioned, cancelled) = tokio::join!(provision, cancel);
    let provisioned = provisioned.expect("late ambiguous create receipt");
    let cancelled = cancelled.expect("early instance-less cancellation receipt");
    assert_eq!(provisioned.body.outcome, LifecycleOutcome::CreateAmbiguous);
    assert!(provisioned.body.ambiguity);
    assert_eq!(cancelled.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(context.fixture.counts().3, 1);

    // Reconciliation only reclaims an ambiguous row once its startup deadline
    // has passed, and that deadline is anchored to the admission time in the
    // ledger. Retire the admission explicitly rather than leaving a short
    // wall-clock budget to expire on its own, which would race the provision
    // above on a loaded host.
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "UPDATE requests SET created_at_unix_ms = ?2 WHERE request_id = ?1",
            rusqlite::params![
                request.request_id.to_string(),
                now_ms() - millis(STARTUP_BUDGET_BEYOND_TEST_WORK_MS) - 1_000,
            ],
        )
        .expect("retire the admission behind its startup deadline");
    drop(database);

    let reconciled = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("clean late ambiguous compute");
    assert_eq!(reconciled.body.cleaned, 1);
    assert_eq!(reconciled.body.escaped_compute_remaining, 0);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn confirmed_cleanup_dominates_a_concurrent_late_delete_failure() {
    // The winning delete has to confirm while the losing delete's malformed
    // response is held open; the fixture holds it for
    // `FIXTURE_RENDEZVOUS_HOLD_MS` so the race gets seconds of room.
    let context = Context::new(FixtureMode::DelayedMalformedDeleteOnce).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before concurrent cleanup");
    let first = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);
    let second = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);

    let (first_receipt, second_receipt) = tokio::join!(
        context.provisioner.cancel(&first),
        context.provisioner.cancel(&second)
    );
    let first_receipt = first_receipt.expect("first converged cleanup receipt");
    let second_receipt = second_receipt.expect("second converged cleanup receipt");
    assert_eq!(first_receipt.body.outcome, LifecycleOutcome::Cancelled);
    assert_eq!(second_receipt.body.outcome, LifecycleOutcome::Cancelled);
    assert!(first_receipt.body.cleanup_confirmed);
    assert!(second_receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);

    let replay = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("terminal cleanup replay");
    assert_eq!(replay.body.outcome, LifecycleOutcome::Cancelled);
    assert!(replay.body.cleanup_confirmed);
}

#[tokio::test]
async fn cleanup_confirmation_absence_yields_to_a_newer_live_revision() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before concurrent cleanup confirmation");
    context
        .fixture
        .set_mode(FixtureMode::DelayedCleanupAbsentThenLive);
    let first = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);
    let second = cancel_request(&context.config, &request, IMPLEMENTATION_SHA256);

    let (first_receipt, second_receipt) = tokio::join!(
        context.provisioner.cancel(&first),
        context.provisioner.cancel(&second)
    );
    let first_receipt = first_receipt.expect("stale absence recovers newer live truth");
    let second_receipt = second_receipt.expect("live confirmation remains ambiguous");
    for receipt in [&first_receipt, &second_receipt] {
        assert_eq!(
            receipt.body.outcome,
            LifecycleOutcome::ReconciliationRequired
        );
        assert!(receipt.body.ambiguity);
        assert!(!receipt.body.cleanup_confirmed);
    }
    assert_eq!(context.fixture.counts().3, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    let state: String = database
        .query_row(
            "SELECT state FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read cleanup state after confirmation race");
    assert_eq!(state, "deleting");
}

#[tokio::test]
async fn reconciliation_preserves_expiry_outcome_after_delete_response_loss() {
    let context = Context::new(FixtureMode::Ready).await;
    let mut request = context.request();
    request.instance_expires_at_unix_ms = now_ms() + 3_000;
    context
        .provisioner
        .provision(&request)
        .await
        .expect("short-lived ready instance");
    context.fixture.set_mode(FixtureMode::MalformedDeleteOnce);
    tokio::time::sleep(std::time::Duration::from_millis(3_100)).await;

    let uncertain = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("retain uncertain expiry cleanup");
    assert_eq!(uncertain.body.cleaned, 0);
    assert_eq!(uncertain.body.ambiguous, 1);
    assert_eq!(context.fixture.counts().3, 0);

    let recovered = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("confirm absent expired instance");
    assert_eq!(recovered.body.cleaned, 1);
    assert_eq!(recovered.body.escaped_compute_remaining, 0);

    let lifecycle = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("read retained terminal lifecycle");
    assert_eq!(lifecycle.body.outcome, LifecycleOutcome::ExpiredCleaned);
    assert!(lifecycle.body.cleanup_confirmed);
}

#[tokio::test]
async fn cancel_validates_lookup_only_instance_before_cleanup() {
    let context = Context::new(FixtureMode::MalformedCreateOnce).await;
    let request = context.request();
    let ambiguous = context
        .provisioner
        .provision(&request)
        .await
        .expect("ambiguous create receipt");
    assert_eq!(ambiguous.body.outcome, LifecycleOutcome::CreateAmbiguous);
    context
        .fixture
        .substitute_lookup_instance(request.request_id);

    let receipt = context
        .provisioner
        .cancel(&cancel_request(
            &context.config,
            &request,
            IMPLEMENTATION_SHA256,
        ))
        .await
        .expect("substituted lookup cleanup receipt");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::SubstitutionDeniedCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn deleted_crash_recovery_preserves_retained_cleanup_intent() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before simulated cleanup crash");
    context.fixture.remove_instance(request.request_id);
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "INSERT INTO cleanup_intents(request_id, reason_json, outcome_json)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                request.request_id.to_string(),
                serde_json::to_vec(&CleanupReason::Expired).expect("cleanup reason JSON"),
                serde_json::to_vec(&LifecycleOutcome::ExpiredCleaned)
                    .expect("cleanup outcome JSON"),
            ],
        )
        .expect("retain cleanup intent");
    database
        .execute(
            "UPDATE requests SET state = 'deleted', latest_receipt_json = NULL
             WHERE request_id = ?1",
            [request.request_id.to_string()],
        )
        .expect("simulate crash before terminal receipt");
    drop(database);

    let restarted = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("restart provisioner");
    let receipt = restarted
        .provision(&request)
        .await
        .expect("recover retained cleanup truth");
    assert_eq!(receipt.body.outcome, LifecycleOutcome::ExpiredCleaned);
    assert!(receipt.body.cleanup_confirmed);
}

#[tokio::test]
async fn signed_absence_crash_recovery_preserves_startup_outcome() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before simulated signed-absence crash");
    context.fixture.remove_instance(request.request_id);
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "INSERT INTO cleanup_intents(request_id, reason_json, outcome_json)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![
                request.request_id.to_string(),
                serde_json::to_vec(&CleanupReason::StartupTimeout).expect("cleanup reason JSON"),
                serde_json::to_vec(&LifecycleOutcome::StartupTimeoutCleaned)
                    .expect("cleanup outcome JSON"),
            ],
        )
        .expect("retain signed-absence cleanup intent");
    database
        .execute(
            "UPDATE requests SET state = 'deleted', instance_json = NULL,
                                 latest_receipt_json = NULL
             WHERE request_id = ?1",
            [request.request_id.to_string()],
        )
        .expect("simulate crash before signed-absence receipt");
    drop(database);

    let restarted = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("restart provisioner");
    let receipt = restarted
        .provision(&request)
        .await
        .expect("recover signed-absence startup truth");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
}

#[tokio::test]
async fn recovery_anchors_startup_timeout_to_immutable_admission_time() {
    // The startup timeout is the subject here: recovery must measure it from
    // the admission time recorded in the ledger, so the backdated
    // `created_at_unix_ms` below has to sit further in the past than the
    // budget.
    let context =
        Context::with_startup_timeout(FixtureMode::Ready, STARTUP_BUDGET_UNDER_TEST_MS).await;
    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before simulated pending crash");
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "UPDATE requests
             SET state = 'pending', latest_receipt_json = NULL,
                 created_at_unix_ms = ?2, updated_at_unix_ms = ?3
             WHERE request_id = ?1",
            rusqlite::params![
                request.request_id.to_string(),
                now_ms() - millis(STARTUP_BUDGET_UNDER_TEST_MS) - 1_000,
                now_ms(),
            ],
        )
        .expect("simulate mutable update after original admission");
    drop(database);
    context.fixture.remove_instance(request.request_id);

    let restarted = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("restart provisioner");
    let receipt = restarted
        .provision(&request)
        .await
        .expect("recover against original startup deadline");
    assert_eq!(
        receipt.body.outcome,
        LifecycleOutcome::StartupTimeoutCleaned
    );
    assert!(receipt.body.cleanup_confirmed);
    assert_eq!(context.fixture.counts().3, 0);
}

#[tokio::test]
async fn recovered_absence_preserves_ready_and_deleting_lifecycle_truth() {
    for (state, expected) in [
        ("ready", LifecycleOutcome::AgentLostCleaned),
        ("deleting", LifecycleOutcome::Cancelled),
    ] {
        let context = Context::new(FixtureMode::Ready).await;
        let request = context.request();
        context
            .provisioner
            .provision(&request)
            .await
            .expect("ready before simulated crash boundary");
        context.fixture.remove_instance(request.request_id);
        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("open retained ledger");
        database
            .execute(
                "UPDATE requests SET state = ?2, latest_receipt_json = NULL WHERE request_id = ?1",
                rusqlite::params![request.request_id.to_string(), state],
            )
            .expect("simulate crash before receipt publication");
        drop(database);

        let restarted = Provisioner::new(
            context.config.clone(),
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            context.fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await
        .expect("restart provisioner");
        let receipt = restarted
            .provision(&request)
            .await
            .expect("recover signed absence");
        assert_eq!(receipt.body.outcome, expected);
        assert!(receipt.body.cleanup_confirmed);
        assert!(!receipt.body.ambiguity);

        let database =
            rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
                .expect("reopen retained ledger");
        database
            .execute(
                "UPDATE requests SET latest_receipt_json = NULL WHERE request_id = ?1",
                [request.request_id.to_string()],
            )
            .expect("simulate a second crash after terminal state");
        drop(database);
        let restarted_again = Provisioner::new(
            context.config.clone(),
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            context.fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await
        .expect("restart provisioner again");
        let retained = restarted_again
            .provision(&request)
            .await
            .expect("recover durable absence reason");
        assert_eq!(retained.body.outcome, expected);
        assert!(retained.body.cleanup_confirmed);
    }
}

#[tokio::test]
async fn reconciliation_absence_crash_recovery_preserves_agent_loss() {
    let context = Context::new(FixtureMode::Ready).await;
    let request = context.request();
    let ready = context
        .provisioner
        .provision(&request)
        .await
        .expect("ready before reconciliation absence");
    context.fixture.remove_instance(request.request_id);
    let reconciled = context
        .provisioner
        .reconcile(&reconcile_request(&context.config, IMPLEMENTATION_SHA256))
        .await
        .expect("reconcile signed absence");
    assert_eq!(reconciled.body.cleaned, 1);

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute(
            "UPDATE requests SET latest_receipt_json = ?2 WHERE request_id = ?1",
            rusqlite::params![
                request.request_id.to_string(),
                serde_json::to_vec(&ready).expect("ready receipt JSON"),
            ],
        )
        .expect("simulate crash after state commit but before cleanup receipt publication");
    drop(database);
    let restarted = Provisioner::new(
        context.config.clone(),
        IMPLEMENTATION_SHA256.to_owned(),
        PROVIDER_TOKEN.to_owned(),
        context.fixture.public_key(),
        RECEIPT_KEY.to_vec(),
    )
    .await
    .expect("restart provisioner");
    let receipt = restarted
        .provision(&request)
        .await
        .expect("recover reconciliation agent-loss truth");
    assert_eq!(receipt.body.outcome, LifecycleOutcome::AgentLostCleaned);
    assert!(receipt.body.cleanup_confirmed);
}

#[tokio::test]
async fn concurrent_process_instances_converge_on_one_create_and_one_receipt() {
    let context = Context::with_startup_timeout(FixtureMode::PendingThenReady, 5_000).await;
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

#[tokio::test]
async fn retained_ledger_rejects_provider_scope_drift() {
    let context = Context::new(FixtureMode::Ready).await;
    let state_dir = context.config.state_dir.clone();
    let mut drifted = context.config.clone();
    drifted.provider_region = "substituted-region-2".to_owned();

    assert!(matches!(
        Provisioner::new(
            drifted,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            context.fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await,
        Err(ProvisionerError::StateUnavailable)
    ));
    assert!(state_dir.join("provisioner.sqlite3").is_file());
    assert_eq!(context.fixture.counts().0, 0);
}

#[tokio::test]
async fn retained_ledger_rejects_receipt_signing_identity_drift() {
    let context = Context::new(FixtureMode::Ready).await;
    let mut identifier_drift = context.config.clone();
    identifier_drift.receipt_signing_key_id = "replacement-receipt-key".to_owned();
    assert!(matches!(
        Provisioner::new(
            identifier_drift,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            context.fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await,
        Err(ProvisionerError::StateUnavailable)
    ));

    let replacement_key = b"replacement-receipt-signing-key-000000000000000000000000";
    let mut material_drift = context.config.clone();
    material_drift.receipt_signing_key_sha256 = digest(replacement_key);
    assert!(matches!(
        Provisioner::new(
            material_drift,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            context.fixture.public_key(),
            replacement_key.to_vec(),
        )
        .await,
        Err(ProvisionerError::StateUnavailable)
    ));
    assert_eq!(context.fixture.counts().0, 0);
}

#[tokio::test]
async fn concurrent_processes_serialize_the_ledger_migration_and_fence_legacy_writes() {
    let context = Context::new(FixtureMode::Ready).await;
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open retained ledger");
    database
        .execute_batch(
            "DROP TRIGGER requests_legacy_state_revision_exhausted;
             DROP TRIGGER requests_legacy_state_revision;
             ALTER TABLE metadata DROP COLUMN admission_epoch;
             ALTER TABLE requests DROP COLUMN state_revision;",
        )
        .expect("simulate retained pre-epoch ledger");
    drop(database);

    let first_config = context.config.clone();
    let second_config = context.config.clone();
    let first_provider_key = context.fixture.public_key();
    let second_provider_key = context.fixture.public_key();
    let first = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("first migration runtime")
            .block_on(Provisioner::new(
                first_config,
                IMPLEMENTATION_SHA256.to_owned(),
                PROVIDER_TOKEN.to_owned(),
                first_provider_key,
                RECEIPT_KEY.to_vec(),
            ))
            .is_ok()
    });
    let second = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("second migration runtime")
            .block_on(Provisioner::new(
                second_config,
                IMPLEMENTATION_SHA256.to_owned(),
                PROVIDER_TOKEN.to_owned(),
                second_provider_key,
                RECEIPT_KEY.to_vec(),
            ))
            .is_ok()
    });
    assert!(first.join().expect("first migration process"));
    assert!(second.join().expect("second migration process"));

    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("open migrated ledger");
    let columns: i64 = database
        .query_row(
            "SELECT count(*) FROM pragma_table_info('metadata')
             WHERE name = 'admission_epoch'",
            [],
            |row| row.get(0),
        )
        .expect("count admission epoch columns");
    assert_eq!(columns, 1);
    let revision_columns: i64 = database
        .query_row(
            "SELECT count(*) FROM pragma_table_info('requests')
             WHERE name = 'state_revision'",
            [],
            |row| row.get(0),
        )
        .expect("count state revision columns");
    assert_eq!(revision_columns, 1);
    let compatibility_triggers: i64 = database
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'trigger'
               AND name IN (
                   'requests_legacy_state_revision',
                   'requests_legacy_state_revision_exhausted'
               )",
            [],
            |row| row.get(0),
        )
        .expect("count legacy compatibility triggers");
    assert_eq!(compatibility_triggers, 2);
    drop(database);

    let request = context.request();
    context
        .provisioner
        .provision(&request)
        .await
        .expect("provision after migration");
    let database = rusqlite::Connection::open(context.config.state_dir.join("provisioner.sqlite3"))
        .expect("reopen migrated ledger");
    let revision_before: i64 = database
        .query_row(
            "SELECT state_revision FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read revision before legacy write");
    database
        .execute(
            "UPDATE requests SET state = state, instance_json = instance_json
             WHERE request_id = ?1",
            [request.request_id.to_string()],
        )
        .expect("simulate admitted legacy state writer");
    let revision_after: i64 = database
        .query_row(
            "SELECT state_revision FROM requests WHERE request_id = ?1",
            [request.request_id.to_string()],
            |row| row.get(0),
        )
        .expect("read revision after legacy write");
    assert_eq!(revision_after, revision_before + 1);
}

#[tokio::test]
async fn state_directory_and_database_reject_special_permission_bits() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::start(FixtureMode::Ready).await;
    let temporary = tempfile::tempdir().expect("temporary directory");

    let sticky_state = temporary.path().join("sticky-state");
    std::fs::create_dir(&sticky_state).expect("create sticky state directory");
    std::fs::set_permissions(&sticky_state, std::fs::Permissions::from_mode(0o1700))
        .expect("set sticky state permissions");
    let sticky_config = configuration(&fixture, sticky_state, IMPLEMENTATION_SHA256, 1);
    assert!(matches!(
        Provisioner::new(
            sticky_config,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await,
        Err(ProvisionerError::InvalidConfig)
    ));

    let state_with_special_database = temporary.path().join("special-database-state");
    std::fs::create_dir(&state_with_special_database).expect("create private state directory");
    std::fs::set_permissions(
        &state_with_special_database,
        std::fs::Permissions::from_mode(0o700),
    )
    .expect("set private state permissions");
    let database_path = state_with_special_database.join("provisioner.sqlite3");
    std::fs::write(&database_path, []).expect("create database file");
    std::fs::set_permissions(&database_path, std::fs::Permissions::from_mode(0o4600))
        .expect("set special database permissions");
    let database_config = configuration(
        &fixture,
        state_with_special_database,
        IMPLEMENTATION_SHA256,
        1,
    );
    assert!(matches!(
        Provisioner::new(
            database_config,
            IMPLEMENTATION_SHA256.to_owned(),
            PROVIDER_TOKEN.to_owned(),
            fixture.public_key(),
            RECEIPT_KEY.to_vec(),
        )
        .await,
        Err(ProvisionerError::InvalidConfig)
    ));
    assert_eq!(fixture.counts().0, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standalone_binary_accepts_final_frame_and_does_not_disclose_authority_material() {
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

/// Widen a `u64` millisecond duration into the `i64` the protocol timestamps
/// use. Checked rather than cast, so a duration that could not round-trip
/// fails here instead of wrapping into a nonsensical deadline.
fn millis(value: u64) -> i64 {
    i64::try_from(value).expect("duration fits in a protocol timestamp")
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
