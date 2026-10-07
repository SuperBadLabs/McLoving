//! Negotiated whole-set artifact transport. PostgreSQL reservations/member row
//! locks provide cross-controller quota/retry authority; the runtime never writes
//! or finalizes a staging file synchronously.
use super::*;
use mcloving_agent_protocol::wire::{ArtifactSetControl, ArtifactUploadFrame};
use mcloving_controller_store::{ArtifactMemberClaim, ArtifactSetAuthority, ArtifactSetMember};
use mcloving_domain::artifacts::*;
use mcloving_object_store::{ObjectRef, PendingObject};
use tokio::sync::mpsc;

pub(super) fn admitted_capabilities(mut capabilities: Vec<String>, v2: bool) -> Vec<String> {
    if !v2 {
        capabilities.retain(|capability| capability != ARTIFACT_UPLOAD_CAPABILITY);
    }
    capabilities
}
fn set_id(id: &[u8]) -> Result<[u8; 32], Status> {
    id.try_into()
        .map_err(|_| Status::invalid_argument("artifact set id must be SHA-256"))
}
fn store_status(e: mcloving_controller_store::StoreError) -> Status {
    match e {
        mcloving_controller_store::StoreError::ArtifactQuota => {
            Status::resource_exhausted("artifact_refused:object_quota")
        }
        mcloving_controller_store::StoreError::InvalidAgentSession => {
            Status::failed_precondition("artifact authority is stale or cancelled")
        }
        mcloving_controller_store::StoreError::InvalidObjectRecord(s) => {
            Status::invalid_argument(s)
        }
        other => internal_store_error(other),
    }
}
fn accepted(epoch: u64) -> Response<WorkReceipt> {
    Response::new(WorkReceipt {
        session_epoch: epoch,
        accepted: true,
        published_outcome: WorkOutcome::Unspecified as i32,
        cancellation_requested: false,
    })
}
async fn authority(
    service: &ControllerAgentService,
    identity: &AgentIdentity,
    wire: &WorkAuthority,
) -> Result<ArtifactSetAuthority, Status> {
    let c =
        authorize_work_authority(&service.store, &service.session_churn, identity, wire).await?;
    if !service
        .store
        .agent_session_supports(&wire.agent_id, wire.session_epoch, ARTIFACT_SET_FEATURE)
        .await
        .map_err(store_status)?
    {
        return Err(Status::failed_precondition(
            "artifact-set-v2 was not negotiated; no v1 fallback",
        ));
    }
    Ok(ArtifactSetAuthority {
        organization_id: c.organization_id,
        attempt_id: c.attempt_id,
        fence: c.fence,
        restore_epoch: c.restore_epoch,
        agent_id: wire.agent_id.clone(),
        session_epoch: wire.session_epoch,
    })
}
async fn no_tail(frames: &mut tonic::Streaming<ArtifactUploadFrame>) -> Result<(), Status> {
    if frames.message().await?.is_some() {
        return Err(Status::invalid_argument(
            "artifact control operation carries one frame",
        ));
    }
    Ok(())
}
/// Before registration starts, unadopted claims are cleaned on the blocking
/// pool. Once registration can commit, custody must transfer to maintenance:
/// dropping an RPC is not evidence that PostgreSQL did not commit.
struct PendingCustody {
    store: FilesystemObjectStore,
    pending: Option<PendingObject>,
}
impl PendingCustody {
    fn keep(mut self) -> PendingObject {
        self.pending.take().expect("active pending custody")
    }
}
impl Drop for PendingCustody {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let store = self.store.clone();
            // This drop can happen on a runtime worker or the blocking actor.
            // The actual unlink/fsync always runs off the runtime worker.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn_blocking(move || {
                    let _ = store.abort_pending(&pending);
                });
            } else {
                std::thread::spawn(move || {
                    let _ = store.abort_pending(&pending);
                });
            }
        }
    }
}
/// This is the production custody-transfer boundary, shared with the controlled
/// cancelled-future driver. Retention occurs before polling registration: an
/// interrupted future cannot distinguish rollback from a committed lost result.
async fn register_retaining_custody(
    custody: PendingCustody,
    registration: impl std::future::Future<Output = Result<(), Status>>,
) -> Result<(), Status> {
    let _retained = custody.keep();
    registration.await
}
enum WriterCommand {
    Data(Vec<u8>),
    Finish,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WriterPhase {
    Write,
    Finish,
}
fn spawn_writer(
    store: FilesystemObjectStore,
    namespace: String,
    bytes: u64,
    digest: [u8; 32],
    receiver: mpsc::Receiver<WriterCommand>,
    hook: impl FnMut(WriterPhase) + Send + 'static,
) -> tokio::task::JoinHandle<Result<PendingCustody, Status>> {
    tokio::task::spawn_blocking(move || {
        writer_actor(store, namespace, bytes, digest, receiver, hook)
    })
}
fn writer_actor(
    store: FilesystemObjectStore,
    namespace: String,
    bytes: u64,
    digest: [u8; 32],
    mut commands: mpsc::Receiver<WriterCommand>,
    mut hook: impl FnMut(WriterPhase),
) -> Result<PendingCustody, Status> {
    let mut writer = store
        .begin_artifact(&namespace, bytes)
        .map_err(object_store_status)?;
    while let Some(command) = commands.blocking_recv() {
        match command {
            WriterCommand::Data(data) => {
                hook(WriterPhase::Write);
                writer.write(&data).map_err(object_store_status)?;
            }
            WriterCommand::Finish => {
                hook(WriterPhase::Finish);
                let staged = writer.finish().map_err(object_store_status)?;
                if staged.object_ref().bytes != bytes || staged.object_ref().sha256 != digest {
                    return Err(Status::invalid_argument(ARTIFACT_DIGEST_MISMATCH));
                }
                let pending = staged.persist().map_err(object_store_status)?;
                let mut custody = PendingCustody {
                    store: store.clone(),
                    pending: Some(pending.clone()),
                };
                custody.pending = Some(store.claim_pending(&pending).map_err(object_store_status)?);
                return Ok(custody);
            }
        }
    }
    Err(Status::cancelled(
        "artifact staging cancelled before object-end",
    ))
}
async fn stage(
    service: &ControllerAgentService,
    identity: &AgentIdentity,
    header: mcloving_agent_protocol::wire::ArtifactUploadHeader,
    frames: &mut tonic::Streaming<ArtifactUploadFrame>,
    receive_deadline: tokio::time::Instant,
) -> Result<Response<WorkReceipt>, Status> {
    let wire = header
        .authority
        .ok_or_else(|| Status::invalid_argument("artifact authority required"))?;
    let a = authority(service, identity, &wire).await?;
    let id = set_id(&header.set_id)?;
    let d = set_id(&header.sha256)?;
    let claim: ArtifactMemberClaim = service
        .store
        .claim_artifact_set_member(&a, id, &header.name)
        .await
        .map_err(store_status)?;
    if claim.member.bytes != header.bytes || claim.member.media_type != header.media_type {
        return Err(Status::invalid_argument(
            "artifact member differs from immutable manifest",
        ));
    }
    if let Some(existing) = claim.member.digest {
        if existing != d {
            return Err(Status::invalid_argument("artifact retry digest differs"));
        }
        let token = claim
            .member
            .pending_token
            .clone()
            .ok_or_else(|| Status::internal("artifact pending token absent"))?;
        let object = PendingObject::from_parts(
            token.clone(),
            ObjectRef {
                sha256: d,
                bytes: header.bytes,
            },
        )
        .map_err(object_store_status)?;
        let store = service.object_store.clone();
        tokio::task::spawn_blocking(move || {
            let pending = store.claim_pending(&object)?;
            store.verify_pending(&pending)
        })
        .await
        .map_err(|e| Status::internal(format!("artifact retry worker: {e}")))?
        .map_err(object_store_status)?;
        // No second stage or reservation, including already committed CAS bytes.
        claim.register(d, &token).await.map_err(store_status)?;
        return Ok(accepted(wire.session_epoch));
    }
    let store = service.object_store.clone();
    let namespace = a.organization_id.to_string();
    let (commands, receiver) = mpsc::channel(4);
    let actor = spawn_writer(store, namespace, header.bytes, d, receiver, |_| {});
    let mut object_end = false;
    let received = tokio::time::timeout_at(receive_deadline, async {
        while let Some(frame) = frames.message().await? {
            match frame.frame {
                Some(ArtifactFrame::Data(data))
                    if !object_end && data.len() <= MAX_ARTIFACT_FRAME_BYTES =>
                {
                    commands
                        .send(WriterCommand::Data(data))
                        .await
                        .map_err(|_| Status::cancelled("artifact writer closed"))?
                }
                Some(ArtifactFrame::ObjectEnd(_)) if !object_end => object_end = true,
                _ => {
                    return Err(Status::invalid_argument(
                        "artifact data followed by one explicit object-end required",
                    ));
                }
            }
        }
        if !object_end {
            return Err(Status::invalid_argument(
                "artifact source did not finish growth probe",
            ));
        }
        commands
            .send(WriterCommand::Finish)
            .await
            .map_err(|_| Status::cancelled("artifact writer closed"))?;
        Ok::<(), Status>(())
    })
    .await;
    drop(commands);
    let receive_error = match received {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e),
        Err(_) => Some(Status::deadline_exceeded("artifact receive budget spent")),
    };
    let result = actor
        .await
        .map_err(|e| Status::internal(format!("artifact writer worker: {e}")))?;
    // An actor may refuse its physical quota before it accepts any frame.
    // Preserve that named ResourceExhausted answer, not a channel-closed error.
    if let Err(error) = &result
        && error.code() == tonic::Code::ResourceExhausted
    {
        return Err(error.clone());
    }
    if let Some(error) = receive_error {
        return Err(error);
    }
    let custody = result?;
    let token = custody
        .pending
        .as_ref()
        .expect("writer returned active custody")
        .token()
        .to_owned();
    // Disarm unlink BEFORE entering a possibly committing transaction. A lost
    // response or cancelled commit future leaves this claim for durable retry or
    // orphan maintenance, which can establish the database outcome safely.
    // Even an ordinary register error retains the token: cleanup needs proven
    // durable absence, not a client-side error classification.
    register_retaining_custody(custody, async {
        registration_boundary_delay().await;
        claim.register(d, &token).await.map_err(store_status)
    })
    .await?;
    Ok(accepted(wire.session_epoch))
}
// A debug-binary-only integration seam delays the real registration boundary.
// Release builds cannot accept this environment override. One upload per process
// consumes it, allowing a shipped-agent fixture to observe lease renewals and
// successful receipt after the old receive-only client deadline has elapsed.
async fn registration_boundary_delay() {
    #[cfg(debug_assertions)]
    {
        static USED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        let delay = std::env::var("MCLOVING_TEST_ARTIFACT_REGISTER_DELAY_MILLISECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v <= 60_000)
            .unwrap_or(0);
        if delay > 0 && !USED.swap(true, std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
}
async fn control(
    service: &ControllerAgentService,
    identity: &AgentIdentity,
    c: ArtifactSetControl,
    commit: bool,
) -> Result<Response<WorkReceipt>, Status> {
    let wire = c
        .authority
        .ok_or_else(|| Status::invalid_argument("artifact authority required"))?;
    let a = authority(service, identity, &wire).await?;
    let id = set_id(&c.set_id)?;
    if commit {
        let members = service
            .store
            .artifact_set_members(&a, id)
            .await
            .map_err(store_status)?;
        if members.iter().map(|m| m.bytes).sum::<u64>() != c.bytes {
            return Err(Status::invalid_argument("artifact set byte count differs"));
        }
        // CAS publication is private until the complete metadata transaction.
        // The tokens remain durable if commit is interrupted halfway through.
        for member in members {
            let pending = pending_member(member)?;
            let store = service.object_store.clone();
            tokio::task::spawn_blocking(move || {
                let pending = store.claim_pending(&pending)?;
                store.verify_pending(&pending)?;
                store.commit_pending(pending)
            })
            .await
            .map_err(|e| Status::internal(format!("artifact commit worker: {e}")))?
            .map_err(object_store_status)?;
        }
        service
            .store
            .commit_artifact_set(&a, id)
            .await
            .map_err(store_status)?;
    } else {
        let members = service
            .store
            .abort_artifact_set(&a, id)
            .await
            .map_err(store_status)?;
        let store = service.object_store.clone();
        // The durable abort hides metadata and releases quota first. Cleanup
        // removes only claim files, never shared immutable content.
        tokio::task::spawn_blocking(
            move || -> Result<(), mcloving_object_store::ObjectStoreError> {
                for m in members {
                    if let (Some(d), Some(t)) = (m.digest, m.pending_token) {
                        let p = PendingObject::from_parts(
                            t,
                            ObjectRef {
                                sha256: d,
                                bytes: m.bytes,
                            },
                        )?;
                        store.abort_existing_pending(&p)?;
                    }
                }
                Ok(())
            },
        )
        .await
        .map_err(|e| Status::internal(format!("artifact abort worker: {e}")))?
        .map_err(object_store_status)?;
    }
    Ok(accepted(wire.session_epoch))
}
fn pending_member(m: ArtifactSetMember) -> Result<PendingObject, Status> {
    PendingObject::from_parts(
        m.pending_token
            .ok_or_else(|| Status::failed_precondition("artifact set incomplete"))?,
        ObjectRef {
            sha256: m
                .digest
                .ok_or_else(|| Status::failed_precondition("artifact set incomplete"))?,
            bytes: m.bytes,
        },
    )
    .map_err(object_store_status)
}
pub(super) async fn upload(
    service: &ControllerAgentService,
    request: Request<tonic::Streaming<ArtifactUploadFrame>>,
) -> Result<Response<WorkReceipt>, Status> {
    let started = tokio::time::Instant::now();
    let identity = service.identities.authenticate(&request)?.clone();
    let mut frames = request.into_inner();
    let first = tokio::time::timeout(
        Duration::from_secs(ARTIFACT_UPLOAD_BASE_SECONDS),
        frames.message(),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("artifact header budget spent"))??
    .and_then(|f| f.frame)
    .ok_or_else(|| Status::invalid_argument("artifact operation required"))?;
    let bytes = match &first {
        ArtifactFrame::Header(h) => h.bytes,
        ArtifactFrame::BeginSet(b) => b
            .members
            .iter()
            .try_fold(0_u64, |s, m| s.checked_add(m.bytes))
            .ok_or_else(|| Status::resource_exhausted("artifact_refused:object_quota"))?,
        ArtifactFrame::CommitSet(c) | ArtifactFrame::AbortSet(c) => c.bytes,
        _ => {
            return Err(Status::invalid_argument(
                "artifact first frame must name operation",
            ));
        }
    };
    if bytes > MAX_ATTEMPT_ARTIFACT_BYTES {
        return Err(Status::resource_exhausted("artifact_refused:object_quota"));
    }
    let deadline = started + Duration::from_secs(artifact_server_seconds(bytes));
    tokio::time::timeout_at(deadline, async {
        match first {
            ArtifactFrame::BeginSet(begin) => {
                no_tail(&mut frames).await?;
                let wire = begin
                    .authority
                    .ok_or_else(|| Status::invalid_argument("artifact authority required"))?;
                let a = authority(service, &identity, &wire).await?;
                let members = begin
                    .members
                    .into_iter()
                    .map(|m| ArtifactManifestMember {
                        name: m.name,
                        bytes: m.bytes,
                        media_type: m.media_type,
                    })
                    .collect::<Vec<_>>();
                service
                    .store
                    .begin_artifact_set(&a, set_id(&begin.set_id)?, &members)
                    .await
                    .map_err(store_status)?;
                Ok(accepted(wire.session_epoch))
            }
            ArtifactFrame::Header(header) => {
                stage(
                    service,
                    &identity,
                    header,
                    &mut frames,
                    tokio::time::Instant::now()
                        + Duration::from_secs(artifact_upload_seconds(bytes)),
                )
                .await
            }
            ArtifactFrame::CommitSet(c) => {
                no_tail(&mut frames).await?;
                control(service, &identity, c, true).await
            }
            ArtifactFrame::AbortSet(c) => {
                no_tail(&mut frames).await?;
                control(service, &identity, c, false).await
            }
            _ => Err(Status::invalid_argument("artifact operation required")),
        }
    })
    .await
    .map_err(|_| {
        Status::deadline_exceeded("artifact receive/finish/register/availability deadline spent")
    })?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_capability_is_not_persisted_without_atomic_negotiation() {
        let offered = vec![
            "linux".into(),
            "attempt-credentials-v1".into(),
            ARTIFACT_UPLOAD_CAPABILITY.into(),
        ];
        assert_eq!(
            admitted_capabilities(offered.clone(), false),
            vec!["linux".to_string(), "attempt-credentials-v1".to_string()]
        );
        assert_eq!(admitted_capabilities(offered.clone(), true), offered);
    }
    #[tokio::test]
    async fn actual_pending_custody_survives_registration_future_result_loss() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            tmp.path(),
            Quota {
                max_object_bytes: 3,
                max_total_bytes: 3,
                max_staged_objects: 4,
            },
        )
        .unwrap();
        let staged = store
            .stage_artifact("tenant", b"abc")
            .unwrap()
            .persist()
            .unwrap();
        let pending = store.claim_pending(&staged).unwrap();
        let expected = pending.token().to_owned();
        let custody = PendingCustody {
            store: store.clone(),
            pending: Some(pending.clone()),
        };
        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let registration = tokio::spawn(register_retaining_custody(custody, async move {
            entered_tx.send(()).unwrap();
            std::future::pending::<Result<(), Status>>().await
        }));
        entered.await.unwrap();
        registration.abort();
        assert!(registration.await.unwrap_err().is_cancelled());
        // This uses the real production helper and real claim files. Giving the
        // blocking cleanup pool time to run catches an accidentally armed Drop.
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let reopened = FilesystemObjectStore::open(
                tmp.path(),
                Quota {
                    max_object_bytes: 3,
                    max_total_bytes: 3,
                    max_staged_objects: 4,
                },
            )
            .unwrap();
            let recovered = reopened
                .claim_pending(&pending)
                .expect("uncertain registration result unlinked retained pending token");
            assert_eq!(recovered.token(), expected);
            assert_eq!(reopened.verify_pending(&recovered).unwrap().bytes, 3);
            assert!(reopened.begin_artifact("second-copy", 3).is_err());
        }
        // Only established maintenance disposition, not loss of an RPC future,
        // is allowed to remove an unregistered claim.
        store.abort_existing_pending(&pending).unwrap();
    }
    #[tokio::test(flavor = "current_thread")]
    async fn actual_writer_and_finish_leave_runtime_progress_available() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            tmp.path(),
            Quota {
                max_object_bytes: 8,
                max_total_bytes: 8,
                max_staged_objects: 4,
            },
        )
        .unwrap();
        let verify = store.clone();
        let (tx, rx) = mpsc::channel(4);
        let (phases, mut observed) = mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        let runtime_thread = std::thread::current().id();
        let expected: [u8; 32] = Sha256::digest(b"abc").into();
        let actor = spawn_writer(store, "tenant".into(), 3, expected, rx, move |phase| {
            assert_ne!(
                std::thread::current().id(),
                runtime_thread,
                "actual write/finish moved back onto the runtime worker"
            );
            phases.send(phase).unwrap();
            wait.recv().unwrap();
        });
        tx.send(WriterCommand::Data(b"abc".to_vec())).await.unwrap();
        tx.send(WriterCommand::Finish).await.unwrap();
        drop(tx);
        for phase in [WriterPhase::Write, WriterPhase::Finish] {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), observed.recv())
                    .await
                    .unwrap(),
                Some(phase)
            );
            // The actor is still held at an actual I/O boundary; this current-
            // thread timer cannot progress if that boundary runs inline.
            tokio::time::timeout(
                Duration::from_millis(100),
                tokio::time::sleep(Duration::from_millis(10)),
            )
            .await
            .unwrap();
            release.send(()).unwrap();
        }
        let pending = actor.await.unwrap().unwrap();
        let object = pending.pending.as_ref().unwrap();
        assert_eq!(verify.verify_pending(object).unwrap().sha256, expected);
        drop(pending);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn actual_zero_byte_finish_runs_off_runtime_thread() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            tmp.path(),
            Quota {
                max_object_bytes: 8,
                max_total_bytes: 8,
                max_staged_objects: 4,
            },
        )
        .unwrap();
        let (tx, rx) = mpsc::channel(4);
        let runtime_thread = std::thread::current().id();
        let expected: [u8; 32] = Sha256::digest([]).into();
        let actor = spawn_writer(store, "tenant".into(), 0, expected, rx, move |phase| {
            assert_eq!(
                phase,
                WriterPhase::Finish,
                "zero-byte control must reach actual Finish with no Write"
            );
            assert_ne!(
                std::thread::current().id(),
                runtime_thread,
                "actual finish moved back onto the runtime worker"
            );
        });
        tx.send(WriterCommand::Finish).await.unwrap();
        drop(tx);
        let pending = tokio::time::timeout(Duration::from_secs(2), actor)
            .await
            .expect("actual Finish join bound")
            .unwrap()
            .unwrap();
        assert_eq!(pending.pending.as_ref().unwrap().object_ref().bytes, 0);
    }
    #[tokio::test]
    async fn physical_object_and_total_quota_answers_stay_resource_exhausted() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FilesystemObjectStore::open(
            tmp.path(),
            Quota {
                max_object_bytes: 8,
                max_total_bytes: 8,
                max_staged_objects: 4,
            },
        )
        .unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let result = spawn_writer(store.clone(), "tenant".into(), 9, [0; 32], rx, |_| {})
            .await
            .unwrap();
        assert!(
            matches!(result,Err(ref e) if e.code()==tonic::Code::ResourceExhausted && e.message().contains("artifact_refused:object_quota")),
            "physical object quota must map to ResourceExhausted"
        );
        let mut reserved = store.begin_artifact("other", 8).unwrap();
        reserved.write(b"12345678").unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let result = spawn_writer(store, "tenant".into(), 1, [0; 32], rx, |_| {})
            .await
            .unwrap();
        assert!(matches!(result,Err(ref e) if e.code()==tonic::Code::ResourceExhausted));
        drop(reserved);
    }
}
