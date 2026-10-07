//! One owned artifact reader across digest and stream. A bounded await never
//! means a running kernel read was aborted: the worker retains FD/permit/workspace
//! custody, and unproven quiescence parks the attempt instead of reclaiming it.
use super::*;
use mcloving_agent_protocol::wire::artifact_upload_frame::Frame;
use mcloving_agent_protocol::wire::{
    ArtifactObjectEnd, ArtifactSetBegin, ArtifactSetControl, ArtifactUploadFrame,
    ArtifactUploadHeader,
};
use mcloving_domain::artifacts::*;
use std::collections::BTreeSet;
use std::io::{Read, Seek};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

static ACTIVE_READER: AtomicBool = AtomicBool::new(false);
static CUSTODY: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();
fn custody() -> &'static Mutex<BTreeSet<PathBuf>> {
    CUSTODY.get_or_init(|| Mutex::new(BTreeSet::new()))
}
pub(super) fn workspace_busy(workspace: &Path) -> bool {
    custody().lock().map_or(true, |c| c.contains(workspace))
}
struct IoCustody {
    workspace: PathBuf,
}
impl IoCustody {
    fn acquire(workspace: &Path) -> Result<Self, AgentError> {
        ACTIVE_READER
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| AgentError::UnresolvedReconciliation)?;
        let mut owned = custody()
            .lock()
            .map_err(|_| AgentError::UnresolvedReconciliation)?;
        owned.insert(workspace.to_owned());
        Ok(Self {
            workspace: workspace.to_owned(),
        })
    }
}
impl Drop for IoCustody {
    fn drop(&mut self) {
        if let Ok(mut c) = custody().lock() {
            c.remove(&self.workspace);
        }
        ACTIVE_READER.store(false, Ordering::Release);
    }
}
#[derive(Debug)]
enum ReadOutcome {
    Complete,
    Closed,
    Refused(String),
    Cancelled,
}
#[derive(Clone)]
struct ReadControl {
    cancellation: CancellationToken,
    authority_lost: CancellationToken,
    stop: CancellationToken,
}
impl ReadControl {
    fn cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
            || self.authority_lost.is_cancelled()
            || self.stop.is_cancelled()
    }
}
fn digest_reader(
    source: &mut (impl Read + Seek),
    bytes: u64,
    control: &ReadControl,
) -> Result<[u8; 32], String> {
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| format!("unreadable:{e}"))?;
    let mut digest = Sha256::new();
    let mut remaining = bytes;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        if control.cancelled() {
            return Err("cancelled".into());
        }
        let want = remaining.min(buffer.len() as u64) as usize;
        let n = source
            .read(&mut buffer[..want])
            .map_err(|e| format!("unreadable:{e}"))?;
        if control.cancelled() {
            return Err("cancelled".into());
        }
        if n == 0 {
            return Err("changed_length".into());
        }
        remaining -= n as u64;
        digest.update(&buffer[..n]);
    }
    if control.cancelled() {
        return Err("cancelled".into());
    }
    let mut probe = [0];
    if source
        .read(&mut probe)
        .map_err(|e| format!("unreadable:{e}"))?
        != 0
    {
        return Err("changed_length".into());
    }
    if control.cancelled() {
        return Err("cancelled".into());
    }
    source
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|e| format!("unreadable:{e}"))?;
    Ok(digest.finalize().into())
}
fn stream_reader(
    source: &mut impl Read,
    bytes: u64,
    control: &ReadControl,
    mut send: impl FnMut(Frame) -> bool,
) -> Result<ReadOutcome, std::io::Error> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; MAX_ARTIFACT_FRAME_BYTES];
    while remaining > 0 {
        if control.cancelled() {
            return Ok(ReadOutcome::Cancelled);
        }
        let want = remaining.min(buffer.len() as u64) as usize;
        let n = source.read(&mut buffer[..want])?;
        if control.cancelled() {
            return Ok(ReadOutcome::Cancelled);
        }
        if n == 0 {
            return Ok(ReadOutcome::Refused("changed_length".into()));
        }
        remaining -= n as u64;
        if !send(Frame::Data(buffer[..n].to_vec())) {
            return Ok(ReadOutcome::Closed);
        }
    }
    // Unconditional, including header-only/zero-byte streams. ObjectEnd is a
    // positive acknowledgement of this probe; EOF by itself never stages bytes.
    if control.cancelled() {
        return Ok(ReadOutcome::Cancelled);
    }
    let mut probe = [0];
    if source.read(&mut probe)? != 0 {
        return Ok(ReadOutcome::Refused("changed_length".into()));
    }
    if control.cancelled() {
        return Ok(ReadOutcome::Cancelled);
    }
    if !send(Frame::ObjectEnd(ArtifactObjectEnd {})) {
        return Ok(ReadOutcome::Closed);
    }
    Ok(ReadOutcome::Complete)
}
fn parked(a: &ValidatedAssignment) -> AgentError {
    AgentError::ExecutionReconciliationRequired {
        organization: a.authority.organization_id.clone(),
        attempt: a.authority.attempt_id.clone(),
        cause: "artifact_reader_unquiescent".into(),
    }
}
async fn reader_join(
    reader: &mut tokio::task::JoinHandle<ReadOutcome>,
    duration: Duration,
) -> Result<ReadOutcome, Option<String>> {
    match tokio::time::timeout(duration, reader).await {
        Ok(Ok(outcome)) => Ok(outcome),
        Ok(Err(error)) => Err(Some(error.to_string())),
        Err(_) => Err(None),
    }
}
async fn bounded_join(
    reader: &mut tokio::task::JoinHandle<ReadOutcome>,
    a: &ValidatedAssignment,
) -> Result<ReadOutcome, AgentError> {
    reader_join(reader, Duration::from_secs(ARTIFACT_READER_JOIN_SECONDS))
        .await
        .map_err(|error| match error {
            None => parked(a),
            Some(error) => AgentError::InvalidAssignment(format!("artifact reader failed:{error}")),
        })
}
pub(super) fn ensure_reclaimable(
    workspace: &Path,
    organization: &str,
    attempt: &str,
) -> Result<(), AgentError> {
    if workspace_busy(workspace) {
        return Err(AgentError::ExecutionReconciliationRequired {
            organization: organization.into(),
            attempt: attempt.into(),
            cause: "artifact_reader_unquiescent".into(),
        });
    }
    Ok(())
}
pub(super) fn park_journal(
    journal: &mut Journal,
    organization: &str,
    attempt: &str,
    fence: u64,
    epoch: u64,
    process: u32,
) -> Result<(), mcloving_agent_runtime::JournalError> {
    journal.transition(
        organization,
        attempt,
        fence,
        epoch,
        AttemptPhase::ReconciliationRequired,
        Some(process),
    )
}
fn named(path: &str, cause: &str) -> String {
    format!("artifact_refused:{cause}:{path}")
}
async fn operation(
    client: &mut AgentControlClient<Channel>,
    frame: Frame,
    bytes: u64,
    control: AuthorityRpcControl<'_>,
    cancellation: Option<&CancellationToken>,
) -> Result<bool, AgentError> {
    let stream = tokio_stream::iter([ArtifactUploadFrame { frame: Some(frame) }]);
    let cancelled = async {
        match cancellation {
            Some(c) => c.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };
    let reply = tokio::select! {biased;
        ()=control.authority_lost.cancelled()=>return Err(AgentError::StaleAuthority),
        ()=control.stop.cancelled()=>return Err(AgentError::Stopped),
        ()=cancelled=>return Ok(false),
        reply=tokio::time::timeout(Duration::from_secs(artifact_client_seconds(bytes)),client.upload_artifact(stream))=>reply.map_err(|_|AgentError::AuthorityRpcTimeout)??.into_inner(),
    };
    if !reply.accepted {
        return Err(AgentError::StaleAuthority);
    }
    Ok(true)
}
fn refusal_status(path: &str, status: &tonic::Status) -> Option<String> {
    if status.code() == tonic::Code::ResourceExhausted {
        Some(named(path, "object_quota"))
    } else if status.code() == tonic::Code::InvalidArgument
        && status.message().contains(ARTIFACT_DIGEST_MISMATCH)
    {
        Some(named(path, "changed_content"))
    } else {
        None
    }
}
#[allow(clippy::too_many_arguments)]
async fn upload_file(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    a: &ValidatedAssignment,
    control: AuthorityRpcControl<'_>,
    cancellation: &CancellationToken,
    id: [u8; 32],
    file: crate::artifacts::CollectedFile,
) -> Result<Option<String>, AgentError> {
    let owner = IoCustody::acquire(&a.workspace)?;
    let path = file.relative_path.clone();
    let bytes = file.bytes;
    let root = config.workspace_root.clone();
    let workspace = a.workspace.clone();
    let authority = a.authority.clone();
    let local_stop = CancellationToken::new();
    let read_control = ReadControl {
        cancellation: cancellation.clone(),
        authority_lost: control.authority_lost.clone(),
        stop: local_stop.clone(),
    };
    let (ready_tx, ready) = tokio::sync::oneshot::channel::<Result<(), String>>();
    let (frames, receiver) = tokio::sync::mpsc::channel(4);
    let mut reader = tokio::task::spawn_blocking(move || {
        let _owner = owner;
        let mut source = match crate::artifacts::reopen(&root, &workspace, &file) {
            Ok(f) => f,
            Err(e) => {
                let reason = match e {
                    crate::artifacts::CollectionError::Refused(r) => r.to_string(),
                    crate::artifacts::CollectionError::Io(e) => {
                        named(&file.relative_path, &format!("unreadable:{e}"))
                    }
                };
                let _ = ready_tx.send(Err(reason.clone()));
                return ReadOutcome::Refused(reason);
            }
        };
        let digest = match digest_reader(&mut source, bytes, &read_control) {
            Ok(d) => d,
            Err(cause) => {
                let reason = if cause == "cancelled" {
                    "artifact_collection_cancelled".into()
                } else {
                    named(&file.relative_path, &cause)
                };
                let _ = ready_tx.send(Err(reason.clone()));
                return ReadOutcome::Refused(reason);
            }
        };
        if ready_tx.send(Ok(())).is_err() {
            return ReadOutcome::Closed;
        }
        let header = Frame::Header(ArtifactUploadHeader {
            authority: Some(authority),
            name: file.name,
            media_type: ARTIFACT_MEDIA_TYPE.into(),
            bytes,
            sha256: digest.to_vec(),
            set_id: id.to_vec(),
        });
        if frames
            .blocking_send(ArtifactUploadFrame {
                frame: Some(header),
            })
            .is_err()
        {
            return ReadOutcome::Closed;
        }
        match stream_reader(&mut source, bytes, &read_control, |frame| {
            frames
                .blocking_send(ArtifactUploadFrame { frame: Some(frame) })
                .is_ok()
        }) {
            Ok(ReadOutcome::Refused(cause)) => {
                ReadOutcome::Refused(named(&file.relative_path, &cause))
            }
            Ok(outcome) => outcome,
            Err(e) => ReadOutcome::Refused(named(&file.relative_path, &format!("unreadable:{e}"))),
        }
    });
    let preparation = tokio::select! {biased;
        ()=control.authority_lost.cancelled()=>Err(AgentError::StaleAuthority),
        ()=control.stop.cancelled()=>Err(AgentError::Stopped),
        ()=cancellation.cancelled()=>Ok(Some("artifact_collection_cancelled".into())),
        result=tokio::time::timeout(Duration::from_secs(artifact_client_seconds(bytes)),ready)=>match result {
            Ok(Ok(Ok(())))=>Ok(None),Ok(Ok(Err(reason)))=>Ok(Some(reason)),Ok(Err(_))=>Err(AgentError::InvalidAssignment("artifact digest worker closed".into())),Err(_)=>Ok(Some(named(&path,"read_timeout"))),
        },
    };
    if !matches!(&preparation, Ok(None)) {
        local_stop.cancel();
        drop(receiver);
        bounded_join(&mut reader, a).await?;
        return preparation;
    }
    let stream = tokio_stream::wrappers::ReceiverStream::new(receiver);
    let receipt = tokio::select! {biased;
        ()=control.authority_lost.cancelled()=>Err(AgentError::StaleAuthority),
        ()=control.stop.cancelled()=>Err(AgentError::Stopped),
        ()=cancellation.cancelled()=>Ok(None),
        result=tokio::time::timeout(Duration::from_secs(artifact_client_seconds(bytes)),client.upload_artifact(stream))=>result.map_err(|_|AgentError::AuthorityRpcTimeout).and_then(|r|r.map(|r|Some(r.into_inner())).map_err(AgentError::from)),
    };
    local_stop.cancel();
    let read = bounded_join(&mut reader, a).await?;
    if let ReadOutcome::Refused(reason) = read {
        return Ok(Some(reason));
    }
    match receipt {
        Ok(Some(receipt)) if receipt.accepted => Ok(None),
        Ok(Some(_)) => Err(AgentError::StaleAuthority),
        Ok(None) => Ok(Some("artifact_collection_cancelled".into())),
        Err(AgentError::Rpc(s)) => match refusal_status(&path, &s) {
            Some(reason) => Ok(Some(reason)),
            None => Err(AgentError::Rpc(s)),
        },
        Err(e) => Err(e),
    }
}
pub(super) async fn collect_and_upload_artifacts(
    config: &AgentConfig,
    client: &mut AgentControlClient<Channel>,
    a: &ValidatedAssignment,
    features: &SessionFeatures,
    control: AuthorityRpcControl<'_>,
    cancellation: &CancellationToken,
) -> Result<Option<String>, AgentError> {
    if !features.artifact_upload {
        return Ok(Some("artifact_set_v2_unsupported".into()));
    }
    if ACTIVE_READER.load(Ordering::Acquire) {
        return Err(parked(a));
    }
    let files = match tokio::task::block_in_place(|| {
        crate::artifacts::collect_cancellable(
            &config.workspace_root,
            &a.workspace,
            &a.artifacts,
            cancellation,
        )
    }) {
        Ok(files) => files,
        Err(crate::artifacts::CollectionError::Refused(r)) => {
            return Ok(Some(bounded_refusal_detail(r.to_string())));
        }
        Err(crate::artifacts::CollectionError::Io(e)) => return Err(e.into()),
    };
    let manifest = files
        .iter()
        .map(|f| ArtifactManifestMember {
            name: f.name.clone(),
            bytes: f.bytes,
            media_type: ARTIFACT_MEDIA_TYPE.into(),
        })
        .collect::<Vec<_>>();
    let total =
        validate_manifest(&manifest).map_err(|e| AgentError::InvalidAssignment(e.to_string()))?;
    let id = artifact_manifest_digest(&manifest);
    let begin = Frame::BeginSet(ArtifactSetBegin {
        authority: Some(a.authority.clone()),
        set_id: id.to_vec(),
        members: manifest
            .iter()
            .map(|m| mcloving_agent_protocol::wire::ArtifactManifestMember {
                name: m.name.clone(),
                bytes: m.bytes,
                media_type: m.media_type.clone(),
            })
            .collect(),
    });
    match operation(client, begin, total, control, Some(cancellation)).await {
        Ok(true) => {}
        Ok(false) => {
            let abort = Frame::AbortSet(ArtifactSetControl {
                authority: Some(a.authority.clone()),
                set_id: id.to_vec(),
                bytes: total,
            });
            let _ = operation(client, abort, total, control, None).await;
            return Ok(Some("artifact_collection_cancelled".into()));
        }
        Err(AgentError::Rpc(s)) if s.code() == tonic::Code::ResourceExhausted => {
            return Ok(Some("artifact_refused:object_quota:<set>".into()));
        }
        Err(e) => return Err(e),
    }
    let staged = async {
        for file in files {
            if cancellation.is_cancelled() {
                return Ok(Some("artifact_collection_cancelled".into()));
            }
            if let Some(reason) =
                upload_file(config, client, a, control, cancellation, id, file).await?
            {
                return Ok(Some(bounded_refusal_detail(reason)));
            }
        }
        Ok::<Option<String>, AgentError>(None)
    }
    .await;
    if matches!(
        &staged,
        Err(AgentError::ExecutionReconciliationRequired { .. })
    ) {
        // Do not extend the bounded reader join while cleanup waits for the
        // server member lock. A separately owned, bounded abort still revokes
        // hidden batch metadata; stale authority falls back to durable reaping.
        let mut cleanup_client = client.clone();
        let wire = a.authority.clone();
        let lost = control.authority_lost.clone();
        let stop = control.stop.clone();
        let lease_window = control.lease_window;
        tokio::spawn(async move {
            let abort = Frame::AbortSet(ArtifactSetControl {
                authority: Some(wire),
                set_id: id.to_vec(),
                bytes: total,
            });
            let _ = operation(
                &mut cleanup_client,
                abort,
                total,
                AuthorityRpcControl {
                    authority_lost: &lost,
                    stop: &stop,
                    lease_window,
                },
                None,
            )
            .await;
        });
        return staged;
    }
    if !matches!(&staged, Ok(None)) {
        let abort = Frame::AbortSet(ArtifactSetControl {
            authority: Some(a.authority.clone()),
            set_id: id.to_vec(),
            bytes: total,
        });
        // Execution cancellation is deliberately excluded from cleanup; fencing
        // still applies. Loss of authority leaves durable hidden custody for reaping.
        let cleanup = operation(client, abort, total, control, None).await;
        if let Err(e) = cleanup
            && staged.is_ok()
        {
            return Err(e);
        }
        return staged;
    }
    let commit = Frame::CommitSet(ArtifactSetControl {
        authority: Some(a.authority.clone()),
        set_id: id.to_vec(),
        bytes: total,
    });
    match operation(client, commit, total, control, Some(cancellation)).await {
        Ok(true) => Ok(None),
        other => {
            let abort = Frame::AbortSet(ArtifactSetControl {
                authority: Some(a.authority.clone()),
                set_id: id.to_vec(),
                bytes: total,
            });
            let _ = operation(client, abort, total, control, None).await;
            match other {
                Ok(false) => Ok(Some("artifact_collection_cancelled".into())),
                Err(AgentError::Rpc(s)) if s.code() == tonic::Code::ResourceExhausted => {
                    Ok(Some("artifact_refused:object_quota:<set>".into()))
                }
                Err(e) => Err(e),
                Ok(true) => Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn control() -> ReadControl {
        ReadControl {
            cancellation: CancellationToken::new(),
            authority_lost: CancellationToken::new(),
            stop: CancellationToken::new(),
        }
    }
    #[test]
    fn zero_byte_appended_after_collection_is_refused_by_original_path() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = Path::new("org/attempt/1");
        let root = tmp.path().join(workspace);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("empty"), []).unwrap();
        let specs = [mcloving_domain::artifacts::ArtifactSpec {
            name: "outputs".into(),
            paths: vec!["**".into()],
        }];
        let file = crate::artifacts::collect(tmp.path(), workspace, &specs)
            .unwrap()
            .remove(0);
        assert_eq!(file.bytes, 0);
        std::fs::write(root.join("empty"), b"detached append").unwrap();
        let error = crate::artifacts::reopen(tmp.path(), workspace, &file)
            .expect_err("zero-byte collection append escaped changed_length refusal");
        let crate::artifacts::CollectionError::Refused(refusal) = error else {
            panic!("zero-byte collection append must yield a named refusal")
        };
        assert_eq!(refusal.to_string(), "artifact_refused:changed_length:empty");
    }
    #[test]
    fn zero_byte_append_after_digest_refuses_before_object_end() {
        use std::io::Write;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("empty");
        std::fs::write(&path, []).unwrap();
        let mut source = std::fs::File::open(&path).unwrap();
        let c = control();
        let expected: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(digest_reader(&mut source, 0, &c).unwrap(), expected);
        // This is the exact boundary after digest/header and before stream close.
        let mut writer = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writer.write_all(b"detached append").unwrap();
        let mut frames = Vec::new();
        let outcome = stream_reader(&mut source, 0, &c, |f| {
            frames.push(f);
            true
        })
        .unwrap();
        assert!(
            matches!(outcome,ReadOutcome::Refused(ref s) if s=="changed_length"),
            "zero byte stream accepted growth instead of changed_length"
        );
        assert!(!frames.iter().any(|f| matches!(f, Frame::ObjectEnd(_))));
        assert_eq!(
            named("empty", "changed_length"),
            "artifact_refused:changed_length:empty"
        );
    }
    struct CancelReader {
        cursor: std::io::Cursor<Vec<u8>>,
        token: CancellationToken,
        reads: usize,
    }
    impl Read for CancelReader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            let n = std::io::Read::read(&mut self.cursor, b)?;
            self.token.cancel();
            Ok(n)
        }
    }
    impl Seek for CancelReader {
        fn seek(&mut self, p: std::io::SeekFrom) -> std::io::Result<u64> {
            self.cursor.seek(p)
        }
    }
    #[test]
    fn digest_observes_execution_and_authority_between_actual_reads() {
        for authority in [false, true] {
            let c = control();
            let token = if authority {
                c.authority_lost.clone()
            } else {
                c.cancellation.clone()
            };
            let mut source = CancelReader {
                cursor: std::io::Cursor::new(vec![7; 128 * 1024]),
                token,
                reads: 0,
            };
            assert_eq!(
                digest_reader(&mut source, 128 * 1024, &c),
                Err("cancelled".into()),
                "digest consumed beyond execution/authority cancellation"
            );
            assert_eq!(source.reads, 1);
        }
    }
    struct BlockedFile {
        file: std::fs::File,
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl Read for BlockedFile {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
                self.release
                    .recv()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            self.file.read(b)
        }
    }
    struct ReleaseReader(Option<std::sync::mpsc::Sender<()>>);
    impl ReleaseReader {
        fn release(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    impl Drop for ReleaseReader {
        fn drop(&mut self) {
            self.release();
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn stalled_read_keeps_fd_permit_workspace_and_durable_park_until_completion() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = PathBuf::from("org/attempt/1");
        let path = tmp.path().join("source");
        std::fs::write(&path, b"x").unwrap();
        let owner = IoCustody::acquire(&workspace).unwrap();
        let (entered_tx, entered) = tokio::sync::oneshot::channel();
        let (release_tx, release) = std::sync::mpsc::channel();
        let mut release_guard = ReleaseReader(Some(release_tx));
        let mut source = BlockedFile {
            file: std::fs::File::open(path).unwrap(),
            entered: Some(entered_tx),
            release,
        };
        let c = control();
        let mut reader = tokio::task::spawn_blocking(move || {
            let _owner = owner;
            stream_reader(&mut source, 1, &c, |_| true).unwrap()
        });
        entered.await.unwrap();
        let joined = tokio::time::timeout(
            Duration::from_millis(100),
            reader_join(&mut reader, Duration::from_millis(20)),
        )
        .await;
        assert!(
            matches!(joined, Ok(Err(None))),
            "bounded reader join did not return while owned file stalled"
        );
        assert!(workspace_busy(&workspace));
        assert!(IoCustody::acquire(Path::new("different/workspace")).is_err());
        assert!(
            matches!(
                ensure_reclaimable(&workspace, "org", "attempt"),
                Err(AgentError::ExecutionReconciliationRequired { .. })
            ),
            "workspace reclamation succeeded with actual reader custody"
        );
        let journal_path = tmp.path().join("agent.db");
        let acceptance = Acceptance {
            organization_id: "org".into(),
            attempt_id: "attempt".into(),
            fence_token: 1,
            session_epoch: 1,
            payload_digest: [0; 32],
            workspace: workspace.clone(),
        };
        let mut journal = Journal::open(&journal_path).unwrap();
        journal.accept(&acceptance).unwrap();
        journal
            .transition("org", "attempt", 1, 1, AttemptPhase::Running, Some(42))
            .unwrap();
        park_journal(&mut journal, "org", "attempt", 1, 1, 42).unwrap();
        drop(journal);
        let observation = Journal::observe(&journal_path).unwrap();
        assert_eq!(observation.active_attempts, 1);
        let journal = Journal::open(&journal_path).unwrap();
        let persisted = journal.reconcile().unwrap();
        assert_eq!(
            persisted.attempts[0].phase,
            AttemptPhase::ReconciliationRequired
        );
        let row = &persisted.attempts[0];
        assert_eq!(row.organization_id, acceptance.organization_id);
        assert_eq!(row.attempt_id, acceptance.attempt_id);
        assert_eq!(row.fence_token, acceptance.fence_token);
        assert_eq!(row.session_epoch, acceptance.session_epoch);
        assert_eq!(row.workspace, acceptance.workspace);
        assert!(!reader.is_finished());
        release_guard.release();
        assert!(matches!(
            reader_join(&mut reader, Duration::from_secs(2)).await,
            Ok(ReadOutcome::Complete)
        ));
        assert!(!workspace_busy(&workspace));
        ensure_reclaimable(&workspace, "org", "attempt").unwrap();
        // Real quiescence releases the permit; a timeout alone did not.
        drop(IoCustody::acquire(&workspace).unwrap());
    }
    #[test]
    fn changed_length_and_unreadability_never_send_successful_object_end() {
        let c = control();
        for (bytes, contents) in [(4, b"abc".as_slice()), (2, b"abc".as_slice())] {
            let mut source = std::io::Cursor::new(contents);
            let mut complete = false;
            let read = stream_reader(&mut source, bytes, &c, |f| {
                complete |= matches!(f, Frame::ObjectEnd(_));
                true
            })
            .unwrap();
            assert!(matches!(read, ReadOutcome::Refused(_)));
            assert!(!complete);
        }
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    #[test]
    fn object_and_total_resource_quota_are_named_without_consuming_authority_errors() {
        for message in [
            "object exceeds per-object quota",
            "object store exceeds total-byte quota",
        ] {
            assert_eq!(
                refusal_status("out/x", &tonic::Status::resource_exhausted(message)),
                Some("artifact_refused:object_quota:out/x".into())
            );
        }
        assert_eq!(
            refusal_status(
                "out/x",
                &tonic::Status::failed_precondition("stale authority")
            ),
            None
        );
        assert_eq!(
            refusal_status(
                "out/x",
                &tonic::Status::invalid_argument(ARTIFACT_DIGEST_MISMATCH)
            ),
            Some("artifact_refused:changed_content:out/x".into())
        );
    }
}
