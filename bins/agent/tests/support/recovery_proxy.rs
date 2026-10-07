//! A fixture-only, authenticated forwarding peer. No production fault switches.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use mcloving_agent_protocol::wire::{
    agent_control_client::AgentControlClient,
    agent_control_server::{AgentControl, AgentControlServer},
    *,
};
use mcloving_agent_runtime::Journal;
use sha2::Digest;
use sqlx::PgPool;
use tokio::sync::Notify;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig},
};
use uuid::Uuid;

#[derive(Default)]
pub(super) struct Faults {
    pub first_started: Notify,
    pub first_send: Notify,
    pub first_committed: Notify,
    pub first_reply: Notify,
    pub retry_committed: Notify,
    pub retry_reply: Notify,
    pub blocked_session: Notify,
    pub session_resume: Notify,
    pub block_sessions: AtomicBool,
    pub cancellations: AtomicUsize,
    pub cancellation_completed: Notify,
    pub chunks: Mutex<Vec<WorkLogChunk>>,
    pub sessions: Mutex<Vec<u64>>,
    pub observations: Mutex<Vec<serde_json::Value>>,
    pub observation_failed: Notify,
    pub failure: Mutex<Option<String>>,
    context: Mutex<Option<ObservationContext>>,
}

#[derive(Clone)]
struct ObservationContext {
    journal: std::path::PathBuf,
    pool: PgPool,
    organization: Uuid,
    build: Uuid,
}

impl Faults {
    pub(super) fn observe_attempt(
        &self,
        journal: std::path::PathBuf,
        pool: PgPool,
        organization: Uuid,
        build: Uuid,
    ) {
        *self.context.lock().unwrap() = Some(ObservationContext {
            journal,
            pool,
            organization,
            build,
        });
    }

    fn fail(&self, message: String) -> Status {
        *self.failure.lock().unwrap() = Some(message.clone());
        self.observation_failed.notify_one();
        Status::failed_precondition(message)
    }

    async fn snapshot(
        &self,
        chunk: &WorkLogChunk,
        index: usize,
        moment: &str,
    ) -> Result<(), Status> {
        let context = self
            .context
            .lock()
            .unwrap()
            .clone()
            .expect("observation context before recovery");
        let authority = chunk
            .authority
            .as_ref()
            .expect("publication has fenced authority");
        // Finish the SQLite read before the await; do not carry a Journal over it.
        let phase = Journal::open(&context.journal)
            .unwrap()
            .reconcile()
            .unwrap()
            .attempts
            .iter()
            .find(|attempt| attempt.attempt_id == authority.attempt_id)
            .map(|attempt| attempt.phase.wire_name().to_owned());
        let ledger =
            super::recovery_ledger_from(&context.pool, context.organization, context.build).await;
        let cancellations = self.cancellations.load(Ordering::SeqCst);
        let snapshot = serde_json::json!({"moment":moment,"publication":index,"sequence":chunk.sequence,
            "step":chunk.step_ordinal,"stream":chunk.stream,"digest":super::hex(&sha2::Sha256::digest(&chunk.content)),
            "attempt":authority.attempt_id,"fence_token":authority.fence_token,"session":authority.session_epoch,
            "active_journal_row":phase.is_some(),"journal_phase":phase,"cancellation_requests":cancellations,"controller":ledger});
        self.observations.lock().unwrap().push(snapshot.clone());
        if snapshot["journal_phase"] != "cancelling"
            || cancellations != 0
            || snapshot["controller"]["terminal_events"] != 0
            || snapshot["controller"]["attempt_status"] != "cancelling"
        {
            return Err(self.fail(format!(
                "every descriptor publication and receipt precedes retirement: {snapshot}"
            )));
        }
        Ok(())
    }

    /// Observe retirement independently of an upload. A broken publisher may
    /// terminalize its journal and fail locally before it can send the next RPC.
    pub(super) async fn watch_local_phase(&self) {
        loop {
            if self.cancellations.load(Ordering::SeqCst) != 0 {
                return;
            }
            let last = self.chunks.lock().unwrap().last().cloned();
            if let Some(chunk) = last {
                let context = self.context.lock().unwrap().clone().unwrap();
                let authority = chunk.authority.as_ref().unwrap();
                let phase = Journal::open(&context.journal)
                    .unwrap()
                    .reconcile()
                    .unwrap()
                    .attempts
                    .iter()
                    .find(|attempt| attempt.attempt_id == authority.attempt_id)
                    .map(|attempt| attempt.phase.wire_name().to_owned());
                let committed = self
                    .observations
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|snapshot| snapshot["moment"] == "committed_receipt")
                    .count();
                if phase.as_deref() != Some("cancelling") && committed < 4 {
                    let ledger = super::recovery_ledger_from(
                        &context.pool,
                        context.organization,
                        context.build,
                    )
                    .await;
                    let _ = self.fail(format!("local journal left cancelling before all descriptor receipts: phase={phase:?} committed_receipts={committed} controller={ledger}"));
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

#[derive(Clone)]
struct Proxy {
    upstream: AgentControlClient<Channel>,
    faults: Arc<Faults>,
}

pub(super) async fn start(
    tls: &super::MtlsFiles,
    upstream_port: u16,
) -> (u16, Arc<Faults>, tokio::task::JoinHandle<()>) {
    let read = |path: &std::path::Path| std::fs::read(path).expect("read fixture TLS");
    let upstream = Channel::from_shared(format!("https://127.0.0.1:{upstream_port}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .domain_name("controller.internal")
                .ca_certificate(Certificate::from_pem(read(&tls.ca_certificate)))
                .identity(Identity::from_pem(
                    read(&tls.agent_certificate),
                    read(&tls.agent_key),
                )),
        )
        .unwrap()
        .connect()
        .await
        .expect("connect authenticated upstream");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let faults = Arc::new(Faults::default());
    let service = Proxy {
        upstream: AgentControlClient::new(upstream),
        faults: faults.clone(),
    };
    let mut server = Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(Identity::from_pem(
                    read(&tls.server_certificate),
                    read(&tls.server_key),
                ))
                .client_ca_root(Certificate::from_pem(read(&tls.ca_certificate))),
        )
        .unwrap();
    let task = tokio::spawn(async move {
        server
            .add_service(AgentControlServer::new(service))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("fixture proxy serves");
    });
    (port, faults, task)
}

#[tonic::async_trait]
impl AgentControl for Proxy {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        if self.faults.block_sessions.load(Ordering::SeqCst) {
            self.faults.blocked_session.notify_one();
            self.faults.session_resume.notified().await;
        }
        // Negotiate the supported terminal-only mode on both sides. This
        // leaves every finished-step descriptor unpublished until recovery;
        // the separate existing test covers negotiated live streaming.
        let mut message = request.into_inner();
        if let Some(offer) = message.protocol.as_mut() {
            offer
                .features
                .retain(|feature| feature != "live-log-stream-v1");
        }
        let response = self.upstream.clone().open_session(message).await?;
        self.faults
            .sessions
            .lock()
            .unwrap()
            .push(response.get_ref().session_epoch);
        Ok(response)
    }

    async fn publish_log(
        &self,
        request: Request<WorkLogChunk>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let chunk = request.into_inner();
        let index = {
            let mut chunks = self.faults.chunks.lock().unwrap();
            chunks.push(chunk.clone());
            chunks.len()
        };
        if index == 1 {
            self.faults.first_started.notify_one();
            self.faults.first_send.notified().await;
        }
        self.faults
            .snapshot(&chunk, index, "before_publication")
            .await?;
        let response = self.upstream.clone().publish_log(chunk.clone()).await?;
        assert!(
            response.get_ref().accepted,
            "every observed recovery upload is accepted by the real controller"
        );
        self.faults
            .snapshot(&chunk, index, "committed_receipt")
            .await?;
        if index == 1 {
            assert!(
                response.get_ref().accepted,
                "fault applies only after a real accepted commit"
            );
            self.faults.first_committed.notify_one();
            self.faults.first_reply.notified().await;
            return Err(Status::unavailable(
                "fixture discarded committed upload response",
            ));
        }
        if index == 2 {
            assert!(
                response.get_ref().accepted,
                "identical recovery retry accepted"
            );
            self.faults.retry_committed.notify_one();
            self.faults.retry_reply.notified().await;
        }
        Ok(response)
    }

    async fn complete_cancellation(
        &self,
        request: Request<CancellationCompletion>,
    ) -> Result<Response<CancellationReceipt>, Status> {
        self.faults.cancellations.fetch_add(1, Ordering::SeqCst);
        let response = self
            .upstream
            .clone()
            .complete_cancellation(request.into_inner())
            .await?;
        self.faults.cancellation_completed.notify_one();
        Ok(response)
    }

    async fn rotate_certificate(
        &self,
        request: Request<RotateCertificateRequest>,
    ) -> Result<Response<RotateCertificateResponse>, Status> {
        self.upstream
            .clone()
            .rotate_certificate(request.into_inner())
            .await
    }

    async fn reconcile(
        &self,
        request: Request<ReconciliationReport>,
    ) -> Result<Response<ReconciliationDirective>, Status> {
        self.upstream.clone().reconcile(request.into_inner()).await
    }

    async fn poll_work(&self, request: Request<WorkPoll>) -> Result<Response<WorkOffer>, Status> {
        self.upstream.clone().poll_work(request.into_inner()).await
    }

    async fn accept_work(
        &self,
        request: Request<WorkAuthority>,
    ) -> Result<Response<WorkReceipt>, Status> {
        self.upstream
            .clone()
            .accept_work(request.into_inner())
            .await
    }

    async fn start_work(
        &self,
        request: Request<WorkAuthority>,
    ) -> Result<Response<WorkReceipt>, Status> {
        self.upstream.clone().start_work(request.into_inner()).await
    }

    async fn fetch_credentials(
        &self,
        request: Request<CredentialRequest>,
    ) -> Result<Response<CredentialEnvelope>, Status> {
        self.upstream
            .clone()
            .fetch_credentials(request.into_inner())
            .await
    }

    async fn renew_work_lease(
        &self,
        request: Request<WorkLeaseRenewal>,
    ) -> Result<Response<WorkLeaseReceipt>, Status> {
        self.upstream
            .clone()
            .renew_work_lease(request.into_inner())
            .await
    }

    async fn complete_work(
        &self,
        request: Request<WorkCompletion>,
    ) -> Result<Response<WorkReceipt>, Status> {
        self.upstream
            .clone()
            .complete_work(request.into_inner())
            .await
    }

    async fn upload_artifact(
        &self,
        _: Request<tonic::Streaming<ArtifactUploadFrame>>,
    ) -> Result<Response<WorkReceipt>, Status> {
        Err(Status::unimplemented(
            "recovery log fixture does not upload artifacts",
        ))
    }
}
