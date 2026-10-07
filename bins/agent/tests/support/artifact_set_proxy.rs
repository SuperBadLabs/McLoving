//! Fixture-only authenticated stream forwarder with a post-registration receipt
//! barrier. The real controller authorizes/stages/registers; no production switch.
use mcloving_agent_protocol::wire::{
    agent_control_client::AgentControlClient,
    agent_control_server::{AgentControl, AgentControlServer},
    *,
};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::Notify;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Channel, ClientTlsConfig, Identity, Server, ServerTlsConfig},
};
#[derive(Default)]
pub(super) struct Barrier {
    pub registered: Notify,
    pub release: Notify,
    pub first: Mutex<Option<ArtifactUploadHeader>>,
    held: AtomicBool,
}
pub(super) struct ServerGuard(pub tokio::task::JoinHandle<()>);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub(super) struct Release(pub Arc<Barrier>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release.notify_one();
    }
}
#[derive(Clone)]
struct Proxy {
    upstream: AgentControlClient<Channel>,
    barrier: Arc<Barrier>,
}
pub(super) async fn start(
    tls: &super::MtlsFiles,
    upstream_port: u16,
) -> (u16, Arc<Barrier>, tokio::task::JoinHandle<()>) {
    let read = |p: &std::path::Path| std::fs::read(p).expect("read fixture TLS");
    let channel = Channel::from_shared(format!("https://127.0.0.1:{upstream_port}"))
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
        .expect("connect authenticated artifact upstream");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let barrier = Arc::new(Barrier::default());
    let service = Proxy {
        upstream: AgentControlClient::new(channel),
        barrier: barrier.clone(),
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
            .expect("artifact fixture proxy serves");
    });
    (port, barrier, task)
}
#[tonic::async_trait]
impl AgentControl for Proxy {
    async fn open_session(
        &self,
        request: Request<OpenSessionRequest>,
    ) -> Result<Response<OpenSessionResponse>, Status> {
        self.upstream
            .clone()
            .open_session(request.into_inner())
            .await
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
    async fn complete_cancellation(
        &self,
        request: Request<CancellationCompletion>,
    ) -> Result<Response<CancellationReceipt>, Status> {
        self.upstream
            .clone()
            .complete_cancellation(request.into_inner())
            .await
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
    async fn publish_log(
        &self,
        request: Request<WorkLogChunk>,
    ) -> Result<Response<WorkReceipt>, Status> {
        self.upstream
            .clone()
            .publish_log(request.into_inner())
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
        request: Request<tonic::Streaming<ArtifactUploadFrame>>,
    ) -> Result<Response<WorkReceipt>, Status> {
        let mut incoming = request.into_inner();
        let first = incoming
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("fixture missing first frame"))?;
        let header = match first.frame.as_ref() {
            Some(artifact_upload_frame::Frame::Header(header)) => Some(header.clone()),
            _ => None,
        };
        let (send, receive) = tokio::sync::mpsc::channel(4);
        let relay = tokio::spawn(async move {
            if send.send(first).await.is_err() {
                return Ok::<(), Status>(());
            }
            while let Some(frame) = incoming.message().await? {
                if send.send(frame).await.is_err() {
                    break;
                }
            }
            Ok(())
        });
        let response = self
            .upstream
            .clone()
            .upload_artifact(tokio_stream::wrappers::ReceiverStream::new(receive))
            .await;
        relay
            .await
            .map_err(|e| Status::internal(format!("fixture relay:{e}")))??;
        let response = response?;
        if let Some(header) = header
            && response.get_ref().accepted
            && !self.barrier.held.swap(true, Ordering::SeqCst)
        {
            *self.barrier.first.lock().unwrap() = Some(header);
            // This notification occurs only AFTER the real accepted stage
            // response: its member and claim token are durably registered.
            self.barrier.registered.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                self.barrier.release.notified(),
            )
            .await
            .map_err(|_| Status::deadline_exceeded("fixture receipt barrier unreleased"))?;
        }
        Ok(response)
    }
}
