//! Transport tests of the production renewal loop against a real tonic peer.
//! A pending response is distinct from connection refusal or an answered denial.

use super::*;
use mcloving_agent_protocol::wire;
use std::sync::Mutex;

#[derive(Clone)]
struct StallingRenewals {
    requests: Arc<Mutex<Vec<tokio::time::Instant>>>,
    recover_after_first: bool,
    healthy_response_delay: Option<Duration>,
    first_response_request_count: Arc<Mutex<Option<usize>>>,
}

#[tonic::async_trait]
impl wire::agent_control_server::AgentControl for StallingRenewals {
    async fn renew_work_lease(
        &self,
        request: tonic::Request<wire::WorkLeaseRenewal>,
    ) -> Result<tonic::Response<wire::WorkLeaseReceipt>, tonic::Status> {
        let ordinal = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(tokio::time::Instant::now());
            requests.len()
        };
        if let Some(delay) = self.healthy_response_delay {
            tokio::time::sleep(delay).await;
            let mut first = self.first_response_request_count.lock().unwrap();
            if first.is_none() {
                *first = Some(self.requests.lock().unwrap().len());
            }
        } else if ordinal == 1 || !self.recover_after_first {
            // Keep a real HTTP/2 request pending. No response/refusal is sent.
            return std::future::pending().await;
        }
        let authority = request.into_inner().authority.unwrap();
        Ok(tonic::Response::new(wire::WorkLeaseReceipt {
            session_epoch: authority.session_epoch,
            accepted: true,
            cancellation_requested: false,
            rejection_cause: String::new(),
        }))
    }
    async fn open_session(
        &self,
        _: tonic::Request<wire::OpenSessionRequest>,
    ) -> Result<tonic::Response<wire::OpenSessionResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn rotate_certificate(
        &self,
        _: tonic::Request<wire::RotateCertificateRequest>,
    ) -> Result<tonic::Response<wire::RotateCertificateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn reconcile(
        &self,
        _: tonic::Request<wire::ReconciliationReport>,
    ) -> Result<tonic::Response<wire::ReconciliationDirective>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn complete_cancellation(
        &self,
        _: tonic::Request<wire::CancellationCompletion>,
    ) -> Result<tonic::Response<wire::CancellationReceipt>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn poll_work(
        &self,
        _: tonic::Request<wire::WorkPoll>,
    ) -> Result<tonic::Response<wire::WorkOffer>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn accept_work(
        &self,
        _: tonic::Request<wire::WorkAuthority>,
    ) -> Result<tonic::Response<wire::WorkReceipt>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn start_work(
        &self,
        _: tonic::Request<wire::WorkAuthority>,
    ) -> Result<tonic::Response<wire::WorkReceipt>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn fetch_credentials(
        &self,
        _: tonic::Request<wire::CredentialRequest>,
    ) -> Result<tonic::Response<wire::CredentialEnvelope>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn publish_log(
        &self,
        _: tonic::Request<wire::WorkLogChunk>,
    ) -> Result<tonic::Response<wire::WorkReceipt>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
    async fn complete_work(
        &self,
        _: tonic::Request<wire::WorkCompletion>,
    ) -> Result<tonic::Response<wire::WorkReceipt>, tonic::Status> {
        Err(tonic::Status::unimplemented("renewal-only test peer"))
    }
}

async fn run_peer(recover_after_first: bool, healthy_response_delay: Option<Duration>) {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_stop = CancellationToken::new();
    let _server_guard = server_stop.clone().drop_guard();
    let first_response_request_count = Arc::new(Mutex::new(None));
    let peer = StallingRenewals {
        requests: requests.clone(),
        recover_after_first,
        healthy_response_delay,
        first_response_request_count: first_response_request_count.clone(),
    };
    let server = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(wire::agent_control_server::AgentControlServer::new(peer))
            .serve_with_shutdown(address, server_stop.cancelled_owned())
            .await
            .unwrap();
    });
    let client = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(client) = AgentControlClient::connect(format!("http://{address}")).await {
                break client;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("tonic renewal peer must become reachable");
    let started = tokio::time::Instant::now();
    let deadline =
        lease_cancellation_deadline(started, Duration::from_secs(5), Duration::from_secs(1));
    let stop = CancellationToken::new();
    let _renewal_guard = stop.clone().drop_guard();
    let execution_cancellation = CancellationToken::new();
    let authority_lost = CancellationToken::new();
    let loss_reason = Arc::new(OnceLock::new());
    let task = tokio::spawn(renew_lease(
        client,
        WorkAuthority {
            agent_id: "stalled-renewal-agent".to_owned(),
            session_epoch: 7,
            organization_id: Uuid::new_v4().to_string(),
            attempt_id: Uuid::new_v4().to_string(),
            fence_token: 11,
        },
        LeaseRenewalControl {
            lease_seconds: 5,
            renewal_interval: if healthy_response_delay.is_some() {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(1)
            },
            lease_started_at: started,
            lease_window: Duration::from_secs(5),
            termination_grace: Duration::from_secs(1),
            execution_cancellation: execution_cancellation.clone(),
            authority_lost: authority_lost.clone(),
            stop: stop.clone(),
            loss_reason: loss_reason.clone(),
        },
    ));
    if healthy_response_delay.is_some() {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(count) = *first_response_request_count.lock().unwrap() {
                    assert_eq!(count, 1, "a healthy response must arrive before any retry");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the healthy delayed response must not be repeatedly cancelled");
        tokio::time::sleep_until(deadline + Duration::from_millis(100)).await;
        assert!(!execution_cancellation.is_cancelled());
        assert!(!authority_lost.is_cancelled());
        assert!(loss_reason.get().is_none());
        stop.cancel();
        assert!(task.await.unwrap().is_ok());
    } else if recover_after_first {
        // First request starts at about one second. Its bounded ask expires at
        // two seconds; a second full sleep would miss the original three-second
        // cancellation deadline just as surely as one unbounded hanging RPC.
        tokio::time::timeout_at(deadline - Duration::from_millis(100), async {
            loop {
                if requests.lock().unwrap().len() >= 2 {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("another RPC must observe recovery before the original held term expires");
        tokio::time::sleep_until(deadline + Duration::from_millis(100)).await;
        assert!(!execution_cancellation.is_cancelled());
        assert!(!authority_lost.is_cancelled());
        assert!(loss_reason.get().is_none());
        stop.cancel();
        assert!(task.await.unwrap().is_ok());
    } else {
        let result = tokio::time::timeout_at(deadline + Duration::from_secs(1), task)
            .await
            .expect("retries must not extend the original held term")
            .unwrap();
        assert!(matches!(result, Err(AgentError::LeaseRenewalTimeout)));
        assert!(execution_cancellation.is_cancelled());
        assert!(authority_lost.is_cancelled());
        assert_eq!(loss_reason.get(), Some(&"renewal_unanswered_until_expiry"));
        let sent = requests.lock().unwrap();
        assert!(
            sent.len() >= 2,
            "individual pending requests must be retried"
        );
        assert!(sent.iter().all(|at| *at < deadline));
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn a_stalled_renewal_response_is_retried_and_recovery_keeps_authority() {
    run_peer(true, None).await;
}

#[tokio::test]
async fn repeated_stalled_responses_never_extend_the_held_term() {
    run_peer(false, None).await;
}

#[tokio::test]
async fn healthy_response_slower_than_the_renewal_cadence_is_not_retried() {
    run_peer(true, Some(Duration::from_millis(200))).await;
}
