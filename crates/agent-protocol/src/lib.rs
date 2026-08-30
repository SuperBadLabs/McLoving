//! Versioned outbound agent protocol, enrollment, and session fencing.
//!
//! The agent is a client only: it builds an HTTPS gRPC endpoint with an
//! explicitly configured controller CA and client identity. Controller-side
//! service stubs are generated for the controller crate, but this crate never
//! opens a listener.

use std::collections::{BTreeSet, HashMap};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
use x509_parser::parse_x509_certificate;

/// Generated Protobuf and gRPC contract.
pub mod wire {
    tonic::include_proto!("mcloving.agent.v1");
}

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
pub const WORK_DELIVERY_FEATURE: &str = "work-delivery-v1";
pub const ATTEMPT_CREDENTIALS_FEATURE: &str = "attempt-credentials-v1";
/// gRPC metadata key on a stale-epoch open-session rejection carrying the
/// controller's currently stored session epoch. A lagging journal (for
/// example after a documented journal replacement) reserves past this floor
/// in one step instead of brute-forcing the epoch space one reconnect at a
/// time. The rejection itself stays fail-closed.
pub const CURRENT_SESSION_EPOCH_METADATA: &str = "mcloving-current-session-epoch";
/// The peer understands `WorkReceipt.published_outcome` and will journal the
/// terminal the controller actually published.
///
/// A committed cancellation can override a non-succeeded terminal at the
/// publishing row lock. An agent without this feature ignores the field and
/// would record the outcome it requested, so the controller must not substitute
/// for such a peer during a rolling upgrade.
pub const WORK_COMPLETION_SUBSTITUTION_FEATURE: &str = "work-completion-substitution-v1";
/// The peer's `AcceptWork` receipt carries `cancellation_requested` read
/// under the accepting transaction's row lock.
///
/// An agent that negotiated this skips the serialized `RenewWorkLease` round
/// trip between accept and start entirely: the claim-time lease keeps its
/// window minus the offer-to-accept latency, and the periodic renewal task
/// re-arms it on its ordinary cadence. A controller without the feature
/// leaves the field default-false, so the agent must keep the explicit
/// renewal for such a peer or it would spawn work whose cancellation it
/// never observed.
pub const ACCEPT_LEASE_STATE_FEATURE: &str = "accept-carries-lease-state-v1";
/// The peer processes `WorkCompletion.inline_log_chunks`.
///
/// A controller without this feature ignores the unknown field, so an agent
/// that inlined its log streams anyway would report a terminal whose logs
/// were silently never published. The agent must therefore publish through
/// `PublishLog` unless this feature was negotiated; the controller side
/// accepts inline chunks unconditionally because they carry exactly the
/// authority and bounds of a `PublishLog` call.
pub const INLINE_TERMINAL_LOGS_FEATURE: &str = "inline-terminal-logs-v1";
/// The peer understands `CancellationDisposition::DISCHARGE_RECOVERED`.
///
/// A peer without it rejects the unknown enum value as an unsupported
/// protocol and reconnects, leaving the recovered attempt parked forever, so
/// the controller must answer such a peer with the previous disposition.
pub const RECOVERED_DISCHARGE_FEATURE: &str = "recovered-discharge-v1";
/// Controller lease granted while a retained terminal attempt is replayed.
pub const RECOVERED_FINALIZATION_LEASE_SECONDS: u64 = 30;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolRange {
    pub major: u16,
    pub minimum_minor: u16,
    pub maximum_minor: u16,
    pub features: BTreeSet<String>,
}

impl ProtocolRange {
    #[must_use]
    pub fn current(features: impl IntoIterator<Item = String>) -> Self {
        Self {
            major: PROTOCOL_MAJOR,
            minimum_minor: PROTOCOL_MINOR,
            maximum_minor: PROTOCOL_MINOR,
            features: features.into_iter().collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NegotiatedProtocol {
    pub major: u16,
    pub minor: u16,
    pub features: BTreeSet<String>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum ProtocolError {
    #[error("protocol major mismatch: local {local}, remote {remote}")]
    MajorMismatch { local: u16, remote: u16 },
    #[error(
        "protocol minor ranges do not overlap: local {local_min}..={local_max}, remote {remote_min}..={remote_max}"
    )]
    MinorMismatch {
        local_min: u16,
        local_max: u16,
        remote_min: u16,
        remote_max: u16,
    },
    #[error("protocol minor range is invalid: {minimum}..={maximum}")]
    InvalidRange { minimum: u16, maximum: u16 },
    #[error("protocol field {field} exceeds the supported 16-bit range")]
    FieldOverflow { field: &'static str },
}

impl TryFrom<&wire::ProtocolOffer> for ProtocolRange {
    type Error = ProtocolError;

    fn try_from(value: &wire::ProtocolOffer) -> Result<Self, Self::Error> {
        Ok(Self {
            major: u16::try_from(value.major)
                .map_err(|_| ProtocolError::FieldOverflow { field: "major" })?,
            minimum_minor: u16::try_from(value.minimum_minor).map_err(|_| {
                ProtocolError::FieldOverflow {
                    field: "minimum_minor",
                }
            })?,
            maximum_minor: u16::try_from(value.maximum_minor).map_err(|_| {
                ProtocolError::FieldOverflow {
                    field: "maximum_minor",
                }
            })?,
            features: value.features.iter().cloned().collect(),
        })
    }
}

pub fn negotiate(
    local: &ProtocolRange,
    remote: &ProtocolRange,
) -> Result<NegotiatedProtocol, ProtocolError> {
    if local.minimum_minor > local.maximum_minor {
        return Err(ProtocolError::InvalidRange {
            minimum: local.minimum_minor,
            maximum: local.maximum_minor,
        });
    }
    if remote.minimum_minor > remote.maximum_minor {
        return Err(ProtocolError::InvalidRange {
            minimum: remote.minimum_minor,
            maximum: remote.maximum_minor,
        });
    }
    if local.major != remote.major {
        return Err(ProtocolError::MajorMismatch {
            local: local.major,
            remote: remote.major,
        });
    }

    let minimum = local.minimum_minor.max(remote.minimum_minor);
    let maximum = local.maximum_minor.min(remote.maximum_minor);
    if minimum > maximum {
        return Err(ProtocolError::MinorMismatch {
            local_min: local.minimum_minor,
            local_max: local.maximum_minor,
            remote_min: remote.minimum_minor,
            remote_max: remote.maximum_minor,
        });
    }

    Ok(NegotiatedProtocol {
        major: local.major,
        minor: maximum,
        features: local
            .features
            .intersection(&remote.features)
            .cloned()
            .collect(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Enrollment {
    pub agent_id: String,
    pub trust_pool: String,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EnrollmentError {
    #[error("enrollment token is unknown or already consumed")]
    InvalidToken,
    #[error("enrollment token must not be empty")]
    EmptyToken,
    #[error("enrollment token digest is already registered")]
    DuplicateToken,
    #[error("certificate signing request is empty")]
    EmptyCertificateSigningRequest,
}

/// One-time bootstrap-token registry.
///
/// Only SHA-256 digests are retained. Successful consumption removes the
/// digest before returning identity data, so a token cannot be replayed.
#[derive(Debug, Default)]
pub struct EnrollmentRegistry {
    pending: HashMap<[u8; 32], Enrollment>,
}

impl EnrollmentRegistry {
    pub fn register(
        &mut self,
        token: &[u8],
        enrollment: Enrollment,
    ) -> Result<(), EnrollmentError> {
        if token.is_empty() {
            return Err(EnrollmentError::EmptyToken);
        }
        let digest = token_digest(token);
        if self.pending.contains_key(&digest) {
            return Err(EnrollmentError::DuplicateToken);
        }
        self.pending.insert(digest, enrollment);
        Ok(())
    }

    pub fn consume(
        &mut self,
        token: &[u8],
        certificate_signing_request_der: &[u8],
    ) -> Result<Enrollment, EnrollmentError> {
        if certificate_signing_request_der.is_empty() {
            return Err(EnrollmentError::EmptyCertificateSigningRequest);
        }
        self.pending
            .remove(&token_digest(token))
            .ok_or(EnrollmentError::InvalidToken)
    }
}

fn token_digest(token: &[u8]) -> [u8; 32] {
    Sha256::digest(token).into()
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum FenceError {
    #[error("session epoch {offered} is not newer than current epoch {current}")]
    StaleOpen { offered: u64, current: u64 },
    #[error("session epoch {offered} is stale; current epoch is {current}")]
    StaleAuthority { offered: u64, current: u64 },
    #[error("certificate epoch {offered} is stale; current epoch is {current}")]
    StaleCertificate { offered: u64, current: u64 },
    #[error("certificate epoch is exhausted")]
    CertificateEpochExhausted,
}

/// Monotonic controller-side authority for agent sessions and certificates.
#[derive(Debug, Default)]
pub struct AgentEpochs {
    sessions: HashMap<String, u64>,
    certificates: HashMap<String, u64>,
}

impl AgentEpochs {
    pub fn open_session(&mut self, agent_id: &str, offered: u64) -> Result<(), FenceError> {
        let current = self.sessions.get(agent_id).copied().unwrap_or(0);
        if offered <= current {
            return Err(FenceError::StaleOpen { offered, current });
        }
        self.sessions.insert(agent_id.to_owned(), offered);
        Ok(())
    }

    pub fn authorize(&self, agent_id: &str, offered: u64) -> Result<(), FenceError> {
        let current = self.sessions.get(agent_id).copied().unwrap_or(0);
        if offered != current {
            return Err(FenceError::StaleAuthority { offered, current });
        }
        Ok(())
    }

    pub fn rotate_certificate(
        &mut self,
        agent_id: &str,
        current_certificate_epoch: u64,
    ) -> Result<u64, FenceError> {
        let current = self.certificates.get(agent_id).copied().unwrap_or(0);
        if current_certificate_epoch != current {
            return Err(FenceError::StaleCertificate {
                offered: current_certificate_epoch,
                current,
            });
        }
        let next = current
            .checked_add(1)
            .ok_or(FenceError::CertificateEpochExhausted)?;
        self.certificates.insert(agent_id.to_owned(), next);
        Ok(next)
    }
}

#[derive(Clone, Debug)]
pub struct OutboundMtlsConfig {
    pub controller_uri: String,
    pub controller_dns_name: String,
    pub controller_ca_pem: Vec<u8>,
    pub agent_certificate_pem: Vec<u8>,
    pub agent_private_key_pem: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum TransportError {
    #[error("controller URI must use https")]
    InsecureControllerUri,
    #[error("controller DNS name must not be empty")]
    EmptyControllerDnsName,
    #[error("TLS material must not be empty")]
    EmptyTlsMaterial,
    #[error("controller CA PEM is invalid: {0}")]
    InvalidControllerCa(String),
    #[error("agent certificate PEM is invalid: {0}")]
    InvalidAgentCertificate(String),
    #[error("agent private key PEM is invalid: {0}")]
    InvalidAgentPrivateKey(String),
    #[error("agent certificate and private key are incompatible: {0}")]
    InvalidClientIdentity(String),
    #[error("invalid controller endpoint: {0}")]
    InvalidEndpoint(#[from] tonic::transport::Error),
}

impl OutboundMtlsConfig {
    /// Builds the only transport surface exposed to the agent: an outbound
    /// mTLS endpoint. Calling `connect` on the returned value initiates the
    /// connection from agent to controller.
    pub fn endpoint(&self) -> Result<Endpoint, TransportError> {
        if !self.controller_uri.starts_with("https://") {
            return Err(TransportError::InsecureControllerUri);
        }
        if self.controller_dns_name.trim().is_empty() {
            return Err(TransportError::EmptyControllerDnsName);
        }
        if self.controller_ca_pem.is_empty()
            || self.agent_certificate_pem.is_empty()
            || self.agent_private_key_pem.is_empty()
        {
            return Err(TransportError::EmptyTlsMaterial);
        }

        self.validate_tls_material()?;

        let tls = ClientTlsConfig::new()
            .domain_name(self.controller_dns_name.clone())
            .ca_certificate(Certificate::from_pem(self.controller_ca_pem.clone()))
            .identity(Identity::from_pem(
                self.agent_certificate_pem.clone(),
                self.agent_private_key_pem.clone(),
            ));

        Ok(Endpoint::from_shared(self.controller_uri.clone())?.tls_config(tls)?)
    }

    fn validate_tls_material(&self) -> Result<(), TransportError> {
        let controller_cas = CertificateDer::pem_slice_iter(&self.controller_ca_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TransportError::InvalidControllerCa(error.to_string()))?;
        if controller_cas.is_empty() {
            return Err(TransportError::InvalidControllerCa(
                "no CERTIFICATE section was found".to_owned(),
            ));
        }
        let mut roots = RootCertStore::empty();
        let (accepted, rejected) = roots.add_parsable_certificates(controller_cas);
        if accepted == 0 || rejected != 0 {
            return Err(TransportError::InvalidControllerCa(format!(
                "accepted {accepted} certificate(s) and rejected {rejected}"
            )));
        }

        let certificates = CertificateDer::pem_slice_iter(&self.agent_certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TransportError::InvalidAgentCertificate(error.to_string()))?;
        if certificates.is_empty() {
            return Err(TransportError::InvalidAgentCertificate(
                "no CERTIFICATE section was found".to_owned(),
            ));
        }
        let private_key = PrivateKeyDer::from_pem_slice(&self.agent_private_key_pem)
            .map_err(|error| TransportError::InvalidAgentPrivateKey(error.to_string()))?;

        let leaf = certificates
            .first()
            .expect("the certificate chain was already proven non-empty");
        let (_, parsed_leaf) = parse_x509_certificate(leaf.as_ref())
            .map_err(|error| TransportError::InvalidAgentCertificate(error.to_string()))?;
        if !parsed_leaf.validity().is_valid() {
            return Err(TransportError::InvalidAgentCertificate(
                "certificate is expired or not yet valid".to_owned(),
            ));
        }
        if let Some(extended_key_usage) = parsed_leaf
            .extended_key_usage()
            .map_err(|error| TransportError::InvalidAgentCertificate(error.to_string()))?
            && !extended_key_usage.value.any
            && !extended_key_usage.value.client_auth
        {
            return Err(TransportError::InvalidAgentCertificate(
                "certificate extended key usage does not permit TLS client authentication"
                    .to_owned(),
            ));
        }
        if let Some(key_usage) = parsed_leaf
            .key_usage()
            .map_err(|error| TransportError::InvalidAgentCertificate(error.to_string()))?
            && !key_usage.value.digital_signature()
        {
            return Err(TransportError::InvalidAgentCertificate(
                "certificate key usage does not permit digital signatures".to_owned(),
            ));
        }

        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certificates, private_key)
            .map_err(|error| TransportError::InvalidClientIdentity(error.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, date_time_ymd,
    };

    fn features(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn generated_mtls_config(agent_not_before: i32, agent_not_after: i32) -> OutboundMtlsConfig {
        generated_mtls_config_with_usages(
            agent_not_before,
            agent_not_after,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            Vec::new(),
        )
    }

    fn generated_mtls_config_with_usages(
        agent_not_before: i32,
        agent_not_after: i32,
        extended_key_usages: Vec<ExtendedKeyUsagePurpose>,
        key_usages: Vec<KeyUsagePurpose>,
    ) -> OutboundMtlsConfig {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.not_before = date_time_ymd(2019, 1, 1);
        ca_params.not_after = date_time_ymd(2100, 1, 1);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let mut ca_name = DistinguishedName::new();
        ca_name.push(DnType::CommonName, "McLoving test CA");
        ca_params.distinguished_name = ca_name;
        let ca_key = KeyPair::generate().unwrap();
        let ca = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let mut agent_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        agent_params.not_before = date_time_ymd(agent_not_before, 1, 1);
        agent_params.not_after = date_time_ymd(agent_not_after, 1, 1);
        agent_params.extended_key_usages = extended_key_usages;
        agent_params.key_usages = key_usages;
        let mut agent_name = DistinguishedName::new();
        agent_name.push(DnType::CommonName, "McLoving test agent");
        agent_params.distinguished_name = agent_name;
        let agent_key = KeyPair::generate().unwrap();
        let agent = agent_params.signed_by(&agent_key, &ca).unwrap();

        OutboundMtlsConfig {
            controller_uri: "https://controller.internal:8443".to_owned(),
            controller_dns_name: "controller.internal".to_owned(),
            controller_ca_pem: ca.pem().into_bytes(),
            agent_certificate_pem: agent.pem().into_bytes(),
            agent_private_key_pem: agent_key.serialize_pem().into_bytes(),
        }
    }

    #[test]
    fn negotiation_chooses_highest_shared_minor_and_feature_intersection() {
        let local = ProtocolRange {
            major: 1,
            minimum_minor: 2,
            maximum_minor: 5,
            features: features(&["journal-v1", "rotation-v1"]),
        };
        let remote = ProtocolRange {
            major: 1,
            minimum_minor: 3,
            maximum_minor: 7,
            features: features(&["rotation-v1", "future"]),
        };

        assert_eq!(
            negotiate(&local, &remote),
            Ok(NegotiatedProtocol {
                major: 1,
                minor: 5,
                features: features(&["rotation-v1"]),
            })
        );
    }

    #[test]
    fn negotiation_fails_closed_for_major_or_minor_mismatch() {
        let current = ProtocolRange::current([]);
        let other_major = ProtocolRange {
            major: 2,
            ..current.clone()
        };
        assert!(matches!(
            negotiate(&current, &other_major),
            Err(ProtocolError::MajorMismatch { .. })
        ));

        let future_minor = ProtocolRange {
            major: 1,
            minimum_minor: 1,
            maximum_minor: 1,
            features: BTreeSet::new(),
        };
        assert!(matches!(
            negotiate(&current, &future_minor),
            Err(ProtocolError::MinorMismatch { .. })
        ));
    }

    #[test]
    fn enrollment_token_is_one_time_and_csr_is_required() {
        let mut registry = EnrollmentRegistry::default();
        let enrollment = Enrollment {
            agent_id: "agent-1".to_owned(),
            trust_pool: "untrusted-linux".to_owned(),
        };
        registry
            .register(b"one-time-secret", enrollment.clone())
            .unwrap();

        assert_eq!(
            registry.consume(b"one-time-secret", b""),
            Err(EnrollmentError::EmptyCertificateSigningRequest)
        );
        assert_eq!(registry.consume(b"one-time-secret", b"csr"), Ok(enrollment));
        assert_eq!(
            registry.consume(b"one-time-secret", b"csr"),
            Err(EnrollmentError::InvalidToken)
        );
    }

    #[test]
    fn wire_protocol_fields_fail_closed_before_narrowing() {
        let offer = wire::ProtocolOffer {
            major: u32::from(u16::MAX) + 1,
            minimum_minor: 0,
            maximum_minor: 0,
            features: Vec::new(),
        };
        assert_eq!(
            ProtocolRange::try_from(&offer),
            Err(ProtocolError::FieldOverflow { field: "major" })
        );
    }

    #[test]
    fn enrollment_rejects_empty_or_duplicate_bootstrap_tokens() {
        let mut registry = EnrollmentRegistry::default();
        let enrollment = Enrollment {
            agent_id: "agent-1".to_owned(),
            trust_pool: "untrusted-linux".to_owned(),
        };
        assert_eq!(
            registry.register(b"", enrollment.clone()),
            Err(EnrollmentError::EmptyToken)
        );
        registry.register(b"token", enrollment.clone()).unwrap();
        assert_eq!(
            registry.register(b"token", enrollment),
            Err(EnrollmentError::DuplicateToken)
        );
    }

    #[test]
    fn newer_session_fences_old_authority_and_rotation_is_monotonic() {
        let mut epochs = AgentEpochs::default();
        epochs.open_session("agent-1", 10).unwrap();
        epochs.authorize("agent-1", 10).unwrap();
        epochs.open_session("agent-1", 11).unwrap();

        assert_eq!(
            epochs.authorize("agent-1", 10),
            Err(FenceError::StaleAuthority {
                offered: 10,
                current: 11,
            })
        );
        assert_eq!(
            epochs.open_session("agent-1", 11),
            Err(FenceError::StaleOpen {
                offered: 11,
                current: 11,
            })
        );
        assert_eq!(epochs.rotate_certificate("agent-1", 0), Ok(1));
        assert_eq!(
            epochs.rotate_certificate("agent-1", 0),
            Err(FenceError::StaleCertificate {
                offered: 0,
                current: 1,
            })
        );
    }

    #[test]
    fn outbound_transport_refuses_plaintext_or_partial_identity() {
        let mut config = OutboundMtlsConfig {
            controller_uri: "http://controller.internal:8443".to_owned(),
            controller_dns_name: "controller.internal".to_owned(),
            controller_ca_pem: b"ca".to_vec(),
            agent_certificate_pem: b"cert".to_vec(),
            agent_private_key_pem: b"key".to_vec(),
        };
        assert!(matches!(
            config.endpoint(),
            Err(TransportError::InsecureControllerUri)
        ));

        config.controller_uri = "https://controller.internal:8443".to_owned();
        config.agent_private_key_pem.clear();
        assert!(matches!(
            config.endpoint(),
            Err(TransportError::EmptyTlsMaterial)
        ));
    }

    #[test]
    fn outbound_transport_rejects_malformed_pem_before_connecting() {
        let config = OutboundMtlsConfig {
            controller_uri: "https://controller.internal:8443".to_owned(),
            controller_dns_name: "controller.internal".to_owned(),
            controller_ca_pem: b"not a PEM certificate".to_vec(),
            agent_certificate_pem: b"not a PEM certificate".to_vec(),
            agent_private_key_pem: b"not a PEM key".to_vec(),
        };

        assert!(matches!(
            config.endpoint(),
            Err(TransportError::InvalidControllerCa(_))
        ));
    }

    #[test]
    fn outbound_transport_rejects_expired_or_not_yet_valid_agent_certificates() {
        let expired = generated_mtls_config(2020, 2021);
        assert!(matches!(
            expired.endpoint(),
            Err(TransportError::InvalidAgentCertificate(_))
        ));

        let not_yet_valid = generated_mtls_config(2090, 2091);
        assert!(matches!(
            not_yet_valid.endpoint(),
            Err(TransportError::InvalidAgentCertificate(_))
        ));

        generated_mtls_config(2020, 2090).endpoint().unwrap();
    }

    #[test]
    fn outbound_transport_rejects_incompatible_client_certificate_usages() {
        let server_only = generated_mtls_config_with_usages(
            2020,
            2090,
            vec![ExtendedKeyUsagePurpose::ServerAuth],
            Vec::new(),
        );
        assert!(matches!(
            server_only.endpoint(),
            Err(TransportError::InvalidAgentCertificate(message))
                if message.contains("TLS client authentication")
        ));

        let no_signature = generated_mtls_config_with_usages(
            2020,
            2090,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            vec![KeyUsagePurpose::KeyEncipherment],
        );
        assert!(matches!(
            no_signature.endpoint(),
            Err(TransportError::InvalidAgentCertificate(message))
                if message.contains("digital signatures")
        ));

        generated_mtls_config_with_usages(2020, 2090, Vec::new(), Vec::new())
            .endpoint()
            .unwrap();
    }
}
