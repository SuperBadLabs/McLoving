use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConnectorError {
    #[error("connector configuration is invalid")]
    InvalidConfig,
    #[error("connector request is malformed")]
    MalformedRequest,
    #[error("connector request exceeds its certified bound")]
    OversizedRequest,
    #[error("connector request authorization is invalid")]
    UnauthorizedRequest,
    #[error("connector request does not bind the certified authority")]
    BindingMismatch,
    #[error("connector request or grant has expired")]
    ExpiredAuthority,
    #[error("connector generation is fenced")]
    RuntimeFenced,
    #[error("request identifier was replayed with different content")]
    ReplayMismatch,
    #[error("this physical effect scope already has durable authority or evidence")]
    EffectPending,
    #[error("the external destination denied the connector grant")]
    DestinationUnauthorized,
    #[error("the external destination is unavailable")]
    DestinationUnavailable,
    #[error("the external response is malformed or substituted")]
    MalformedResponse,
    #[error("the external response exceeds its certified bound")]
    OversizedResponse,
    #[error("public protocol data contains protected secret material")]
    ConfidentialityDenied,
    #[error("the effect is ambiguous and requires independent reconciliation")]
    AmbiguousEffect,
    #[error("independent reconciliation evidence is invalid")]
    InvalidObservation,
    #[error("shadow replay evidence is invalid")]
    InvalidReplay,
    #[error("connector evidence capacity is exhausted")]
    CapacityExceeded,
    #[error("connector private state is unavailable or invalid")]
    StateUnavailable,
    #[error("stored or supplied receipt is invalid")]
    InvalidReceipt,
}

impl ConnectorError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::MalformedRequest => "malformed_request",
            Self::OversizedRequest => "oversized_request",
            Self::UnauthorizedRequest => "unauthorized_request",
            Self::BindingMismatch => "binding_mismatch",
            Self::ExpiredAuthority => "expired_authority",
            Self::RuntimeFenced => "runtime_fenced",
            Self::ReplayMismatch => "replay_mismatch",
            Self::EffectPending => "effect_pending",
            Self::DestinationUnauthorized => "destination_unauthorized",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::MalformedResponse => "malformed_response",
            Self::OversizedResponse => "oversized_response",
            Self::ConfidentialityDenied => "confidentiality_denied",
            Self::AmbiguousEffect => "ambiguous_effect",
            Self::InvalidObservation => "invalid_observation",
            Self::InvalidReplay => "invalid_replay",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::StateUnavailable => "state_unavailable",
            Self::InvalidReceipt => "invalid_receipt",
        }
    }
}
