use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ObserverError {
    #[error("observer configuration is invalid")]
    InvalidConfig,
    #[error("observation request is malformed")]
    MalformedRequest,
    #[error("observation request authorization is invalid")]
    UnauthorizedRequest,
    #[error("observation request does not bind the certified runtime")]
    BindingMismatch,
    #[error("observation request has expired")]
    ExpiredRequest,
    #[error("destination read grant has expired")]
    ExpiredGrant,
    #[error("the certified observer runtime is no longer active")]
    RuntimeFenced,
    #[error("observation identifier was replayed with different content")]
    ReplayMismatch,
    #[error("an observation for this destination scope is already pending")]
    ObservationPending,
    #[error("observation phase or predecessor is invalid")]
    PhaseMismatch,
    #[error("destination cursor moved backwards or failed to advance")]
    CursorRollback,
    #[error("destination denied the read-only observer grant")]
    DestinationUnauthorized,
    #[error("destination observation is unavailable")]
    DestinationUnavailable,
    #[error("destination response is malformed or substituted")]
    MalformedResponse,
    #[error("destination response exceeds its certified bound")]
    OversizedResponse,
    #[error("destination response is stale or from the future")]
    StaleObservation,
    #[error("destination response contains denied confidential material")]
    ConfidentialityDenied,
    #[error("observer evidence capacity is exhausted")]
    CapacityExceeded,
    #[error("observer private state is unavailable or invalid")]
    StateUnavailable,
    #[error("stored or supplied receipt is invalid")]
    InvalidReceipt,
}

impl ObserverError {
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::MalformedRequest => "malformed_request",
            Self::UnauthorizedRequest => "unauthorized_request",
            Self::BindingMismatch => "binding_mismatch",
            Self::ExpiredRequest => "expired_request",
            Self::ExpiredGrant => "expired_grant",
            Self::RuntimeFenced => "runtime_fenced",
            Self::ReplayMismatch => "replay_mismatch",
            Self::ObservationPending => "observation_pending",
            Self::PhaseMismatch => "phase_mismatch",
            Self::CursorRollback => "cursor_rollback",
            Self::DestinationUnauthorized => "destination_unauthorized",
            Self::DestinationUnavailable => "destination_unavailable",
            Self::MalformedResponse => "malformed_response",
            Self::OversizedResponse => "oversized_response",
            Self::StaleObservation => "stale_observation",
            Self::ConfidentialityDenied => "confidentiality_denied",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::StateUnavailable => "state_unavailable",
            Self::InvalidReceipt => "invalid_receipt",
        }
    }
}
