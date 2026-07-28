//! State names reserved by the approved architecture.
//!
//! Transition authority and persistence are intentionally not implemented in
//! the foundation ticket.

/// Attempt phases named by the architecture decision record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttemptPhase {
    Offered,
    Accepted,
    Running,
    Finalizing,
    Succeeded,
    Failed,
    Cancelling,
    Aborted,
    ReconciliationRequired,
}
