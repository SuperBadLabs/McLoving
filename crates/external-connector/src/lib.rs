//! Scoped out-of-process external-effect connector and deny-authority shadow replay.
//!
//! The effectful connector owns one exact action at one endpoint/account/resource
//! scope. It has no controller database, scheduler, agent, controller-filesystem,
//! or unrelated-secret authority. The shadow replayer is a separate no-network
//! boundary that consumes only signed, confidentiality-safe outcome receipts.

mod authority;
mod connector;
mod crypto;
mod error;
mod model;
mod shadow;
mod standalone;
mod store;
mod strict_json;

pub use authority::{
    read_bounded_regular_file, read_private_bounded_regular_file, sha256_running_executable,
};
pub use connector::ExternalConnector;
pub use crypto::{
    action_request_digest, canonical_digest, content_sha256, destination_outcome_digest,
    outcome_receipt_digest, public_key_from_seed, request_payload_digest, sign_action_request,
    sign_destination_outcome, sign_outcome_receipt, sign_runtime_image_attestation,
    sign_shadow_receipt, verify_action_request, verify_destination_outcome, verify_outcome_receipt,
    verify_runtime_image_attestation_signature, verify_shadow_receipt,
};
pub use error::ConnectorError;
pub use model::*;
pub use shadow::ShadowReplayer;
pub use standalone::{
    ConnectorCommand, ConnectorResponse, MAX_FRAME_BYTES, ShadowCommand, ShadowResponse,
    load_connector, load_shadow_replayer, require_shadow_apparmor_enforcement,
    serve_connector_stdio, serve_shadow_stdio,
};
pub use strict_json::parse_json_no_duplicates;
