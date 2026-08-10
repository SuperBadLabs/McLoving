use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{ObservationReceipt, ObservationRequest, ObserverError, SignedDestinationState};

const REQUEST_DOMAIN: &[u8] = b"mcloving-destination-observation-request-v1";
const DESTINATION_DOMAIN: &[u8] = b"mcloving-destination-state-v1";
const RECEIPT_DOMAIN: &[u8] = b"mcloving-destination-observation-receipt-v1";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"mcloving-observer-receipt-digest-v1";

fn message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, ObserverError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ObserverError::StateUnavailable)?;
    let mut output = Vec::with_capacity(domain.len() + 1 + encoded.len());
    output.extend_from_slice(domain);
    output.push(0);
    output.extend_from_slice(&encoded);
    Ok(output)
}

pub fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ObserverError> {
    Ok(content_sha256(&message(domain, value)?))
}

pub fn content_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

pub fn observation_request_message(request: &ObservationRequest) -> Result<Vec<u8>, ObserverError> {
    let mut unsigned = request.clone();
    unsigned.authorization.signature_base64.clear();
    message(REQUEST_DOMAIN, &unsigned)
}

pub fn destination_state_message(state: &SignedDestinationState) -> Result<Vec<u8>, ObserverError> {
    message(DESTINATION_DOMAIN, &state.body)
}

pub fn receipt_message(receipt: &ObservationReceipt) -> Result<Vec<u8>, ObserverError> {
    let mut unsigned = receipt.clone();
    unsigned.signature_base64.clear();
    message(RECEIPT_DOMAIN, &unsigned)
}

pub fn observation_receipt_digest(receipt: &ObservationReceipt) -> Result<String, ObserverError> {
    canonical_digest(RECEIPT_DIGEST_DOMAIN, receipt)
}

pub fn sign_observation_request(
    request: &mut ObservationRequest,
    seed: &[u8],
) -> Result<(), ObserverError> {
    request.authorization.signature_base64.clear();
    request.authorization.signature_base64 = sign(&observation_request_message(request)?, seed)?;
    Ok(())
}

pub fn sign_receipt(receipt: &mut ObservationReceipt, seed: &[u8]) -> Result<(), ObserverError> {
    receipt.signature_base64.clear();
    receipt.signature_base64 = sign(&receipt_message(receipt)?, seed)?;
    Ok(())
}

pub(crate) fn verify_request(
    request: &ObservationRequest,
    public_key: &[u8],
) -> Result<(), ObserverError> {
    verify(
        &observation_request_message(request)?,
        &request.authorization.signature_base64,
        public_key,
        ObserverError::UnauthorizedRequest,
    )
}

pub(crate) fn verify_destination_state(
    state: &SignedDestinationState,
    public_key: &[u8],
) -> Result<(), ObserverError> {
    verify(
        &destination_state_message(state)?,
        &state.signature_base64,
        public_key,
        ObserverError::MalformedResponse,
    )
}

pub fn verify_observation_receipt(
    receipt: &ObservationReceipt,
    public_key: &[u8],
) -> Result<(), ObserverError> {
    if receipt.schema_version != crate::RECEIPT_SCHEMA_VERSION
        || receipt.protocol_version != crate::PROTOCOL_VERSION
        || receipt.observation_id.is_nil()
        || receipt.evidence_sequence == 0
        || receipt.receipt_signing_public_key_sha256 != content_sha256(public_key)
    {
        return Err(ObserverError::InvalidReceipt);
    }
    verify(
        &receipt_message(receipt)?,
        &receipt.signature_base64,
        public_key,
        ObserverError::InvalidReceipt,
    )
}

fn sign(message: &[u8], seed: &[u8]) -> Result<String, ObserverError> {
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ObserverError::InvalidConfig)?;
    Ok(BASE64.encode(pair.sign(message).as_ref()))
}

fn verify(
    message: &[u8],
    signature: &str,
    public_key: &[u8],
    error: ObserverError,
) -> Result<(), ObserverError> {
    let signature = BASE64.decode(signature).map_err(|_| error.clone())?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| error)
}

pub(crate) fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, ObserverError> {
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ObserverError::InvalidConfig)?;
    Ok(pair.public_key().as_ref().to_vec())
}
