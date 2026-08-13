use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    ActionRequest, ConnectorError, OutcomeReceipt, RuntimeImageAttestation, ShadowReplayReceipt,
    SignedDestinationOutcome,
};

const REQUEST_DOMAIN: &[u8] = b"mcloving-external-action-request-v1";
const DESTINATION_DOMAIN: &[u8] = b"mcloving-external-destination-outcome-v1";
const OUTCOME_DOMAIN: &[u8] = b"mcloving-external-outcome-receipt-v1";
const OUTCOME_DIGEST_DOMAIN: &[u8] = b"mcloving-external-outcome-digest-v1";
const SHADOW_DOMAIN: &[u8] = b"mcloving-external-shadow-receipt-v1";
const RUNTIME_IMAGE_ATTESTATION_DOMAIN: &[u8] = b"mcloving-runtime-image-attestation-v1";

pub fn content_sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

pub fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, ConnectorError> {
    Ok(content_sha256(&message(domain, value)?))
}

pub fn action_request_digest(request: &ActionRequest) -> Result<String, ConnectorError> {
    canonical_digest(REQUEST_DOMAIN, &unsigned_request(request))
}

pub fn destination_outcome_digest(
    response: &SignedDestinationOutcome,
) -> Result<String, ConnectorError> {
    canonical_digest(DESTINATION_DOMAIN, response)
}

pub fn outcome_receipt_digest(receipt: &OutcomeReceipt) -> Result<String, ConnectorError> {
    canonical_digest(OUTCOME_DIGEST_DOMAIN, receipt)
}

pub fn sign_action_request(request: &mut ActionRequest, seed: &[u8]) -> Result<(), ConnectorError> {
    request.authorization.signature_base64.clear();
    request.authorization.signature_base64 = sign(&request_message(request)?, seed)?;
    Ok(())
}

pub fn verify_action_request(
    request: &ActionRequest,
    public_key: &[u8],
) -> Result<(), ConnectorError> {
    verify(
        &request_message(request)?,
        &request.authorization.signature_base64,
        public_key,
        ConnectorError::UnauthorizedRequest,
    )
}

pub fn sign_destination_outcome(
    response: &mut SignedDestinationOutcome,
    seed: &[u8],
) -> Result<(), ConnectorError> {
    response.signature_base64.clear();
    response.signature_base64 = sign(&destination_message(response)?, seed)?;
    Ok(())
}

pub fn verify_destination_outcome(
    response: &SignedDestinationOutcome,
    public_key: &[u8],
) -> Result<(), ConnectorError> {
    verify(
        &destination_message(response)?,
        &response.signature_base64,
        public_key,
        ConnectorError::MalformedResponse,
    )
}

pub fn sign_outcome_receipt(
    receipt: &mut OutcomeReceipt,
    seed: &[u8],
) -> Result<(), ConnectorError> {
    receipt.signature_base64.clear();
    receipt.signature_base64 = sign(&outcome_message(receipt)?, seed)?;
    Ok(())
}

pub fn verify_outcome_receipt(
    receipt: &OutcomeReceipt,
    public_key: &[u8],
) -> Result<(), ConnectorError> {
    if receipt.schema_version != crate::OUTCOME_RECEIPT_SCHEMA_VERSION
        || receipt.protocol_version != crate::PROTOCOL_VERSION
        || receipt.evidence_sequence == 0
        || receipt.request_id.is_nil()
        || receipt.outcome_signing_public_key_sha256 != content_sha256(public_key)
    {
        return Err(ConnectorError::InvalidReceipt);
    }
    verify(
        &outcome_message(receipt)?,
        &receipt.signature_base64,
        public_key,
        ConnectorError::InvalidReceipt,
    )
}

pub fn sign_shadow_receipt(
    receipt: &mut ShadowReplayReceipt,
    seed: &[u8],
) -> Result<(), ConnectorError> {
    receipt.signature_base64.clear();
    receipt.signature_base64 = sign(&shadow_message(receipt)?, seed)?;
    Ok(())
}

pub fn verify_shadow_receipt(
    receipt: &ShadowReplayReceipt,
    public_key: &[u8],
) -> Result<(), ConnectorError> {
    if receipt.schema_version != crate::SHADOW_RECEIPT_SCHEMA_VERSION
        || receipt.replay_id.is_nil()
        || receipt.replay_signing_public_key_sha256 != content_sha256(public_key)
    {
        return Err(ConnectorError::InvalidReplay);
    }
    verify(
        &shadow_message(receipt)?,
        &receipt.signature_base64,
        public_key,
        ConnectorError::InvalidReplay,
    )
}

pub fn sign_runtime_image_attestation(
    attestation: &mut RuntimeImageAttestation,
    seed: &[u8],
) -> Result<(), ConnectorError> {
    attestation.signature_base64.clear();
    attestation.signature_base64 = sign(&runtime_attestation_message(attestation)?, seed)?;
    Ok(())
}

pub fn verify_runtime_image_attestation_signature(
    attestation: &RuntimeImageAttestation,
    public_key: &[u8],
) -> Result<(), ConnectorError> {
    verify(
        &runtime_attestation_message(attestation)?,
        &attestation.signature_base64,
        public_key,
        ConnectorError::InvalidConfig,
    )
}

pub fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, ConnectorError> {
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ConnectorError::InvalidConfig)?;
    Ok(pair.public_key().as_ref().to_vec())
}

fn request_message(request: &ActionRequest) -> Result<Vec<u8>, ConnectorError> {
    message(REQUEST_DOMAIN, &unsigned_request(request))
}

fn unsigned_request(request: &ActionRequest) -> ActionRequest {
    let mut unsigned = request.clone();
    unsigned.authorization.signature_base64.clear();
    unsigned
}

fn destination_message(response: &SignedDestinationOutcome) -> Result<Vec<u8>, ConnectorError> {
    let mut unsigned = response.clone();
    unsigned.signature_base64.clear();
    message(DESTINATION_DOMAIN, &unsigned.body)
}

fn outcome_message(receipt: &OutcomeReceipt) -> Result<Vec<u8>, ConnectorError> {
    let mut unsigned = receipt.clone();
    unsigned.signature_base64.clear();
    message(OUTCOME_DOMAIN, &unsigned)
}

fn shadow_message(receipt: &ShadowReplayReceipt) -> Result<Vec<u8>, ConnectorError> {
    let mut unsigned = receipt.clone();
    unsigned.signature_base64.clear();
    message(SHADOW_DOMAIN, &unsigned)
}

fn runtime_attestation_message(
    attestation: &RuntimeImageAttestation,
) -> Result<Vec<u8>, ConnectorError> {
    let mut unsigned = attestation.clone();
    unsigned.signature_base64.clear();
    message(RUNTIME_IMAGE_ATTESTATION_DOMAIN, &unsigned)
}

fn message<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, ConnectorError> {
    let encoded = serde_json::to_vec(value).map_err(|_| ConnectorError::MalformedRequest)?;
    let domain_len = u64::try_from(domain.len()).map_err(|_| ConnectorError::MalformedRequest)?;
    let encoded_len = u64::try_from(encoded.len()).map_err(|_| ConnectorError::MalformedRequest)?;
    let mut output = Vec::with_capacity(16 + domain.len() + encoded.len());
    output.extend_from_slice(&domain_len.to_be_bytes());
    output.extend_from_slice(domain);
    output.extend_from_slice(&encoded_len.to_be_bytes());
    output.extend_from_slice(&encoded);
    Ok(output)
}

fn sign(message: &[u8], seed: &[u8]) -> Result<String, ConnectorError> {
    let pair =
        Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ConnectorError::InvalidConfig)?;
    Ok(BASE64.encode(pair.sign(message).as_ref()))
}

fn verify(
    message: &[u8],
    signature: &str,
    public_key: &[u8],
    error: ConnectorError,
) -> Result<(), ConnectorError> {
    let signature = BASE64.decode(signature).map_err(|_| error.clone())?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| error)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}
