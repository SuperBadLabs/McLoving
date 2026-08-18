#!/usr/bin/python3
"""Deterministic, process-isolated EXT-002 protocol fixture.

This fixture owns no endpoint or credential.  It exists only to prove the
controller's signed connector/observer/shadow join over the real stdio process
boundary.  The three Ed25519 PKCS#8 keys are supplied by the test deployment.
"""

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import time


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def connector_frame(domain, value):
    encoded = compact(value)
    return len(domain).to_bytes(8, "big") + domain + len(encoded).to_bytes(8, "big") + encoded


def observer_frame(domain, value):
    return domain + b"\0" + compact(value)


def public_key_digest(openssl, key):
    result = subprocess.run(
        [openssl, "pkey", "-in", key, "-inform", "DER", "-pubout", "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return hashlib.sha256(result.stdout[-32:]).hexdigest()


def sign(openssl, key, domain, value, frame):
    unsigned = dict(value)
    unsigned["signature_base64"] = ""
    with tempfile.NamedTemporaryFile() as message:
        message.write(frame(domain, unsigned))
        message.flush()
        result = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-inkey",
                key,
                "-keyform",
                "DER",
                "-rawin",
                "-in",
                message.name,
            ],
            check=True,
            capture_output=True,
        )
    value["signature_base64"] = base64.b64encode(result.stdout).decode()


def action_digest(request):
    unsigned = dict(request)
    unsigned["authorization"] = dict(request["authorization"])
    unsigned["authorization"]["signature_base64"] = ""
    return hashlib.sha256(
        connector_frame(b"mcloving-external-action-request-v1", unsigned)
    ).hexdigest()


def observation_digest(request):
    unsigned = dict(request)
    unsigned["authorization"] = dict(request["authorization"])
    unsigned["authorization"]["signature_base64"] = ""
    return hashlib.sha256(
        observer_frame(b"mcloving-destination-observation-request-v1", unsigned)
    ).hexdigest()


def connector_response(command, openssl, outcome_key):
    if command.get("command") != "execute":
        raise ValueError("only execute is supported by the positive fixture")
    request = command["request"]
    now = int(time.time() * 1000)
    receipt = {
        "schema_version": "mcloving.external-outcome-receipt/v1",
        "protocol_version": "mcloving.external-connector/v1",
        "evidence_sequence": 1,
        "request_id": request["request_id"],
        "request_sha256": action_digest(request),
        "tenant_id": request["tenant_id"],
        "project_id": request["project_id"],
        "pipeline_id": request["pipeline_id"],
        "build_id": request["build_id"],
        "attempt_id": request["attempt_id"],
        "effect_fence": request["effect_fence"],
        "effect_key": request["effect_key"],
        "connector_id": request["connector_id"],
        "connector_implementation_sha256": request["expected_implementation_sha256"],
        "connector_image_sha256": request["expected_image_sha256"],
        "connector_config_sha256": request["expected_config_sha256"],
        "deployment_identity": "fixture-connector-deployment",
        "operator_trust_identity": "fixture-connector-operator",
        "runtime_boundary_identity": "fixture-connector-runtime",
        "service_identity": "fixture-connector-service",
        "configuration_authority_identity": "fixture-connector-config-authority",
        "request_authority_identity": "fixture-controller",
        "credential_issuance_path_identity": "fixture-grant-issuer",
        "generation": request["expected_generation"],
        "activation_mode": "current",
        "previous_generation": None,
        "previous_config_sha256": None,
        "rollback_from_generation": None,
        "endpoint_identity": request["endpoint_identity"],
        "account_identity": request["account_identity"],
        "resource_identity": request["resource_identity"],
        "effect_class": request["effect_class"],
        "idempotency_class": request["idempotency_class"],
        "action_name": request["action_name"],
        "action_schema_version": request["action_schema_version"],
        "credential_grant_id": request["credential_grant_id"],
        "credential_grant_version": request["credential_grant_version"],
        "credential_grant_scope": request["credential_grant_scope"],
        "request_payload_sha256": hashlib.sha256(compact(request["request_payload"])).hexdigest(),
        "status": "succeeded",
        "status_code": "fixture_succeeded",
        "public_values": {"delivery_id": "fixture-delivery-1"},
        "protected_secret_refs": [],
        "external_ids": {"delivery": "fixture-delivery-1"},
        "downstream_control_digest": "sha256:" + "b" * 64,
        "later_intents_digest": "sha256:" + "c" * 64,
        "destination_response_sha256": None,
        "destination_signature_base64": None,
        "destination_attestation_key_id": None,
        "attempt_count": 1,
        "ambiguous_requires_observation": False,
        "observation_receipt_sha256": None,
        "dispatched_at_unix_ms": now,
        "captured_at_unix_ms": now,
        "audit_provenance": "ext-002/fixture/connector",
        "outcome_signing_key_id": "fixture-outcome-key",
        "outcome_signing_public_key_sha256": public_key_digest(openssl, outcome_key),
        "signature_base64": "",
    }
    sign(
        openssl,
        outcome_key,
        b"mcloving-external-outcome-receipt-v1",
        receipt,
        connector_frame,
    )
    return {"status": "ok", "receipt": receipt}


def observer_response(command, openssl, observer_key):
    if command.get("operation") != "observe":
        raise ValueError("only observe is supported by the positive fixture")
    request = command["request"]
    now = int(time.time() * 1000)
    receipt = {
        "schema_version": "mcloving.destination-observation-receipt/v1",
        "protocol_version": "mcloving.destination-observer/v1",
        "evidence_sequence": 1,
        "observation_id": request["observation_id"],
        "request_sha256": observation_digest(request),
        "tenant_id": request["tenant_id"],
        "project_id": request["project_id"],
        "pipeline_id": request["pipeline_id"],
        "build_id": request["build_id"],
        "attempt_id": request["attempt_id"],
        "effect_fence": request["effect_fence"],
        "phase": request["phase"],
        "predecessor_receipt_sha256": request["predecessor_receipt_sha256"],
        "observer_id": request["observer_id"],
        "observer_implementation_sha256": request["expected_implementation_sha256"],
        "observer_image_sha256": request["expected_image_sha256"],
        "observer_config_sha256": request["expected_config_sha256"],
        "deployment_identity": "fixture-observer-deployment",
        "operator_trust_identity": "fixture-observer-operator",
        "runtime_boundary_identity": "fixture-observer-runtime",
        "service_identity": "fixture-observer-service",
        "credential_issuance_path_identity": "fixture-read-grant-issuer",
        "configuration_authority_identity": "fixture-observer-config-authority",
        "request_authority_identity": request["request_authority_identity"],
        "generation": request["expected_generation"],
        "activation_mode": request["activation_mode"],
        "previous_generation": request["previous_generation"],
        "rollback_from_generation": request["rollback_from_generation"],
        "endpoint_identity": request["endpoint_identity"],
        "account_identity": request["account_identity"],
        "resource_identity": request["resource_identity"],
        "effect_class": request["effect_class"],
        "read_grant_id": request["read_grant_id"],
        "read_grant_version": request["read_grant_version"],
        "read_grant_scope": request["read_grant_scope"],
        "canonical_query": request["query"],
        "destination_cursor": 1,
        "destination_observed_at_unix_ms": now,
        "captured_at_unix_ms": now,
        "publication_deadline_unix_ms": request["expires_at_unix_ms"],
        "state_schema_version": "fixture.observation/v1",
        "confidentiality": "public",
        "destination_response_sha256": hashlib.sha256(b"fixture-observation").hexdigest(),
        "destination_signature_base64": "fixture-destination-signature",
        "destination_attestation_key_id": "fixture-destination-key",
        "state": {"connector_request_sha256": "joined-by-controller", "effect_observed": True},
        "retry_count": 0,
        "audit_provenance": "ext-002/fixture/observer",
        "receipt_signing_key_id": "fixture-observer-key",
        "receipt_signing_public_key_sha256": public_key_digest(openssl, observer_key),
        "signature_base64": "",
    }
    sign(
        openssl,
        observer_key,
        b"mcloving-destination-observation-receipt-v1",
        receipt,
        observer_frame,
    )
    return {"status": "observed", "receipt": receipt}


def shadow_response(command, openssl, shadow_key):
    if command.get("command") != "replay":
        raise ValueError("only replay is supported by the positive fixture")
    request = command["request"]
    outcome = request["outcome_receipt"]
    # Hold the terminal join open long enough for the integration test to prove
    # that the attempt is still non-terminal after outcome and observation are
    # durable but before the deny-authority replay completes.
    time.sleep(0.75)
    receipt = {
        "schema_version": "mcloving.external-shadow-receipt/v1",
        "replay_id": request["replay_id"],
        "outcome_receipt_sha256": request["expected_outcome_receipt_sha256"],
        "request_id": outcome["request_id"],
        "tenant_id": outcome["tenant_id"],
        "project_id": outcome["project_id"],
        "build_id": outcome["build_id"],
        "attempt_id": outcome["attempt_id"],
        "effect_fence": outcome["effect_fence"],
        "effect_key": outcome["effect_key"],
        "shadow_identity": request["expected_shadow_identity"],
        "replay_authority_identity": "fixture-shadow-authority",
        "status": outcome["status"],
        "status_code": outcome["status_code"],
        "public_values": outcome["public_values"],
        "protected_secret_refs": outcome["protected_secret_refs"],
        "external_ids": outcome["external_ids"],
        "downstream_control_digest": outcome["downstream_control_digest"],
        "later_intents_digest": outcome["later_intents_digest"],
        "replayed_at_unix_ms": request["replayed_at_unix_ms"],
        "audit_provenance": "ext-002/fixture/shadow",
        "replay_signing_key_id": "fixture-shadow-key",
        "replay_signing_public_key_sha256": public_key_digest(openssl, shadow_key),
        "signature_base64": "",
    }
    sign(
        openssl,
        shadow_key,
        b"mcloving-external-shadow-receipt-v1",
        receipt,
        connector_frame,
    )
    return {"status": "ok", "receipt": receipt}


def main():
    if len(sys.argv) != 6:
        raise ValueError("expected openssl, three role-key paths, and a diagnostic path")
    openssl, outcome_key, observer_key, shadow_key, _diagnostic = sys.argv[1:]
    command = json.loads(sys.stdin.readline())
    if "operation" in command:
        response = observer_response(command, openssl, observer_key)
    elif command.get("command") == "replay":
        response = shadow_response(command, openssl, shadow_key)
    else:
        response = connector_response(command, openssl, outcome_key)
    sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        if len(sys.argv) == 6:
            with open(sys.argv[5], "w", encoding="utf-8") as output:
                output.write(repr(error))
        raise
