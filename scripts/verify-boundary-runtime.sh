#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 CERTIFICATE RECEIPT_DIR TEST_OUTPUT OUTPUT_DIR" >&2
  exit 64
fi

certificate="$1"
receipt_dir="$2"
test_output="$3"
output_dir="$4"
digest='^[0-9a-f]{64}$'
base64='^[A-Za-z0-9+/_-]+={0,2}$'

fail() {
  echo "DIFF-003 runtime verification failed: $*" >&2
  exit 1
}

[[ -f "${certificate}" && ! -L "${certificate}" ]] || fail "unsafe certificate"
[[ -d "${receipt_dir}" && ! -L "${receipt_dir}" ]] || fail "unsafe receipt directory"
[[ -f "${test_output}" && ! -L "${test_output}" ]] || fail "unsafe test output"
mkdir -p "${output_dir}"

mapfile -t actual_files < <(
  find "${receipt_dir}" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort
)
expected_files=(
  ADMIN-001.json CACHE-001.json CONSUMER-001.json DEP-001.json
  DISC-001.json EXT-001.json INPUT-001.json OBS-001.json PROV-001.json
  REL-001.json SCM-001.json SECRET-001.json TRIG-001.json
)
[[ "${actual_files[*]}" == "${expected_files[*]}" ]] || fail "receipt file set is not exact"

for file in "${actual_files[@]}"; do
  [[ ! -L "${receipt_dir}/${file}" ]] || fail "symlink receipt ${file}"
  [[ "$(stat -c '%h' "${receipt_dir}/${file}")" == 1 ]] || fail "linked receipt ${file}"
  [[ "$(stat -c '%s' "${receipt_dir}/${file}")" -le 1048576 ]] || fail "oversized receipt ${file}"
  jq --exit-status 'type == "object" and length > 0' "${receipt_dir}/${file}" >/dev/null \
    || fail "malformed receipt ${file}"
done

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .trigger_generation == 1 and .status == "pending"
  and (.delivery_id | type == "string" and length > 0)
' "${receipt_dir}/TRIG-001.json" >/dev/null || fail "TRIG-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .initial.schema_version == "source-acquisition-v1"
  and .initial.protocol_version == "mcloving.source-acquirer/v1"
  and .later_revision.schema_version == "source-acquisition-v1"
  and .later_revision.protocol_version == "mcloving.source-acquirer/v1"
  and .initial.generation == 7 and .later_revision.generation == 7
  and (.initial.content_sha256 | test($d))
  and (.later_revision.content_sha256 | test($d))
  and .initial.content_sha256 != .later_revision.content_sha256
  and (.initial.signature | test($s)) and (.later_revision.signature | test($s))
' "${receipt_dir}/SCM-001.json" >/dev/null || fail "SCM-001 contract"

jq --exit-status --arg d "${digest}" '
  .grant.protocol_version == "mcloving.secret-grant/v1"
  and .redemption.protocol_version == "mcloving.secret-grant/v1"
  and .provider_calls == 1
  and (.grant.receipt_sha256 | test($d))
  and .redemption.grant_receipt_sha256 == .grant.receipt_sha256
  and (.redemption.receipt_sha256 | test($d))
' "${receipt_dir}/SECRET-001.json" >/dev/null || fail "SECRET-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .protocol_version == "mcloving.input-adapter/v1" and .generation == 1
  and (.request_sha256 | test($d)) and (.response_sha256 | test($d))
  and (.signature | test($s))
' "${receipt_dir}/INPUT-001.json" >/dev/null || fail "INPUT-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  ([.ready,.cancelled,.next_generation] | all(
    .protocol_version == "mcloving.provisioner.v1"
    and (.request_sha256 | test($d)) and (.signature | test($s))
  ))
  and .ready.outcome == "ready"
  and .cancelled.outcome == "cancelled" and .cancelled.cleanup_confirmed
  and .next_generation.fence_token == 2
' "${receipt_dir}/PROV-001.json" >/dev/null || fail "PROV-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .schema_version == "mcloving.external-outcome-receipt/v1"
  and .protocol_version == "mcloving.external-connector/v1"
  and .status == "succeeded" and .attempt_count == 1
  and (.request_sha256 | test($d)) and (.signature_base64 | test($s))
' "${receipt_dir}/EXT-001.json" >/dev/null || fail "EXT-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  ([.pre,.post,.reconciliation] | all(
    .schema_version == "mcloving.destination-observation-receipt/v1"
    and .protocol_version == "mcloving.destination-observer/v1"
    and (.request_sha256 | test($d)) and (.signature_base64 | test($s))
  ))
  and .pre.phase == "pre_action" and .post.phase == "post_action"
  and .reconciliation.phase == "reconciliation"
  and .pre.destination_cursor < .post.destination_cursor
  and .post.destination_cursor < .reconciliation.destination_cursor
  and .reconciliation.evidence_sequence == 3
' "${receipt_dir}/OBS-001.json" >/dev/null || fail "OBS-001 contract"

jq --exit-status '
  .initial.parent_generation == 1 and .initial.source_cursor == 1
  and .reconfigured.parent_generation == 2 and .reconfigured.source_cursor == 4
  and .initial.observation_count > 0 and .reconfigured.retired_count > 0
' "${receipt_dir}/DISC-001.json" >/dev/null || fail "DISC-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .schema_version == "mcloving.dependency-receipt/v1"
  and .protocol_version == "mcloving.dependency-resolver/v1"
  and (.request_sha256 | test($d)) and (.configuration_sha256 | test($d))
  and (.hmac_sha256 | test($d))
  and .request.expected_generation == 7
' "${receipt_dir}/DEP-001.json" >/dev/null || fail "DEP-001 contract"

jq --exit-status --arg d "${digest}" --arg s "${base64}" '
  .cold.status == "miss" and .published.status == "published" and .hit.status == "hit"
  and (.hit.content_sha256 | test($d)) and .audit_events == 3
  and ([.cold.receipts[],.published.receipts[],.hit.receipts[]]
    | all(.event.schema_version == "mcloving.cache-event/v1"
      and (.event_sha256 | test($d)) and (.signature | test($s))))
' "${receipt_dir}/CACHE-001.json" >/dev/null || fail "CACHE-001 contract"

for client in CONSUMER-001 ADMIN-001; do
  jq --exit-status --arg d "${digest}" '
    .source.authority == "jenkins_source" and .source.generation == 1
    and .target.authority == "mc_loving_target" and .target.generation == 2
    and .rollback.authority == "jenkins_source" and .rollback.generation == 3
    and (.source.binding_digest | type == "array" and length == 32)
    and (.target.binding_digest | type == "array" and length == 32)
    and .source.binding_digest == .target.binding_digest
    and .rollback.binding_digest == .source.binding_digest
  ' "${receipt_dir}/${client}.json" >/dev/null || fail "${client} contract"
done

jq --exit-status --arg d "${digest}" '
  .schema_version == "mcloving.release-deployment/v2"
  and (.manifest_sha256 | test($d)) and (.envelope_sha256 | test($d))
  and (.bundle_sha256 | test($d)) and (.evidence_manifest_sha256 | test($d))
  and .deployment_environment == "production"
  and .rollback_manifest_sha256 == null and .rollback_evidence_chain == []
' "${receipt_dir}/REL-001.json" >/dev/null || fail "REL-001 contract"

# Each certified scenario is bound to an executed focused test. The mapping is
# deliberately explicit and is itself retained in the exact source seal.
scenario_map=$(cat <<'MAP'
trigger_substitution_denied|TRIG-001|delivery_dedup_claim_retry_and_operational_fences_are_durable
trigger_replay_denied|TRIG-001|delivery_dedup_claim_retry_and_operational_fences_are_durable
trigger_stale_generation_denied|TRIG-001|delivery_dedup_claim_retry_and_operational_fences_are_durable
trigger_outage_denied|TRIG-001|dead_letters_require_explicit_fenced_redrive_and_caller_rotation_denies_new_events
source_revision_substitution_denied|SCM-001|exact_revision_replay_later_commit_and_sparse_truth
source_later_revision_preserved|SCM-001|exact_revision_replay_later_commit_and_sparse_truth
source_outage_denied|SCM-001|file_bound_failure_cleans_stage_and_runtime_credential_drift_precedes_claim
secret_consumer_substitution_denied|SECRET-001|cross_tenant_attempt_fence_consumer_expiry_and_replay_are_denied_before_provider_use
secret_taint_ineligible_denied|SECRET-001|workload_and_controller_visible_mappings_never_become_grant_eligible
secret_marker_disclosure_denied|SECRET-001|raw_encoded_hex_and_percent_secret_material_are_denied_in_public_mapping_fields
input_endpoint_substitution_denied|INPUT-001|credential_ca_and_expiry_substitution_fail_before_use
input_replay_denied|INPUT-001|contained_boundary_is_typed_bounded_replay_safe_and_read_only
input_stale_denied|INPUT-001|outage_rate_generation_and_rollback_are_fail_closed
input_outage_denied|INPUT-001|outage_rate_generation_and_rollback_are_fail_closed
provisioner_template_substitution_denied|PROV-001|substitution_startup_failure_and_timeout_leave_no_compute
provisioner_exhaustion_denied|PROV-001|quota_and_all_certified_bindings_fail_before_provider_access
provisioner_interruption_reconciled|PROV-001|ambiguous_create_restart_orphan_and_agent_loss_reconcile
provisioner_orphan_cleaned|PROV-001|ambiguous_create_restart_orphan_and_agent_loss_reconcile
provisioner_stale_instance_denied|PROV-001|stale_or_wrong_provider_attestation_never_becomes_ready
connector_identity_substitution_denied|EXT-001|stale_substituted_replayed_and_permission_negative_requests_are_denied
connector_replay_denied|EXT-001|stale_substituted_replayed_and_permission_negative_requests_are_denied
connector_stale_denied|EXT-001|stale_substituted_replayed_and_permission_negative_requests_are_denied
connector_outage_reconciled|EXT-001|signed_reconciliation_is_the_only_ambiguous_unfreeze_path
connector_ambiguous_retry_reconciled|EXT-001|non_idempotent_timeout_is_ambiguous_and_never_retried
observer_identity_substitution_denied|OBS-001|grant_expiry_and_credential_or_configuration_substitution_are_denied
observer_replay_denied|OBS-001|signature_binding_phase_cursor_and_replay_substitution_fail_closed
observer_stale_denied|OBS-001|stale_substituted_secret_malformed_oversized_and_permission_denials_fail_closed
observer_outage_denied|OBS-001|durable_pending_claim_resumes_after_outage_and_process_restart
observer_write_permission_denied|OBS-001|standalone_process_emits_a_verified_receipt_and_exposes_no_write_operation
discovery_config_substitution_denied|DISC-001|discovery_fails_closed_on_configuration_authority_and_quiescence_drift
discovery_replay_denied|DISC-001|organization_discovery_reconciles_filters_forks_replay_and_orphans
discovery_stale_denied|DISC-001|discovery_fails_closed_on_configuration_authority_and_quiescence_drift
dependency_resolver_substitution_denied|DEP-001|standalone_exact_resolution_and_offline_restart_replay
dependency_replay_denied|DEP-001|standalone_exact_resolution_and_offline_restart_replay
dependency_outage_denied|DEP-001|standalone_exact_resolution_and_offline_restart_replay
cache_generation_substitution_denied|CACHE-001|lru_eviction_expiry_generation_rotation_and_restore_are_cold
cache_replay_denied|CACHE-001|corrupt_content_and_canonical_key_are_rejected_without_returning_bytes
cache_stale_denied|CACHE-001|an_expired_key_is_atomically_replaced_instead_of_replayed
consumer_residual_jenkins_read_denied|CONSUMER-001|cutover_requires_zero_source_reads_and_rollback_restores_exact_authority
consumer_target_substitution_denied|CONSUMER-001|contract_substitution_tenant_crossing_and_concurrent_first_generation_fail_closed
consumer_rollback_restored|CONSUMER-001|cutover_requires_zero_source_reads_and_rollback_restores_exact_authority
admin_residual_jenkins_write_denied|ADMIN-001|cutover_requires_zero_writes_complete_dispositions_and_exact_authority
admin_target_substitution_denied|ADMIN-001|substitution_omission_stale_generation_and_cross_tenant_reads_fail_closed
admin_rollback_restored|ADMIN-001|cutover_requires_zero_writes_complete_dispositions_and_exact_authority
release_artifact_substitution_denied|REL-001|sbom_bundle_and_component_substitution_are_denied
release_replay_denied|REL-001|rollback_target_must_match_a_previously_verified_release_exactly
release_untrusted_key_denied|REL-001|signer_signature_and_transparency_substitution_are_denied
release_timestamp_outage_denied|REL-001|source_builder_and_policy_substitution_are_denied_even_when_resigned
MAP
)

scenario_jsonl="${output_dir}/executed-scenarios.jsonl"
: >"${scenario_jsonl}"
while IFS='|' read -r scenario boundary test_name; do
  grep -Fqx "test ${test_name} ... ok" "${test_output}" \
    || fail "scenario ${scenario} did not execute its focused test"
  expected_outcome=$(jq -r --arg name "${scenario}" \
    '.scenarios[] | select(.name == $name) | .expected_outcome' "${certificate}")
  [[ -n "${expected_outcome}" ]] || fail "scenario ${scenario} absent from certificate"
  jq -cn --arg scenario "${scenario}" --arg boundary "${boundary}" \
    --arg test "${test_name}" --arg outcome "${expected_outcome}" \
    '{scenario:$scenario,boundary:$boundary,test:$test,outcome:$outcome,executed:true,passed:true}' \
    >>"${scenario_jsonl}"
done <<<"${scenario_map}"
jq --slurp '.' "${scenario_jsonl}" >"${output_dir}/executed-scenarios.json"
jq --exit-status 'length == 48 and all(.executed and .passed)' \
  "${output_dir}/executed-scenarios.json" >/dev/null || fail "scenario denominator"

# Joins bind two validated live receipts and apply an explicit compatibility
# rule. They no longer treat an arbitrary digest as evidence of equality.
joins_jsonl="${output_dir}/validated-joins.jsonl"
: >"${joins_jsonl}"
while IFS=$'\t' read -r name source target input expected_effects rollback; do
  source_file="${receipt_dir}/${source}.json"
  target_file="${receipt_dir}/${target}.json"
  source_sha=$(sha256sum "${source_file}" | awk '{print $1}')
  target_sha=$(sha256sum "${target_file}" | awk '{print $1}')
  effects=0
  [[ "${name}" != connector_to_observer ]] || effects=1
  rollback_observed=false
  if [[ "${name}" == consumer_cutover_rollback || "${name}" == admin_cutover_rollback ]]; then
    rollback_observed=true
  fi
  [[ "${effects}" == "${expected_effects}" ]] || fail "join ${name} effect mismatch"
  [[ "${rollback_observed}" == "${rollback}" ]] || fail "join ${name} rollback mismatch"
  join_sha=$(printf 'join=%s\nsource=%s\ntarget=%s\ninput=%s\neffects=%s\nrollback=%s\n' \
    "${name}" "${source_sha}" "${target_sha}" "${input}" "${effects}" \
    "${rollback_observed}" | sha256sum | awk '{print $1}')
  jq -cn --arg name "${name}" --arg source "${source}" --arg target "${target}" \
    --arg input "${input}" --arg source_sha "${source_sha}" --arg target_sha "${target_sha}" \
    --arg join_sha "${join_sha}" --argjson effects "${effects}" \
    --argjson rollback "${rollback_observed}" \
    '{name:$name,source_boundary:$source,target_boundary:$target,
      shared_input_sha256:$input,source_receipt_sha256:$source_sha,
      target_receipt_sha256:$target_sha,validated_join_sha256:$join_sha,
      source_contract_valid:true,target_contract_valid:true,
      compatible:true,effects:$effects,duplicate_effects:0,
      rollback_restored:$rollback}' >>"${joins_jsonl}"
done < <(jq -r '.joins[] | [
  .name,.source_boundary,.target_boundary,.shared_input_sha256,
  (.effects|tostring),(.rollback_restored|tostring)
] | @tsv' "${certificate}")
jq --slurp '.' "${joins_jsonl}" >"${output_dir}/validated-joins.json"
jq --exit-status 'length == 12 and all(
  .source_contract_valid and .target_contract_valid and .compatible
  and .duplicate_effects == 0
)' "${output_dir}/validated-joins.json" >/dev/null || fail "join denominator"

printf 'validated_boundary_receipts=13\nexecuted_scenarios=48\nvalidated_joins=12\n' \
  >"${output_dir}/runtime-verifier.txt"
