# INPUT-001 security and implementation closure

Date: 2026-08-05

Verdict: implementation gate pending the complete exact-head protected checks
and independent review. This receipt does not claim a Mario production input,
canary, cutover, rollback, or Jenkins decommissioning event.

## Inventory denominator

The accepted MIG-000 runtime-dependency manifest SHA-256 is
`238ed4cc59ff67bbb1dc40bb1bd3ec28dce914c4dffd701f1a8505d760ba11a4`.
The executable inventory test proves that all 230 entries are the sealed
`opaque-cps-runtime`, `controller-global`, `scripted` dependency and that the
manifest declares no admitted live external input. No synthetic fixture is
represented as Mario production truth.

## Implemented boundary

- standalone NDJSON adapter process with self-hashed executable and canonical
  immutable configuration binding;
- one exact GET-only endpoint, no redirects, no ambient proxies, HTTPS/private
  CA production policy, and double-gated loopback fixture mode;
- scoped bearer grant identity/version/scope/expiry/content digest, pinned
  HMAC-key and private-CA content digests, and canonical query allowlist;
- bounded regular-file reads for configuration, credentials, full CA bundle,
  executable, claims, and receipts, with symlink and oversize denial;
- tenant/project/pipeline/build/attempt/input, generation, cursor, expiry,
  confidentiality, and audit-lineage binding;
- bounded timeout, retry, response size, rate, freshness, and typed JSON schema;
- secret-labelled response denial plus marker-set non-disclosure scanning;
- atomic durable capture claims, no-overwrite receipt publication, restart
  replay, and substituted-replay denial; and
- complete signed response receipt with source provenance and canonical value
  digest for identical dual-runner consumption.

## Current executable receipt

Focused pinned-Rust check and clippy pass. The suite currently proves four
contained end-to-end journeys, four unit contracts, and one sealed-inventory
denominator check. The complete locked workspace clippy and test gates also
pass. The final exact-head receipt will record the protected check results after
implementation review.

## Residual risk and authority boundary

V1 validates top-level JSON field types rather than an arbitrary schema
language. Secret-labelled inputs are unsupported, and marker scanning cannot
prove non-disclosure of every transformed secret. The adapter and verifier
share an HMAC key, so their collusion could forge a receipt. Host, endpoint,
private-CA, read-grant issuer, adapter operator, and marker-set operator remain
trusted within their explicit scopes. DIFF-003, SHADOW-001, CANARY-001,
CUTOVER-001, ROLLBACK-001, and SEC-004 remain mandatory for any later real
input and authority transition.
