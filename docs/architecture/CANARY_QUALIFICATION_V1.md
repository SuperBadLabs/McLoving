# Canary qualification v1

Status: CANARY-001 effect-free qualification foundation; production ceremony pending an eligible case

## Purpose and authority boundary

`mcloving.canary-qualification/private-v1` verifies one graduated production
effect action after it has been observed. It does not grant authority, invoke a
connector, create credentials, contact a destination, or change Jenkins or
McLoving state. A successful verifier result says that the supplied signed
pre-action gates, authoritative connector outcome, effect-free shadow replay,
and paired independently authenticated destination observations describe one
bounded action. The result always reports
`authority_granted_by_verifier=false`.

The current sealed Mario population cannot produce a successful session. Its
scenario contract states `effect_authority=false` and
`canary_eligible=false`; all 230 reconciled jobs remain `unsupported`. The sole
owner-private MIG-007 package is a disabled, zero-effect case admitted only for
SHADOW-001 denial parity. A production ceremony therefore requires a new
effectful case to complete its exact current MIG-002 through MIG-007
certification and SHADOW-001 qualification before CANARY-001 can grant one
action. Configuration cannot override this eligibility boundary.

## Canonical private inputs

The verifier accepts a canonical, duplicate-free JSON session and a separate
canonical owner-held pin set. The raw session digest, reviewed implementation
Git head, and public-key digest for every signing role are pinned independently.
The verifier rejects a session whose repeated implementation head differs from
that independent expected head. The session is bounded to one MiB and
operational output contains only counts and booleans; it never prints a session,
pin, package, evidence, key, job, account, resource, or digest value.

The ten signing roles are pairwise distinct:

- threat-model review;
- live inventory reconciliation;
- atomic runtime/input freeze;
- relinquishing-runner quiescence;
- execution-history/state transfer;
- canonical intent comparison;
- one-action effect grant;
- authoritative connector outcome;
- effect-free shadow replay; and
- independent destination observation.

An embedded public key is useful only when its digest equals the independently
supplied role pin. Reusing one key for two roles rejects the complete session.
Every CANARY gate receipt binds the same ceremony UUID, job, action UUID,
reviewed implementation head, MIG-007 package, MIG-006 receipt, SHADOW-001
session, evidence digest, collection time, and expiry.

## Pre-action gates

Seven signed gates must all precede the effect grant:

1. The current threat-model content, mitigations, verification evidence, and
   residual-risk acceptance are bound to at least two distinct named reviewers.
2. A live inventory re-read exactly matches its certified digest, the job is
   enabled and explicitly canary-eligible, the effect class is known, and no
   Jenkins-only external reader or administrative writer remains.
3. One atomic re-read exactly matches all 20 certified source, shared-library,
   controller-input, compiler, mapping, component, state-transform, release,
   platform, agent, toolchain, authorization, trigger, discovery, connector,
   SCM, credential, dependency, cache, and destination identities. Its signed
   semantic platform must also equal the session platform used to select the
   Windows interruption-proof requirement. Four execution-critical component
   digests have normative domain-separated meanings: `external_connector`
   binds the granted connector ID, implementation, image, and configuration;
   `destination` binds the granted destination scope and signed observer
   implementation/deployment identities; `credential_mapping` binds the signed
   connector credential grant and authority identities; and `platform` binds
   the semantic platform. The verifier recomputes all four from the executed
   signed receipts after validating those receipts.
4. The relinquishing runner has paused ingress, scheduling, and grants and has
   zero queue, run, credential, connector-authority, lease, lock, retry,
   uncertain-effect, or residual effect-authority count.
5. A fresh content-hashed export passes the exact certified transform; source
   and imported record counts agree on a nonzero authenticated denominator,
   retention is not shortened, every hold is preserved, and the portable state
   passes its secret scan.
6. Exactly one source intent and one target intent are buffered and their
   canonical digests, effect key, and fence match before authority is issued.
7. The grant is for one action, a bounded positive attempt count and authority
   window, abort on the first failure, mandatory audit and abort-rule digests,
   retained evidence, and fail-closed ambiguity handling.

Windows actions additionally require a signed persistent-host interruption and
reboot proof showing no orphan process and no duplicate effect. This is a
post-action proof: it must be collected strictly after the authoritative
connector outcome and no later than ceremony completion. Supplying that proof
for a Linux action, omitting it for Windows, or supplying stale pre-action proof
fails closed.

## Outcome join

Before the grant, the independent observer signs a fresh pre-action receipt for
the exact tenant, project, pipeline, build, attempt, fence, endpoint, account,
resource, and effect class. The grant binds that receipt digest as its
precondition plus the exact connector request digest and precommitted canonical
post-state digest. Each observer receipt retains its own native digest of its
distinct phase-specific `ObservationRequest`; those digests are not connector
request digests. The independently signed canonical observer query instead
binds `connector_request_sha256` to the exact connector request in the grant,
and that query remains identical across the observer chain.

The authoritative `external-connector/v1` outcome must match the grant's exact
connector implementation, image, configuration, endpoint, account, resource,
effect class, request/build identities, key, fence, and attempt quota. V1 accepts
a successful bounded outcome only. A normal successful connector outcome has no
embedded observation digest and is joined to the separately signed
`destination-observer/v1` post-action receipt by the ceremony. A successfully
reconciled ambiguous outcome must instead embed the digest of the exact signed
reconciliation receipt; the ceremony carries and verifies the complete
pre-action -> post-action -> reconciliation observer chain. This matches both
receipt shapes emitted by `EXT-001` rather than inventing a third shape.

Before downstream control flow is released, the no-authority shadow must replay
that exact outcome digest and match request/build/attempt identities, fence,
effect key, status, public values, protected secret references, external IDs,
downstream-control digest, and later-intent digest. The destination receipt must
then match the tenant/project/pipeline/build/attempt, endpoint/account/resource,
effect class, fence, predecessor precondition digest, publication deadline,
and a destination-observation time strictly after grant issuance; its canonical
state must equal the result committed by the grant before the effect. This
post-grant lower bound also applies when reconciliation is present, which must
preserve the same observer identities and scope, advance the signed cursor from
the post-action receipt, bind the connector request digest, affirm that the
effect was observed in its exact two-field reconciliation state, and precede
the connector's final reconciled outcome. Connector and
observer deployment, runtime, service, and credential-issuance identities must
be separate.

The final authority ledger proves the old runner had no authority before the
grant, the named authoritative runner held the single fenced action, the shadow
had neither effect authority nor a production endpoint, exactly one action
consumed the grant, no duplicate or ambiguous effect remains, and new effects
are frozen again. A later graduated action requires a completely fresh session.

## Retained limitation and next ceremony

This foundation is deliberately effect-free and cannot close CANARY-001 by
itself. The next owner-level decision is the exact Jenkins job and production
effect class to certify. After that case completes the prerequisite package and
shadow chain, the live ceremony must generate fresh independent role pins,
perform the pre-action threat-model review, obtain explicit one-action owner
authority, run the fenced connector once, seal the outcome/shadow/observer
session on HeMan, and verify it at the exact reviewed implementation head.
