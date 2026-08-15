# REL-001 release-ceremony closure

- Status: complete
- Release: McLoving v0.1.0
- Profile: `private-linux-x86_64`
- Release ID: `3d38cc2c-a88b-4fac-aae2-7d9459c36ee5`
- Ceremony date: 2026-08-14/15 UTC

## Scope and claim boundary

REL-001 closes trusted private-release provenance. The protected-main artifact
was signed on HeMan, its secondary attestation was published to the public
Rekor transparency log, its canonical evidence-manifest digest received an
independently verified DigiCert RFC 3161 timestamp, and the complete private
evidence package was retained outside GitHub Actions.

The verifier receipt uses environment `private-release-verification` and its
bound context states `binary_placement_performed: false`. This closure does not
claim production deployment, canary authority, cutover, public release-binary
publication, or a completed Bitcoin confirmation for the supplemental
OpenTimestamps proof.

## Protected source and builder

- Protocol PR: #57
- Exact reviewed head: `e24fadaea5adce777b49716d25a26d9238b9e24f`
- Protected-main squash commit: `8d2519afcf29a82fa813fcddc8e131ddb7e83935`
- Protected-main tree: `0f7b7f30e66c5984a17ce4997970c528de7e1c7e`
- Reviewed-head and protected-main trees: byte-identical
- Foundation run: `31856516170`, success
- Windows Agent run: `31856516169`, success
- Release Builder run: `31858118097`, success
- Authenticated workflow artifact SHA-256:
  `6473174abe701aadf7332aae83744cd599090bfe0bd25c23adeacd1dece9ea94`
- Bundle SHA-256:
  `10ee5896a43940995b817a2c7acdd7223bfc0227194dd9b22a446aa37d77bd59`
- SBOM SHA-256:
  `7ae014d376137d60854f7e47ddf2bfb822c2d2d421cc43b40297facb87591407`

All seven actionable PR review threads were fixed, replied to, and resolved.
The final exact-head review found no major issue. Protected-main Foundation,
Windows Agent, and isolated Release Builder runs all passed.

## Signing custody and signed identity

The primary `release-key:production:v1` Ed25519/PKCS#8 private key exists only
on HeMan at the owner-relative path
`~/.local/share/mcloving/release-signing/v1/release-key.pkcs8`. The containing
directory is mode `0700`; the key is owned by the ceremony account, mode
`0600`, with link count one. Neither private signing key is present in the
repository, GitHub, `/sn8100`, logs, or another host. The private HeMan evidence
package retains the exact authorized absolute path and ownership receipt.

- Primary public-key SHA-256:
  `44ce26be48cb7eda1b5a518908e3dcca1584813c62c9aa9107ba42c794270dbe`
- Signed manifest SHA-256:
  `badd0724faea2b6f8e644216b2ab2c7b0fd12d8c00954693796f590ff2aacf00`
- Signed envelope SHA-256:
  `09fea3d02f5bdb55fd4835a6bf92339eb47cfbba9f33b8b4a3bc4925596e293e`
- One-time genesis policy: explicitly enabled; rollback target is null

## Transparency and independent anchor

- Rekor identity: `rekor:https://rekor.sigstore.dev`
- Rekor entry:
  `108e9186e8c5677aa038380ec1f5062d282b17affb4457a78f2c3d091b993e9ec199595971f9dc0e`
- Rekor entry log index: `2471985405`
- Rekor integrated time: `1786760371`
- Secondary public-key SHA-256:
  `8e072c1c7d054a1509a01104f6299f4d682a2868b30054aed050ae4dcf560dbc`
- Secondary signature SHA-256:
  `83c0507c42c812bb63d5302bad5390b8da51420ce48479c5cd4c8d03d44a1e65`
- Signed-entry timestamp SHA-256:
  `fd066ad8b31863e313008d59d758d2729fcb3f03d03b8af6bb01c20df8b4b8e6`
- Inclusion-proof SHA-256:
  `f0a33f10e92bd4f6c2fa249fdce9419ffcc3318165c09ab2cb8583572fd82ef7`
- Checkpoint SHA-256:
  `9a5ea124912b84d478b3655d5cd689017c327333a752cf5697327cfb70076871`
- Canonical evidence-manifest SHA-256:
  `0ccc39a48217524efe681d984fea41f4f1afe1d3fa1be3177fa4598e6ddf8a41`
- DigiCert RFC 3161 proof SHA-256:
  `e99454ea3af1f0a9fa1ce20d66e93afd7cdc1cc4be50ef4477598e037eec3d3a`
- DigiCert serial: `0xEF41E06E6F4E906BF9CF7FCC31910CA6`
- DigiCert timestamp: `Aug 15 02:22:46 2026 GMT`
- RFC 3161 verification: `Verification: OK` against the system trust store

Rekor preserved the externally returned entry index and the inclusion proof's
internal tree index as separate values. The raw signed entry, SET, proof, and
checkpoint are retained, and the exact-head verifier binds their digests.

## Retained evidence

Complete package:
`/sn8100/runs/mcloving/rel001-ceremony-20260814T134056Z/v2`

- Self-excluding inventory: 47 files
- Evidence-package manifest SHA-256:
  `094276689d6cec9fbb63b1abd51f5b9a3f9b588c52e32be5e264fb20822af237`
- Closure-summary SHA-256:
  `91d0ad157f37770a97e05ab72ebe4d089576e2eb67842c5d047890b3e0d21452`
- Verification-receipt SHA-256:
  `6c11cc651b1f4daab6647b43947a433ae565b1a11dfa09cf5cf48e9f789f139f`
- Private-key marker scan: clean
- Private-key hard-link scan: clean

The package contains the exact protected-main artifact and extracted builder
outputs, authenticated CI receipts, signed envelope, public keys, Rekor entry
and inclusion material, RFC 3161 request/response/verification, pending
supplemental OpenTimestamps proof, final verification policy and receipt, and
the deterministic inventory. It contains no private key.
