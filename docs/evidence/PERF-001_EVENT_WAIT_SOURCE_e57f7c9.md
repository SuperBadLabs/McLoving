# PERF-001 reviewed-source signature carrier

PR #110 was squash-merged. Its protected-main commit
`0f6499ff082f7d7dd7c85831ed4659bc3923dce6` retains the reviewed tree, but the
reviewed signed source commit is not an ancestor of `main`. These files retain
the minimum offline material needed to reconstruct and verify that exact
source identity without relying on a temporary clone, bundle, or GitHub's pull
request object retention.

## Bound identities

| Item | Identity |
|---|---|
| Reviewed signed source | `e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a` |
| Reviewed and merged tree | `b4d4b86b06666fd9bae9f85b8e44f426a9b227dd` |
| Protected-main squash | `0f6499ff082f7d7dd7c85831ed4659bc3923dce6` |
| Signer | `srikanth.remani@gmail.com` |
| ED25519 fingerprint | `SHA256:6cTB2VnhVlZd0WqZSzWP6UsYjYewpNL20zho8M7R1tY` |

Canonical carrier hashes:

- `PERF-001_EVENT_WAIT_SOURCE_e57f7c9.commit` — SHA-256
  `321069313da2dc340d82982f0b09a29ea3541cab1ba4a90129aa5e498797e453`.
- `PERF-001_EVENT_WAIT_SOURCE_e57f7c9.allowed_signers` — SHA-256
  `86ca3dcfdc7f18299e0b6e126fd9aa9e8711d4eff6fc973433b46045db68ac0d`.

The `.commit` file is the exact uncompressed Git commit-object payload,
including the original SSH signature. The `.allowed_signers` file contains the
public key only; it contains no private signing material.

## Offline verification

From the repository root, with Git and OpenSSH installed:

```text
test "$(git hash-object -t commit \
  docs/evidence/PERF-001_EVENT_WAIT_SOURCE_e57f7c9.commit)" = \
  e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a

verify_dir="$(mktemp -d)"
git init --bare "$verify_dir/repo.git"
git -C "$verify_dir/repo.git" hash-object -t commit -w \
  "$PWD/docs/evidence/PERF-001_EVENT_WAIT_SOURCE_e57f7c9.commit"
git -C "$verify_dir/repo.git" \
  -c gpg.format=ssh \
  -c gpg.ssh.allowedSignersFile="$PWD/docs/evidence/PERF-001_EVENT_WAIT_SOURCE_e57f7c9.allowed_signers" \
  verify-commit e57f7c9c6dcd8a1f45bc41393780d90fdbf7c13a

test "$(git show -s --format=%T \
  0f6499ff082f7d7dd7c85831ed4659bc3923dce6)" = \
  b4d4b86b06666fd9bae9f85b8e44f426a9b227dd
```

The first three commands were also executed against an otherwise empty bare
repository at publication time. Git reconstructed `e57f7c9c...` and reported a
good Git signature for `srikanth.remani@gmail.com` with the ED25519 key
identified in the table above.

The final check binds that reviewed source identity to the tree retained on
protected `main`. The source commit's parent is intentionally not claimed as
part of this compact carrier; it is not needed to verify the commit signature
or the reviewed tree.
