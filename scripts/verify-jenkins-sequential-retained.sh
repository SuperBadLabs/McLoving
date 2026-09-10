#!/usr/bin/env bash
# Verify retained measured observations offline; do not launch workloads or admission.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
paired="$repo_root/migration/jenkins-sequential-differential-v2/campaign-v1"
corpus="$repo_root/migration/jenkins-sequential-corpus-v2/campaign-v1"

# Fixed independent publication pins, replaced only with reviewed real receipts.
base_commit='01137b54b8fbefdc0deb0214a5d4d8979a773575'
retention_sha256='8c1ae8c492698a9b4e74e5c704ab410ac4c118556f9a8b96f6f693b0f6370510'
corpus_sha256='0332856ee84aa5035dd65a2ad36bb5c83d17c4f88a77eaad99b37ce67ab20592'
[[ "$base_commit" =~ ^[0-9a-f]{40}$ ]]
[[ "$retention_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$corpus_sha256" =~ ^[0-9a-f]{64}$ ]]

timeout 600 python3 -I "$repo_root/scripts/jcomp003/verify-retained.py" "$paired" \
  --retention-sha256 "$retention_sha256" --base-commit "$base_commit" \
  --repository "$repo_root"
timeout 120 python3 -I "$repo_root/scripts/classify-jenkins-sequential-corpus.py" verify "$corpus" \
  --campaign-sha256 "$corpus_sha256"
