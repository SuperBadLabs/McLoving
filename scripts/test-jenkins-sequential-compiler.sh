#!/usr/bin/env bash
# Compile/admission boundary tests; no Jenkinsfile or shell workload execution.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(cd -- "$script_dir/.." && pwd -P)
(
  cd "$repo_root/compat/jenkins-worker"
  timeout 60 clojure -M:sequential-test
)
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-jenkins-sequential-launcher.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-jenkins-sequential-retained.py"
PYTHONDONTWRITEBYTECODE=1 python3 "$repo_root/scripts/test-jenkins-sequential-contained.py" \
  --verify-retained "$repo_root/docs/evidence/jcomp-002-compiler-v2"
