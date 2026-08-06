#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
profile="${repo_root}/deploy/apparmor/mcloving-source-acquirer"

if ! command -v apparmor_parser >/dev/null 2>&1; then
  printf 'required command is missing: apparmor_parser\n' >&2
  exit 1
fi

profile_names="$(apparmor_parser --skip-kernel-load --skip-cache --names "${profile}")"
if [[ "${profile_names}" != "mcloving-source-acquirer" ]]; then
  printf 'unexpected AppArmor profile names: %s\n' "${profile_names}" >&2
  exit 1
fi

grep -Fxq 'profile mcloving-source-acquirer flags=(unconfined) {' "${profile}"
grep -Fxq '  userns create,' "${profile}"
if grep -Eq '^[[:space:]]*(capability|change_profile|mount|pivot_root|ptrace|signal)[[:space:]]' "${profile}"; then
  printf 'source-acquirer profile contains authority beyond userns creation\n' >&2
  exit 1
fi

printf 'Source-acquirer AppArmor policy validation passed.\n'
