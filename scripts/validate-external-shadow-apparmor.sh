#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
profile="${repo_root}/deploy/apparmor/mcloving-external-shadow-replay"

if ! command -v apparmor_parser >/dev/null 2>&1; then
  printf 'required command is missing: apparmor_parser\n' >&2
  exit 1
fi

profile_names="$(apparmor_parser --skip-kernel-load --skip-cache --names "${profile}")"
if [[ "${profile_names}" != "mcloving-external-shadow-replay" ]]; then
  printf 'unexpected AppArmor profile names: %s\n' "${profile_names}" >&2
  exit 1
fi

grep -Fxq 'profile mcloving-external-shadow-replay flags=(unconfined) {' "${profile}"
grep -Fxq '  deny network,' "${profile}"
if grep -Evq '^[[:space:]]*(#.*)?$|^abi <abi/4\.0>,$|^#include <tunables/global>$|^profile mcloving-external-shadow-replay flags=\(unconfined\) \{$|^  deny network,$|^}$' "${profile}"; then
  printf 'shadow profile contains authority outside its network denial boundary\n' >&2
  exit 1
fi

printf 'External shadow AppArmor policy validation passed.\n'
