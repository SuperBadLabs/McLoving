#!/usr/bin/env bash
# CTRL-007 scoped proof through the actual deployment environment guard.
set -euo pipefail
umask 077
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
case_root="$(mktemp -d "${TMPDIR:-/tmp}/mcloving-nat64-guard.XXXXXX")"
trap 'rm -rf -- "${case_root}"' EXIT
chmod 0700 "${case_root}"
helpers="${case_root}/.local/libexec/mcloving/helpers"
mkdir -p "${helpers}"
cp "${repo_root}/deploy/bin/mcloving-env-guard" "${repo_root}/deploy/bin/mcloving-deploy-lib.sh" "${helpers}/"
chmod 0755 "${helpers}/mcloving-env-guard"
python3 - "${repo_root}" "${case_root}" <<'CONTRACT'
import pathlib, sys
repo, root = map(pathlib.Path, sys.argv[1:])
text = (repo/'deploy/env/controller.env.example').read_text().replace('/home/mcloving',str(root))
for old,new in {
    '__SET_ME_POSTGRES_SUPERUSER_PASSWORD__':'fixture-migration',
    '__SET_ME_TENANT_PASSWORD__':'fixture-runtime',
    '__SET_ME_API_BEARER_TOKEN_MINIMUM_32_BYTES__':'ctrl007-guard-api-token-at-least-32bytes',
    '__SET_ME_DISTINCT_ARTIFACT_TOKEN_MINIMUM_32_BYTES__':'ctrl007-guard-artifact-token-at-least-32bytes',
    '__SET_ME_ORGANIZATION_UUID__':'7bbaf4ac-1f1b-4182-9574-3c306e286585',
}.items(): text=text.replace(old,new)
for line in text.splitlines():
    if line.startswith(('MCLOVING_AGENT_SERVER_CERT_PATH=', 'MCLOVING_AGENT_SERVER_KEY_PATH=',
                        'MCLOVING_AGENT_CLIENT_CA_PATH=', 'MCLOVING_AGENT_IDENTITY_BINDINGS_PATH=')):
        path=pathlib.Path(line.split('=',1)[1]); path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text('fixture-file\n'); path.chmod(0o600)
(root/'controller.env').write_text(text); (root/'controller.env').chmod(0o600)
CONTRACT
contract="${case_root}/controller.env"
guard="${helpers}/mcloving-env-guard"
env -i PATH="${PATH}" HOME="${HOME}" "${guard}" controller "${contract}" > "${case_root}/unset.log"
cp "${contract}" "${case_root}/unset.env"
for width in 32 40 48 56 64 96; do
  cp "${case_root}/unset.env" "${contract}"
  printf 'MCLOVING_NOTIFICATION_NAT64_PREFIXES=2606:4700::/%s\n' "${width}" >> "${contract}"
  env -i PATH="${PATH}" HOME="${HOME}" "${guard}" controller "${contract}" > "${case_root}/valid-${width}.log"
done
for invalid in '' bad-prefix 2606:4700::/72 2606:4700::1/96 fc00::/96 \
  2001:db8::/32 2002:808::/32 2606:4700::/96, \
  2606:4700::/32,2606:4700::/96; do
  cp "${case_root}/unset.env" "${contract}"
  printf 'MCLOVING_NOTIFICATION_NAT64_PREFIXES=%s\n' "${invalid}" >> "${contract}"
  if env -i PATH="${PATH}" HOME="${HOME}" "${guard}" controller "${contract}" > "${case_root}/invalid.log" 2>&1; then
    echo "guard accepted malformed NAT64 policy: ${invalid}" >&2; exit 1
  fi
  grep -q MCLOVING_NOTIFICATION_NAT64_PREFIXES "${case_root}/invalid.log"
done
cp "${case_root}/unset.env" "${contract}"
if env -i PATH="${PATH}" HOME="${HOME}" MCLOVING_NOTIFICATION_NAT64_PREFIXES=2606:4700::/96 \
  "${guard}" controller "${contract}" > "${case_root}/ambient.log" 2>&1; then
  echo 'guard accepted ambient NAT64 policy absent from contract' >&2; exit 1
fi
grep -q 'MCLOVING_NOTIFICATION_NAT64_PREFIXES.*outside its contract' "${case_root}/ambient.log"
printf 'MCLOVING_NOTIFICATION_NAT64_PREFIXES=2606:4700::/96\n' >> "${contract}"
# Compose the actual service environment from the fixture contract, then
# either remove or override just this policy key. The guard is ExecStartPre.
for variant in matching dropped changed; do
  result=0
  env -i PATH="${PATH}" HOME="${HOME}" bash -c '
    set -a
    . "$1"
    set +a
    case "$3" in
      dropped) unset MCLOVING_NOTIFICATION_NAT64_PREFIXES ;;
      changed) export MCLOVING_NOTIFICATION_NAT64_PREFIXES=2606:4701::/96 ;;
    esac
    export INVOCATION_ID=ctrl007-guard SYSTEMD_EXEC_PID=$$
    exec "$2" controller "$1"
  ' bash "${contract}" "${guard}" "${variant}" > "${case_root}/${variant}.log" 2>&1 || result=$?
  if [[ "${variant}" == matching ]]; then
    [[ "${result}" == 0 ]] || { cat "${case_root}/${variant}.log" >&2; exit 1; }
  else
    [[ "${result}" != 0 ]] || { echo "guard accepted ${variant} NAT64 policy" >&2; exit 1; }
    grep -q MCLOVING_NOTIFICATION_NAT64_PREFIXES "${case_root}/${variant}.log"
  fi
done
printf 'CTRL-007 notification NAT64 deployment guard: unset,6 valid widths,9 malformed,ambient,matching,dropped,changed passed\n'
