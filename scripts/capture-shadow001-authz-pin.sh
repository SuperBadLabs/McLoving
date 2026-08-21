#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 NEW_AUTHZ_PIN" >&2
  exit 64
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for command in chmod git id ln mktemp realpath rg rm sed ssh stat sync; do
  command -v "${command}" >/dev/null || {
    echo "required command is unavailable: ${command}" >&2
    exit 69
  }
done

output_parent="$(realpath -e "$(dirname -- "$1")")"
output_leaf="$(basename -- "$1")"
if [[ ! "${output_leaf}" =~ ^[a-z0-9][a-z0-9._-]*\.sha256$ || -e "$1" ]]; then
  echo "authorization pin must be one new lowercase .sha256 file" >&2
  exit 73
fi
if [[ "$(stat -c %u "${output_parent}")" -ne "$(id -u)" ||
      "$(stat -c %a "${output_parent}")" != 700 ]]; then
  echo "authorization-pin parent must be owned by the caller with mode 0700" >&2
  exit 77
fi
if [[ -n "$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "authorization capture requires a clean exact-head source tree" >&2
  exit 78
fi
output="${output_parent}/${output_leaf}"
staging="$(mktemp "${output_parent}/.shadow001-authz-pin.XXXXXX")"
chmod 0600 "${staging}"
linked=false
cleanup() {
  if [[ "${linked}" == true ]]; then
    rm -f -- "${output}"
  fi
  if [[ -n "${staging}" ]]; then
    rm -f -- "${staging}"
  fi
}
trap cleanup EXIT
umask 077

ssh -o BatchMode=yes srikanth@mario 'python3 -c '"'"'
import base64, http.cookiejar, json, sys, urllib.parse, urllib.request
base = "http://100.127.170.90:18080"
password = open(
    "/home/srikanth/jenkins-oracle-228/runner/admin-password",
    encoding="utf-8",
).read().strip()
authorization = "Basic " + base64.b64encode(
    ("oracle-admin:" + password).encode()
).decode()
jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
crumb_request = urllib.request.Request(
    base + "/crumbIssuer/api/json",
    headers={"Authorization": authorization},
)
crumb = json.load(opener.open(crumb_request, timeout=15))
payload = urllib.parse.urlencode({"script": sys.stdin.read()}).encode()
headers = {
    "Authorization": authorization,
    "Content-Type": "application/x-www-form-urlencoded",
    crumb["crumbRequestField"]: crumb["crumb"],
}
response = opener.open(
    urllib.request.Request(base + "/scriptText", data=payload, headers=headers),
    timeout=30,
).read().decode("utf-8", "replace")
marker = next(
    (line for line in response.splitlines() if line.startswith("SHADOW001_AUTHZ=")),
    None,
)
if marker is None:
    raise SystemExit("bounded Jenkins authorization marker is absent")
print(marker)
'"'"'' <"${repo_root}/migration/shadow-runtime-v1/authz-probe.groovy" \
  | sed -n 's/^SHADOW001_AUTHZ=//p' >"${staging}"
if [[ "$(stat -c %h "${staging}")" -ne 1 ]] ||
   ! rg --quiet --line-regexp '[0-9a-f]{64}' \
     "${staging}"; then
  echo "authorization pin publication failed validation" >&2
  exit 1
fi
sync -f "${staging}"
ln "${staging}" "${output}"
linked=true
rm -f -- "${staging}"
staging=''
sync -d "${output_parent}"
linked=false
trap - EXIT
printf '%s\n' 'authz_generation_pin_created=true'
