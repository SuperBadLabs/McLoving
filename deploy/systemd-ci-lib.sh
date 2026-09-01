#!/usr/bin/env bash
# Shared host-input resolver for the service-managed deployment proof.
#
# GitHub's Ubuntu image installs a checksum-pinned static Podman bundle below
# /usr/local, while Ubuntu's podman deb installs the same command/generator
# topology below /usr.  Do not search for an arbitrary Quadlet executable: the
# command systemd will ultimately invoke and its generator must come from one
# explicit, version-matched vendor layout.

mcloving_ci_host_fail() {
  echo "systemd CI host preflight: $1" >&2
  return 1
}

mcloving_ci_require_root_input() {
  local path="$1" kind="$2" mode_owner mode owner
  [[ -e "${path}" || -L "${path}" ]] \
    || { mcloving_ci_host_fail "required ${kind} is absent: ${path}"; return 1; }
  if [[ -L "${path}" ]]; then
    owner="$(stat -c '%u' "${path}")" \
      || { mcloving_ci_host_fail "cannot lstat ${kind}: ${path}"; return 1; }
    [[ "${owner}" == 0 ]] \
      || { mcloving_ci_host_fail "${kind} symlink is owned by uid ${owner}, not root: ${path}"; return 1; }
    return 0
  fi
  mode_owner="$(stat -Lc '%a %u' "${path}")" \
    || { mcloving_ci_host_fail "cannot stat ${kind}: ${path}"; return 1; }
  mode="${mode_owner%% *}"
  owner="${mode_owner##* }"
  [[ "${owner}" == 0 ]] \
    || { mcloving_ci_host_fail "${kind} is owned by uid ${owner}, not root: ${path}"; return 1; }
  (( (8#${mode} & 8#022) == 0 )) \
    || { mcloving_ci_host_fail "${kind} is group/world writable (mode ${mode}): ${path}"; return 1; }
}

mcloving_ci_select_podman_generator() {
  local command_path expected_target quadlet_version path
  local generator generator_dir
  command_path="$(command -v podman 2>/dev/null || true)"
  [[ -n "${command_path}" ]] \
    || { mcloving_ci_host_fail "podman is absent from PATH"; return 1; }
  command_path="$(readlink -f "${command_path}")" \
    || { mcloving_ci_host_fail "cannot resolve the podman command"; return 1; }

  case "${command_path}" in
    /usr/local/bin/podman)
      MCLOVING_CI_PODMAN_GENERATOR=/usr/local/lib/systemd/user-generators/podman-user-generator
      expected_target=/usr/local/libexec/podman/quadlet
      MCLOVING_CI_PODMAN_TRUST_PATHS=(
        / /usr /usr/local /usr/local/bin "${command_path}"
        /usr/local/lib /usr/local/lib/systemd
        /usr/local/lib/systemd/user-generators
        "${MCLOVING_CI_PODMAN_GENERATOR}"
        /usr/local/libexec /usr/local/libexec/podman "${expected_target}"
      )
      ;;
    /usr/bin/podman)
      MCLOVING_CI_PODMAN_GENERATOR=/usr/lib/systemd/user-generators/podman-user-generator
      expected_target=/usr/libexec/podman/quadlet
      MCLOVING_CI_PODMAN_TRUST_PATHS=(
        / /usr /usr/bin "${command_path}"
        /usr/lib /usr/lib/systemd /usr/lib/systemd/user-generators
        "${MCLOVING_CI_PODMAN_GENERATOR}"
        /usr/libexec /usr/libexec/podman "${expected_target}"
      )
      ;;
    *)
      mcloving_ci_host_fail "unsupported podman command layout: ${command_path}"
      return 1
      ;;
  esac

  MCLOVING_CI_PODMAN_COMMAND="${command_path}"
  MCLOVING_CI_QUADLET="${expected_target}"
  [[ -L "${MCLOVING_CI_PODMAN_GENERATOR}" ]] \
    || { mcloving_ci_host_fail "packaged Podman user generator is not a symlink: ${MCLOVING_CI_PODMAN_GENERATOR}"; return 1; }
  [[ "$(readlink -f "${MCLOVING_CI_PODMAN_GENERATOR}")" == "${expected_target}" ]] \
    || { mcloving_ci_host_fail "Podman user generator does not resolve to ${expected_target}: ${MCLOVING_CI_PODMAN_GENERATOR}"; return 1; }
  [[ -f "${expected_target}" && -x "${expected_target}" ]] \
    || { mcloving_ci_host_fail "Quadlet target is not a regular executable: ${expected_target}"; return 1; }

  for path in "${MCLOVING_CI_PODMAN_TRUST_PATHS[@]}"; do
    mcloving_ci_require_root_input "${path}" "Podman/Quadlet input" || return 1
  done

  for generator_dir in /run/systemd/user-generators /etc/systemd/user-generators; do
    generator="${generator_dir}/podman-user-generator"
    [[ ! -e "${generator}" && ! -L "${generator}" ]] \
      || { mcloving_ci_host_fail "higher-precedence Podman user generator exists: ${generator}"; return 1; }
  done
  for generator_dir in /usr/local/lib/systemd/user-generators /usr/lib/systemd/user-generators; do
    generator="${generator_dir}/podman-user-generator"
    [[ ! -e "${generator}" && ! -L "${generator}" ]] && continue
    [[ "${generator}" == "${MCLOVING_CI_PODMAN_GENERATOR}" ]] \
      || { mcloving_ci_host_fail "second Podman user generator would make vendor selection ambiguous: ${generator}"; return 1; }
  done

  quadlet_version="$("${expected_target}" --version | awk '{print $NF}')" \
    || { mcloving_ci_host_fail "cannot read Quadlet version from ${expected_target}"; return 1; }
  [[ -n "${quadlet_version}" ]] \
    || { mcloving_ci_host_fail "Quadlet returned an empty version"; return 1; }
  MCLOVING_CI_QUADLET_VERSION="${quadlet_version}"
}

mcloving_ci_print_podman_generator() {
  local podman_sha quadlet_sha
  podman_sha="$(sha256sum "${MCLOVING_CI_PODMAN_COMMAND}" | awk '{print $1}')"
  quadlet_sha="$(sha256sum "${MCLOVING_CI_QUADLET}" | awk '{print $1}')"
  echo "controlled Podman input: command=${MCLOVING_CI_PODMAN_COMMAND} sha256=${podman_sha} (version deferred until cold start)"
  echo "controlled Quadlet input: generator=${MCLOVING_CI_PODMAN_GENERATOR} target=${MCLOVING_CI_QUADLET} version=${MCLOVING_CI_QUADLET_VERSION} sha256=${quadlet_sha}"
}
