#!/usr/bin/env bash
# Foundation `secrets`: the pinned gitleaks image over the checkout, as the
# lane runs it (rootless podman here instead of the runner's docker). The
# sealed acquirer publishes the tree at the commit without its history, so
# the scan is of the tree (`--no-git`) where Foundation scans the commits;
# the same rules and the same pinned image decide.
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane secrets
# The scan runs from the tree root with a relative source so the
# repository's .gitleaks.toml path allowlists match as they do in Foundation.
podman run --rm \
  --volume "${dogfood_repo}:/repo:ro,Z" --workdir /repo \
  "${MCLOVING_GITLEAKS_IMAGE}" \
  detect --source . --no-banner --redact --verbose --no-git
