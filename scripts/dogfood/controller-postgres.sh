#!/usr/bin/env bash
# Foundation `controller-postgres`: the existing local mirror of the lane,
# which provisions its own PostgreSQL container and runs the suites inside
# the pinned Rust image.
# shellcheck source=lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dogfood_lane controller-postgres
bash scripts/test-controller-postgres.sh
