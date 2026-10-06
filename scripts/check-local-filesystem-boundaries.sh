#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test -p voidb-core local_filesystem_boundary_
cargo test -p voidb-plugin-ssh local_filesystem_boundary_
cargo test -p voidb-plugin-s3 local_filesystem_boundary_
cargo test -p voidb-cli local_filesystem_boundary_
cargo test -p voidb-cli default_grant_fails_closed_on_non_read_only_capabilities

printf 'local filesystem boundary checks passed\n'
