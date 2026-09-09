#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GRIPLINE_PERIMETER_MODE=clustered exec bash "$repo_dir/scripts/qualification/perimeter.sh" "$@"
