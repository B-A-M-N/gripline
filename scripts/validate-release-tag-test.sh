#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validator="$repo_dir/scripts/validate-release-tag.sh"

for tag in v0.1.0 v1.2.3 v10.20.30-beta.1 v2.0.0-rc.2; do
	bash "$validator" "$tag" >/dev/null
done

for tag in v1.2 v1.2.3.4 v01.2.3 v1.02.3 v1.2.03 v1.2.3-beta v1.2.3-rc.0 v1.2.3-alpha.1 1.2.3 v1.2.3+build.1 v1.2.3\  v1.2.3/extra; do
	if bash "$validator" "$tag" >/dev/null 2>&1; then
		echo "release tag fixture unexpectedly accepted: $tag" >&2
		exit 1
	fi
done

echo "release tag fixtures: acceptance and rejection passed"
