#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: validate-release-tag.sh TAG" >&2
	exit 2
fi

tag=$1
if [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(beta|rc)\.[1-9][0-9]*)?$ ]]; then
	echo "release tag accepted: $tag"
	exit 0
fi

echo "release tag rejected: $tag (expected vMAJOR.MINOR.PATCH[-beta.N|-rc.N])" >&2
exit 1
