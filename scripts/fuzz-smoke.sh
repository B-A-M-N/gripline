#!/usr/bin/env bash
set -euo pipefail

fuzz_time="${GRIPLINE_FUZZ_TIME:-5s}"

if [[ -z "${GOCACHE:-}" ]]; then
  fuzz_cache_root="${RUNNER_TEMP:-/tmp}/gripline-fuzz-gocache"
  mkdir -p "$fuzz_cache_root"
  export GOCACHE="$fuzz_cache_root"
fi

go test ./verify -run '^$' -fuzz '^FuzzVerifyAssertionEnvelope$' -fuzztime="$fuzz_time"
go test ./verify -run '^$' -fuzz '^FuzzLoadKeySet$' -fuzztime="$fuzz_time"
go test ./adapter/usage -run '^$' -fuzz '^FuzzJSONProviderUsage$' -fuzztime="$fuzz_time"
go test ./internal/ingress -run '^$' -fuzz '^FuzzTrustedProxyForwardedFor$' -fuzztime="$fuzz_time"
go test ./internal/pseudonym -run '^$' -fuzz '^FuzzVersionedPseudonym$' -fuzztime="$fuzz_time"
go test ./internal/policy -run '^$' -fuzz '^FuzzAuthenticatedPolicyEnvelope$' -fuzztime="$fuzz_time"
go test ./internal/proxy -run '^$' -fuzz '^FuzzPathAndEncodingNormalization$' -fuzztime="$fuzz_time"
go test ./cmd/gripline -run '^$' -fuzz '^FuzzAdminJSONDecoder$' -fuzztime="$fuzz_time"
