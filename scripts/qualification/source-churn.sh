#!/usr/bin/env bash
set -euo pipefail

# Security qualification for first-seen source cardinality. The steady-state
# capacity gate intentionally warms identities; this gate drives hostile
# source churn, authenticated first-seen sources, overflow assignment, key
# rotation overlap, and reference-aware alias maintenance separately.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "$repo_dir/scripts/qualification/assertions.sh"
work_dir="$(mktemp -d)"
evidence_file="$work_dir/source-churn.json"
result_dir="${GRIPLINE_QUALIFICATION_RESULT_DIR:-$repo_dir/qualification-results}"
cleanup() {
	rm -rf "$work_dir"
}
trap cleanup EXIT

invalid_sources="${GRIPLINE_SOURCE_CHURN_INVALID_SOURCES:-10000}"
authenticated_sources="${GRIPLINE_SOURCE_CHURN_AUTHENTICATED_SOURCES:-16}"
source_scope_limit="${GRIPLINE_SOURCE_CHURN_SOURCE_SCOPE_LIMIT:-16}"
preauth_max_sources="${GRIPLINE_SOURCE_CHURN_PREAUTH_MAX_SOURCES:-64}"
adaptive_subject_bound="${GRIPLINE_SOURCE_CHURN_ADAPTIVE_MAX_SUBJECTS:-65536}"
adaptive_key_bound="${GRIPLINE_SOURCE_CHURN_ADAPTIVE_MAX_KEYS:-256}"
duration="${GRIPLINE_SOURCE_CHURN_DURATION:-30s}"
if ! [[ "$invalid_sources" =~ ^[1-9][0-9]*$ && "$authenticated_sources" =~ ^[1-9][0-9]*$ && "$source_scope_limit" =~ ^[1-9][0-9]*$ && "$preauth_max_sources" =~ ^[1-9][0-9]*$ && "$adaptive_subject_bound" =~ ^[1-9][0-9]*$ && "$adaptive_key_bound" =~ ^[1-9][0-9]*$ ]]; then
	echo "source churn qualification: numeric bounds must be positive integers" >&2
	exit 2
fi

GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN=1 \
GRIPLINE_CLUSTER_HARNESS_INVALID_SOURCES="$invalid_sources" \
GRIPLINE_CLUSTER_HARNESS_AUTHENTICATED_SOURCES="$authenticated_sources" \
GRIPLINE_CLUSTER_HARNESS_SOURCE_SCOPE_LIMIT="$source_scope_limit" \
GRIPLINE_CLUSTER_HARNESS_PREAUTH_MAX_SOURCES="$preauth_max_sources" \
GRIPLINE_CLUSTER_HARNESS_ADAPTIVE_MAX_SUBJECTS="$adaptive_subject_bound" \
GRIPLINE_CLUSTER_HARNESS_ADAPTIVE_MAX_KEYS="$adaptive_key_bound" \
GRIPLINE_SOAK_MAX_CONNS="${GRIPLINE_SOURCE_CHURN_MAX_CONNS:-32}" \
GRIPLINE_CLUSTER_HARNESS_SOURCE_CHURN_EVIDENCE_FILE="$evidence_file" \
GRIPLINE_CLUSTER_SOAK_LOAD_MODE=capacity \
GRIPLINE_CLUSTER_SOAK_EXTERNAL_MAINTENANCE=1 \
GRIPLINE_CLUSTER_SOAK_EXTERNAL_MAINTENANCE_INTERVAL=1 \
GRIPLINE_SOAK_RETENTION_WINDOW=1m \
GRIPLINE_SOAK_SOURCE_ALIAS_RETENTION=1m \
GRIPLINE_SOAK_RUNTIME_MAINTENANCE_INTERVAL=5s \
bash "$repo_dir/scripts/qualification/soak.sh" --duration "$duration" --workers "$authenticated_sources"

[[ -s "$evidence_file" ]] || { echo "source churn qualification: structured evidence is missing" >&2; exit 1; }
measurements="$(python3 - "$evidence_file" "$invalid_sources" "$authenticated_sources" "$source_scope_limit" "$preauth_max_sources" <<'PY'
import json
import sys

path, invalid_expected, authenticated_expected, scope_bound, preauth_bound = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)
for name in (
    "invalid_sources", "aliases_before", "aliases_after_invalid",
    "adaptive_rows_after_invalid", "preauth_source_table_entries_peak",
    "adaptive_subjects_after_invalid", "adaptive_keys_after_invalid",
    "adaptive_baselines_after_invalid", "adaptive_subject_bound",
    "adaptive_key_bound",
    "preauth_source_table_bound", "backend_hits_from_invalid",
    "authenticated_aliases_created", "authenticated_source_requests",
    "authenticated_source_failures", "source_scope_bound", "source_scopes_peak",
    "source_scope_overflows", "rotation_source_scopes_before",
    "rotation_source_scopes_after", "stale_aliases_before_maintenance",
    "stale_aliases_after_maintenance", "source_resolution_failures",
    "authority_timeouts",
):
    if name not in value or isinstance(value[name], bool) or not isinstance(value[name], int):
        raise SystemExit(f"source churn measurement is missing or invalid: {name}")
invalid_expected = int(invalid_expected)
authenticated_expected = int(authenticated_expected)
scope_bound = int(scope_bound)
preauth_bound = int(preauth_bound)
if value["invalid_sources"] != invalid_expected:
    raise SystemExit("source churn invalid source count does not match the requested adversarial load")
if value["authenticated_source_requests"] != authenticated_expected or value["authenticated_source_failures"] != 0:
    raise SystemExit("authenticated first-seen source requests were not all successful")
if value["source_scope_bound"] != scope_bound or value["source_scopes_peak"] > scope_bound:
    raise SystemExit("source scope cardinality exceeded its configured bound")
if value["preauth_source_table_bound"] != preauth_bound or value["preauth_source_table_entries_peak"] > preauth_bound + 64:
    raise SystemExit("pre-auth source state exceeded its bounded overflow allowance")
if value["adaptive_rows_after_invalid"] != (
    value["adaptive_subjects_after_invalid"]
    + value["adaptive_keys_after_invalid"]
    + value["adaptive_baselines_after_invalid"]
):
    raise SystemExit("adaptive row measurement does not match its component counts")
if value["adaptive_subject_bound"] != 65536 or value["adaptive_key_bound"] != 256:
    raise SystemExit("source churn adaptive bounds do not match the distributed detector contract")
if value["adaptive_subjects_after_invalid"] > value["adaptive_subject_bound"]:
    raise SystemExit("invalid source churn exceeded its adaptive subject bound")
if value["adaptive_keys_after_invalid"] > value["adaptive_subject_bound"] * value["adaptive_key_bound"]:
    raise SystemExit("invalid source churn exceeded its adaptive key bound")
if value["adaptive_baselines_after_invalid"] > value["adaptive_subject_bound"]:
    raise SystemExit("invalid source churn exceeded its adaptive baseline bound")
if value["aliases_before"] != 0 or value["aliases_after_invalid"] != 0:
    raise SystemExit("invalid source churn created durable aliases")
if value["backend_hits_from_invalid"] != 0:
    raise SystemExit("invalid source churn reached the backend")
if value["authenticated_aliases_created"] < authenticated_expected:
    raise SystemExit("authenticated source churn did not create one canonical identity per source")
if value["source_scope_overflows"] < 1:
    raise SystemExit("source scope saturation did not exercise overflow assignment")
if value["rotation_source_scopes_before"] != value["rotation_source_scopes_after"]:
    raise SystemExit("pseudonym rotation changed source-scope cardinality")
if value["stale_aliases_before_maintenance"] != 1 or value["stale_aliases_after_maintenance"] != 0:
    raise SystemExit("source alias maintenance did not reclaim the stale unreferenced identity")
if value["source_resolution_failures"] != 0 or value["authority_timeouts"] != 0:
    raise SystemExit("source churn observed authority failures or timeouts")
print(json.dumps(value, separators=(",", ":")))
PY
)"
mkdir -p "$result_dir"
cp "$evidence_file" "$result_dir/source-churn-telemetry.json"
emit_qualification_assertions \
	'{"invalid_source_misses_read_only":true,"preauth_state_bounded":true,"backend_isolated":true,"authenticated_sources_registered":true,"source_scope_overflow_bounded":true,"rotation_overlap_continuous":true,"stale_alias_maintenance_succeeded":true}' \
	"$measurements"
echo "source churn qualification: invalid-source spray, authenticated first-seen sources, overflow, rotation overlap, and alias maintenance passed"
