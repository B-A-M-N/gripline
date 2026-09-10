#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
scanner="$repo_dir/scripts/qualification/scan-evidence.py"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

python3 - "$work_dir" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
cases = {
    "private-key": ("artifact.txt", b"-----BEGIN RSA PRIVATE KEY-----\nsecret\n"),
    "dsn": ("artifact.txt", b"postgres://gripline:password@db.example/gripline"),
    "bearer": ("artifact.txt", b"Authorization: Bearer bearer-secret-value"),
    "nested-json": ("artifact.json", b'{"outer":{"access_token":"not-redacted"}}'),
    "sensitive-json": ("artifact.json", b'{"client_secret":"not-redacted","private_key":"not-redacted"}'),
    "credential-value": ("artifact.json", b'{"credential_value":"not-redacted"}'),
}
for name, (relative, content) in cases.items():
    case = root / name
    case.mkdir()
    (case / relative).write_bytes(content)
clean = root / "clean"
clean.mkdir()
(clean / "artifact.json").write_text(
    '{"credential":"credential-identifier","access_token":"<redacted>","nested":{"secret":"redacted"}}\n',
    encoding="utf-8",
)
(clean / "log.txt").write_text("Authorization: Bearer <redacted>\n", encoding="utf-8")
(root / "denylist.txt").write_text("fixture-secret\n", encoding="utf-8")
deny = root / "denylist-case"
deny.mkdir()
(deny / "artifact.txt").write_text("fixture-secret\n", encoding="utf-8")
PY

for case in private-key dsn bearer nested-json sensitive-json credential-value; do
	if python3 "$scanner" "$work_dir/$case" >/dev/null 2>&1; then
		echo "scan-evidence test: $case was accepted" >&2
		exit 1
	fi
done
python3 "$scanner" "$work_dir/clean" >/dev/null
if python3 "$scanner" "$work_dir/denylist-case" "$work_dir/denylist.txt" >/dev/null 2>&1; then
	echo "scan-evidence test: denylisted literal was accepted" >&2
	exit 1
fi
echo "scan-evidence test: rejection and redaction controls passed"
