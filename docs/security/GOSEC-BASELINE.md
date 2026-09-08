# Gosec baseline

The scheduled security workflow runs gosec v2.22.8 with no global rule
exclusions. The repository currently has only the following reviewed,
line-local `// #nosec` exceptions. Each exception is adjacent to the specific
conversion, fixture, or configuration boundary it justifies:

| Rule | Line-local exception rationale |
|---|---|
| G101 | Demo credentials and capability/column identifiers are fixtures or names, not secrets. |
| G104 | Cleanup/close errors are intentionally best-effort on already-failing paths; authoritative sync/write errors are returned. |
| G112 | The only finding is an in-process demo server; the deployable listener has bounded read/header/idle timeouts. |
| G115 | Values are bounded before conversion or are monotonic counters crossing fixed persistence integer types. |
| G304 | Paths are operator/deployment inputs and are cleaned or validated at their authority boundary. |
| G306 | Evidence/audit files use intentionally documented group-readable permissions where configured; key material uses stricter modes. |
| G402 | TLS 1.2 is the explicit minimum compatibility floor; production examples require TLS 1.3 and no disable-verification path exists. |

The workflow command is `go run github.com/securego/gosec/v2/cmd/gosec@v2.22.8
-quiet ./...`. A new finding fails CI; it is not added to a global exclusion.
