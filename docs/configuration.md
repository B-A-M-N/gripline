# Configuration

Gripline configuration is deployment configuration: it describes how one
process is bound, bounded, authenticated, and connected to its fixed backend.
Load it with `gripline config validate --config /path/config.json` before
starting a process. `gripline config effective --config /path/config.json
--redact` prints the validated configuration after defaults are applied; all
secret values are redacted, and redaction is enforced even if the flag is
omitted.

Durations accept Go forms such as `5s`, `10m`, and `24h`. Numeric byte/count
limits are decimal JSON integers. A zero value means “use the documented
default” only where the table says so; required security bounds fail closed.

| Property | Key | Default | Range / validation | Applies to | Scope | Lifecycle | Security effect |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Public bind | `listen` | none | required; TLS-terminated plaintext binds must be private | data plane | process | boot | Determines where inference traffic can arrive |
| TLS posture | `tls.cert_file`, `tls.key_file`, `tls.terminate_tls_upstream` | TLS cert/key required | cert/key together, or explicit private upstream termination | data plane | process | boot | Prevents accidental plaintext credential transport |
| Fixed backend | `backend.url`, `backend.trust_mode` | none | absolute `http`/`https`; persistent mode uses `mtls` or `private_network` | data plane | process | boot | Clients cannot select an upstream origin |
| Public HTTP timeouts | `server.read_timeout`, `server.write_timeout`, `server.idle_timeout`, `server.read_header_timeout` | none | required and positive; read ≥ read-header | data plane | process | boot | Bounds slowloris, stalled, and idle connections |
| Graceful drain | `server.shutdown_timeout` | `30s` | `1s` to `10m` | public/admin servers and cluster membership | process | shutdown | Gives every shutdown path one bounded liveness budget |
| Connection cap | `server.max_connections` | `4096` | positive | public listener | process | boot | Caps accepted connection state |
| Body cap | `server.max_body_bytes` | `32MiB` | non-negative | data plane | process | boot | Bounds request memory, I/O, and backend work |
| Unknown-body spool | `server.spool_dir`, `server.spool_max_bytes`, `server.spool_max_files` | `64MiB` / `64` in persistent mode | non-negative | data plane | process | boot | Bounds disk-backed chunked request work |
| Spool memory threshold | `server.spool_memory_threshold` | `256KiB` | `1` to `64MiB` bytes | data plane | process | boot | Controls per-request memory before file spooling |
| Post-auth source scope | `server.max_source_scopes`, `server.source_scope_idle` | implementation default / `10m` | non-negative | resource governor | process or shared policy state | boot | Bounds source-scoped cardinality and retention |
| Pre-auth source table | `server.preauth_max_sources`, `server.preauth_source_idle`, `server.preauth_*_per_second`, `server.preauth_max_concurrent` | bounded implementation defaults; idle `10m` | non-negative | admission guard | process | boot | Limits attacker-controlled work before authentication |
| Admin bind | `admin.listen` | disabled | numeric loopback only | control plane | process | boot | Keeps bearer-token operations off public interfaces |
| Admin connection cap | `admin.max_connections` | `256` | `1` to `1,000,000` | admin listener | process | boot | Separately limits control-plane resource use |
| Admin HTTP timeouts | `admin.read_header_timeout`, `admin.read_timeout`, `admin.write_timeout`, `admin.idle_timeout` | `10s` / `30s` / `30s` / `120s` | positive; read ≥ read-header | admin listener | process | boot | Prevents an operator endpoint from becoming an unbounded socket pool |
| Cluster authority | `authority.backend`, `authority.dsn_env`, `authority.node_id` | standalone | PostgreSQL requires DSN env, stable node ID, and no local state authority | clustered deployment | shared PostgreSQL | boot | Makes membership, credentials, lanes, audit, and readiness share one authority |
| Cluster lease | `authority.lease_ttl`, `authority.renew_every` | none in PostgreSQL mode | TTL ≥ `5s`; renew positive and below half TTL | clustered deployment | shared PostgreSQL | boot | Fences stale writers and bounds ownership expiry |
| Cluster convergence | `authority.reconcile_interval` | `1s` in PostgreSQL mode | positive | policy and crypto watchers | cluster | boot/runtime | Controls how quickly nodes observe shared lifecycle changes |
| Source alias capacity | `server.max_source_scopes`, `authority.max_source_alias_identities` | `4096` / `4096` | alias capacity must be ≥ scope capacity | clustered deployment | shared PostgreSQL | boot | Makes canonical-identity and row cardinality explicit |
| Verifier peppers | `secrets.pepper_versions` | environment fallback only | at most four positive signed-32-bit generations | credential verifier | process; lifecycle coordinated by authority | boot/rotation | Supports bounded overlap without unbounded key loading |
| Source pseudonyms | `ingress.pseudonym_key`, `ingress.pseudonym_keys` | disabled | at most four positive signed-32-bit generations | trusted ingress | process; lifecycle coordinated by authority | boot/rotation | Prevents raw source identity from entering durable state |
| Durable state | `paths.state`, `paths.signer_keyring`, `paths.audit_log` | persistent state required | ephemeral mode must be explicit; authorities cannot be split | state/control plane | process or shared backend | boot/restart | Preserves credentials, lanes, evidence, keys, and operator history |
| Provider usage | `usage.mode`, `usage.cost_mode`, pricing keys | no usage adapter | `none`, `openai`, or `anthropic`; exact mode has required prices | resource governor | process or shared authority | boot | Keeps accounting bounded and explicit rather than guessed |

## Three configuration planes

There are three deliberately different kinds of configuration:

1. Deployment configuration is the JSON file documented here. It contains
   listener bounds, backend trust, paths, cluster identity, and secret
   references. Changing it normally requires a restart and, for cluster-wide
   behavior fields, all nodes must converge on the same digest.
2. Signed policy is the authenticated policy artifact selected by
   `policy.file` and `policy.verifier_key_file`. It owns risk thresholds,
   hysteresis, enforcement mode, and other operator policy decisions. Use the
   `gripline policy verify|prepare|activate|rollback` lifecycle rather than
   adding those values to ordinary deployment JSON.
3. Live crypto lifecycle is the shared signer, pepper, and pseudonym generation
   state. Prepare, backend-accept, activate, overlap, and retire are explicit
   lifecycle operations. A higher number in the local file is never an
   implicit activation.

Risk thresholds, quarantine/block decisions, signer activation, and retirement
must not become ordinary config knobs: they require signed policy or an
audited shared lifecycle transition. This separation is what lets an operator
review a deployment restart independently from a live security decision.

## Secret handling

Use environment expansion or a secret-injection layer for raw tokens and key
material. Do not paste those values into tickets or shell transcripts. The
effective-config command redacts operator-token map keys, pepper values,
pseudonym keys, and verifier-control tokens before writing JSON.
