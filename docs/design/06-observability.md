# 06 — Observability, Privacy, Audit

## 1. Credential-safe telemetry

Gripline-owned telemetry (logs, traces, metrics, events) never carries raw
credentials (INV-2). The `SealedSecret` type has no formatting/serialization
surface, and the extraction path zeroes the secret before any downstream
handler sees the request. Metrics identify credentials by **pseudonymous
internal ID** (INV-2/§96).

## 2. Privacy defaults

Prohibited retention by default: raw API credentials, Authorization headers,
prompt content, completion content. Exact IP retention minimized; long-term
security records prefer pseudonymous source ID, ASN, network class, coarse
region.

## 3. Pseudonymization

Long-term source identifiers and invalid-credential fingerprints use **keyed**
HMAC transforms, not raw hashes susceptible to trivial enumeration:

```
source_id                 = HMAC(source_pseudonym_key, normalized_source_identifier)
source_abuse_block_hotkey = HMAC(abuse_detection_key, ...)   // distinct key from verifier key
```

Keys support rotation. The abuse-detection key (`internal/pseudonym`) is
distinct from the credential-verifier key (`internal/credential`).

## 4. Invalid-credential fingerprinting

The raw invalid credential is discarded immediately; only a short-lived
pseudonymous fingerprint is retained for key-spray cardinality (§44–45).
Retention measured in minutes/hours.

## 5. Data retention classes

Separately configurable (§74): raw network address (hours/days); invalid-
credential fingerprint (minutes/hours); lane metadata (weeks/months); security
evidence (weeks/months); audit events (long-term per policy). Retention is
explicitly documented.

## 6. Audit

Administrative and security-significant mutations carry `actor, operation,
target, before, after, timestamp, reason`; the audit log is append-only.
Risk-state transitions are audited (INV-7). Control-plane mutations
(revoke/rotate/constrain/policy/emergency) require explicit authorized action —
downgrade never happens implicitly (INV-14).

## 7. Explainability

Every nontrivial action emits a machine-readable explanation answering: what
changed, why, under which policy (revision), at what scope, for how long
(§97). Example:

```json
{
  "credential_id": "cred_83ab", "lane_id": "lane_91",
  "risk_before": 22, "risk_after": 68,
  "evidence": ["NEW_HOSTING_ASN", "SIMULTANEOUS_ESTABLISHED_LANE", "CONCURRENCY_8X_BASELINE"],
  "action": "CONSTRAIN_LANE", "policy_revision": 42
}
```

External errors avoid disclosing detailed security reasoning: 401 invalid
credential, 429 resource restriction with `Retry-After` when a refill-backed
bucket can calculate one, 403 quarantine — with
a request id (`credential_temporarily_restricted`) and investigation via
authenticated operator interfaces (§70).

## 8. Request IDs

Every request gets a globally unique id **before authentication**, encoding
none of credential/account/IP/prompt. It ties together proxy events, resource
accounting, security events, user-visible errors, and audit investigation
(§71).
