# Gripline Threat Model

## Security boundary

Gripline terminates reusable external credentials at the public edge and
forwards only a short-lived, audience-bound internal assertion to a fixed
private inference backend. The verifier-management listener is a separate
control boundary with a distinct URL and authentication identity.

In scope are public HTTP parsing, credential authentication, deterministic
admission, resource accounting, internal assertion verification, backend
reachability, operator lifecycle, and clustered authority failures.

The following are boundary dependencies rather than claims this repository can
prove by unit tests alone: volumetric network DDoS, provider application
object/property authorization, PostgreSQL backup/HA implementation, and
compromise of a host that stores the file-backed signing key. They are not
silently accepted risks: production release requires the corresponding edge,
provider, database, and host/KMS evidence in the release criteria.

## Attacker capabilities

- Possesses a valid or stolen external API credential.
- Sends arbitrary HTTP/1.1 requests, headers, trailers, methods, paths, bodies,
  connection reuse patterns, and malformed authentication carriers.
- Attempts to forge, replay, or route internal assertions.
- Attempts to invoke verifier management through the public data plane.
- Can cause backend, authority, node, or client-side disconnects.
- May submit high-cardinality source identities or invalid-credential floods.

The attacker does not possess the dedicated verifier-control certificate/token,
the signer private key, or PostgreSQL authority credentials.

## Security claims

The repository claims executable coverage for the controls listed in the
assurance matrix. It does not claim that the gateway is secure against every
attack; residual and deployment-qualified items remain explicit.
