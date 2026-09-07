# Security Policy

Gripline is a security gateway: it exists to contain credential abuse. Security
reports are taken seriously and treated with priority.

## Supported versions

Only the latest released `main` branch is supported. Gripline is pre-1.0; there
are no long-term support branches.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report by opening a private GitHub security advisory on this repository
(Security → Report a vulnerability), or contact the maintainers directly using
the contact information on the repository owner's profile.

Include:

- Affected component (e.g. `internal/proxy` body spooler, `internal/statebolt`,
  the admin control plane) and, if possible, the commit hash.
- A minimal reproduction or proof-of-concept.
- Your assessment of severity and impact.

## What to expect

- Acknowledgement within **5 business days**.
- An initial assessment and severity estimate within **14 days**.
- Coordinated disclosure: we ask for up to **90 days** before public
  disclosure, and will work with you on a mutually reasonable timeline.

## Scope

In scope:

- Credential handling and containment guarantees (INV-1: verifiers only, raw
  secrets never persisted, logged, or forwarded).
- The internal assertion boundary (INV-10/11/12): assertion stripping,
  re-injection, audience binding, the reserved `Gripline-*` header namespace.
- Restart-containment guarantees: what the Bolt state authority durably
  preserves (credential status, lane security state, evidence, operator
  posture, audit).
- Body bounding, request/response header hygiene, and timeout semantics of the
  data plane.
- The operator control plane (authentication, authorization, transactional
  mutation + audit).

Out of scope:

- Denial of service via volumetric traffic (the gateway enforces bounded
  resources, but a volumetric DDoS is a network-layer concern).
- Vulnerabilities in the upstream inference provider behind the gateway.
- Misdeployment: binding the admin plane public despite validation refusing
  it, disabling TLS postures via config that fails closed at boot, etc.

## Design documentation

The security-relevant invariants and their enforcement points are documented
in [`docs/design/`](docs/design/) (see `01-containment.md` and
`05-internal-identity.md`) and audited in [`AUDIT.md`](AUDIT.md).
