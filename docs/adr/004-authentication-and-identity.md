# 004. Authentication and identity

* Status: Accepted
* Date: 2026-08-17

## Context

The gateway is Internet-facing and will be shared with a small group (operator + family/friends). We need mutual authentication, isolation between people, one-time bootstrap, OS secret storage, and no replay of enrollment tokens. Password accounts, OAuth, and a web admin UI were rejected for v1.

## Decision

**Two identifiers**

- `user_id` — a person. Quotas and reserved subdomains attach here.
- `client_id` — a device of that person. The mTLS certificate attaches here.

**Bootstrap**

1. Gateway generates an internal tunnel CA (key mode 0600).
2. Operator: `passerelle-gateway user add <name>` then `token create --user <name>`.
3. Token: high entropy, short TTL, single use, SHA-256 stored, bound to `user_id`. Delivered out of band.
4. Client: `passerelle auth <gateway-url>` generates a key, submits a CSR to `POST /v1/enroll` on public HTTPS. The one-time token is read from a hidden prompt (not argv).
5. Gateway consumes the token, enforces the device quota, issues a client cert whose URI SANs carry `user_id` and `client_id`, returns the tunnel CA and tunnel endpoints.

**Steady state**

- Tunnel connections require **mTLS** (client cert + gateway cert issued by the tunnel CA). Application `Hello` identity fields are ignored.
- Public HTTP does not use client certs.
- Private key: macOS Keychain, Windows Credential Manager, libsecret; file `0600` fallback logged as degraded.
- Subdomain requests are **authorizations**, not facts. Routing uses the server-side hostname map only.
- Isolation is by `user_id`: streams only to a device owned by the hostname's user. Reserved names are globally unique on the base domain.
- Revocation: per-device serial denylist or whole-user revoke; persisted on disk.
- Quotas per user: max devices, max tunnels, max concurrent public HTTP connections.
- No 0-RTT. Enrollment rate-limited. Logs may include `user_id`/`client_id` (not secrets) and must never include tokens, PEMs, or `Authorization`.

Admin is local CLI on the gateway host. No web dashboard in v1.

## Rationale

mTLS is a standard (not homemade crypto) and binds the TCP/QUIC session to a device without bearer tokens on the hot path. Splitting user vs device lets Alice enroll a laptop and a desktop under one quota domain without sharing a private key.

Invite tokens avoid building a password database and an identity provider for a handful of relatives. Hashing and single-use close the replay window.

## Consequences

- Compromising one device means revoking that cert, not rotating a shared family password.
- Losing the CA key means re-enrolling every device; back up `data_dir` accordingly.
- Adding a real IdP later can still mint the same client certs; the tunnel protocol does not change.
