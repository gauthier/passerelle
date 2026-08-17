# 005. Public routing and TLS

* Status: Accepted
* Date: 2026-08-17

## Context

Visitors need `https://<name>.<base-domain>` URLs. The gateway must terminate TLS to read `Host`, then multiplex onto the owning client. ACME-in-process, Caddy-in-front, and file-loaded wildcards were options. Hosting (VPS vs other) is not decided; the design must not bake in a domain.

## Decision

- **Terminate TLS on the gateway** for the public listener. Optional HTTP/80 → HTTPS redirect only (no cleartext origin traffic).
- **v1 certificates:** wildcard (or SAN) material **from files** (`tls_cert` / `tls_key` in config). Operator may obtain them with certbot, lego, or Caddy on the side.
- **Optional ACME:** certmagic DNS-01, off by default, for a later ops convenience — not required to run.
- **Default hostname:** cryptographically random subdomain, unguessable. `--subdomain` is opt-in and server-authorized (collision, user ownership, quotas).
- **Routing key:** visitor `Host` (normalized, lowercased, port stripped) looked up in `TunnelRegistry`. Unknown host → 404. Never trust a hostname claimed on the tunnel control stream for public routing.
- **Sticky session:** a tunnel is bound to the gateway process the client is connected to. `TunnelRegistry` is an interface (memory + durable allocations on disk in v1) so a later shared store can exist without rewriting the proxy.
- **No Caddy requirement.** Running HTTP-only behind an external TLS terminator remains possible (`listen_https` with a forwarded proto/headers is out of scope until needed).

## Rationale

Embedding ACME on day one pulls DNS provider credentials into the gateway and expands the Internet-facing attack surface. A wildcard file is the boring, correct MVP for a self-hosted box. Random default names avoid accidental exposure of a well-known `dev.` hostname.

HTTP-01 per random subdomain would hit CA rate limits and delay first request. DNS-01 wildcard is the right ACME mode when we add it.

## Consequences

- Operators point `*.gnthr.dev` at the gateway (already in DNS). Enrollment uses the reserved name `passerelle.gnthr.dev`. Local tests use a random port plus `Host` headers / `/etc/hosts`.
- Certificate paths and listen addresses are config, not constants.
- Multi-region anycast is not implemented; do not put a singleton hostname map in a package-level global that cannot be swapped.
