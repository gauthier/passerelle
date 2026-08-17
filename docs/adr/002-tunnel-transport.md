# 002. Tunnel transport

* Status: Accepted
* Date: 2026-08-17

## Context

The client must open one long-lived encrypted session to the gateway and multiplex many public HTTP requests over it (including WebSocket, SSE, and large uploads) without buffering bodies. QUIC-only, TLS+yamux, SSH, WireGuard, and HTTP/2-only were considered.

## Decision

- **Crypto:** TLS 1.3 only. ALPN `passerelle/1`. QUIC 0-RTT **disabled**. Default Go cipher suites. No homemade crypto.
- **Primary:** QUIC over UDP, typically port 443 (same number as public HTTPS; UDP vs TCP do not collide).
- **Fallback:** HTTP/2 over TLS 1.3 on TCP 443, same ALPN, when UDP is blocked. After the client-initiated TCP+mTLS handshake, the gateway becomes the HTTP/2 *client* and the daemon the HTTP/2 *server* (cloudflared-style reverse roles).
- **Mux:** one bidirectional stream per public HTTP request. Control traffic uses a dedicated stream, length-prefixed protobuf (`protocol/control.proto`). Data streams start with a protobuf preamble `{ tunnel_id }` then raw HTTP/1.1.
- **v1 payload:** HTTP only. No raw TCP/UDP connect frame in `passerelle/1`. A later TCP mode would bump ALPN.
- **Public side:** HTTP/1.1 + HTTP/2 on TCP. No public HTTP/3 in v1.
- **HA:** a single multiplexed session per daemon, not cloudflared's four edge connections. Reconnect with exponential backoff and jitter.

## Rationale

QUIC gives per-stream flow control, no TCP head-of-line blocking, and connection migration (laptop sleep/Wi-Fi change) — all aligned with the resilience goals. UDP is frequently blocked, so a TCP fallback is mandatory; HTTP/2 is a standard mux with flow control, not a homegrown yamux dialect.

WireGuard is a VPN: a misconfig exposes more than the requested port. SSH is battle-tested but a poor fit for hostname routing, mTLS device identity, and a versioned app protocol.

Port 443 (not 7844) is the self-hosted choice: outbound 443 works on café and corporate networks.

Streaming: gateway reverse-proxy must flush immediately (`FlushInterval: -1` if `httputil.ReverseProxy` is used). Never `io.ReadAll` a body. Cap connections, headers, and idle time — not the body size.

## Consequences

- The daemon must probe QUIC, then fall back, and remember the working transport for a cooldown period.
- Protocol versioning is ALPN + protobuf `Hello` min/max. Unknown messages are errors, not silent ignores of identity fields.
- Load tests should include a slow origin and a large download to catch accidental buffering.
