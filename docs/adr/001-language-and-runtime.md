# 001. Language and runtime

* Status: Accepted
* Date: 2026-08-17

## Context

Passerelle needs a single language for the client (macOS, Linux, Windows) and an Internet-facing gateway. Constraints: network performance, low CPU/RAM, TLS quality, concurrency, portable static-ish binaries, Homebrew/deb distribution, and long-term maintenance. Rust and Go were the realistic candidates.

## Decision

Use **Go**, one module (`github.com/gauthier/passerelle`), two binaries (`passerelle`, `passerelle-gateway`). Target the current stable toolchain (Go 1.24+).

Do not split languages (Rust gateway + Go client). Do not use C/C++, Node, or a JVM.

## Rationale

- TLS 1.3 (`crypto/tls`), HTTP/2 (`golang.org/x/net/http2`), and QUIC (`quic-go`, same stack as Caddy and cloudflared) are production-proven for this exact problem.
- Goroutines plus `io.Copy` plus QUIC/HTTP/2 flow control give streaming backpressure without a custom event loop.
- `GOOS/GOARCH` cross-compilation is the cheapest path to macOS/Linux/Windows amd64/arm64 and to Homebrew formulae.
- The WAN is the bottleneck, not the GC. With no full-body buffering, Go saturates a gigabit link. Rust zero-copy would not change user-visible latency on a personal tunnel.
- Memory safety of the interesting kind here is bounds-checked slices and the race detector; the real risks are authz, HTTP smuggling, and unbounded buffers — logic bugs in any language.
- Cobra + Bubble Tea match the CLI/TUI requirement without a second ecosystem.

Rust (tokio, quinn, rustls, ratatui) remains the runner-up if we ever needed a 10 Gbps+ edge or a hard "no GC on the data path" policy. That is not v1.

## Consequences

- All shared protocol code lives in-repo as a Go package generated from `.proto` files.
- CI builds three OSes from one job matrix.
- Contributors need a Go toolchain, not a Rust one.
