# 003. Client daemon architecture

* Status: Accepted
* Date: 2026-08-17

## Context

`passerelle open 8080` must keep the tunnel alive after the terminal closes, expose a TUI that is *not* the tunnel process, and integrate with macOS, Linux, and Windows without a fragile `nohup`/double-fork supervisor.

## Decision

Split three roles in **one client binary**:

1. **Daemon** — owns the gateway session, origin dials, stats, and persistence. User-level service: launchd agent, systemd `--user`, Windows logon task. A system-wide Windows Service is optional packaging, not the default (it wants elevation).
2. **CLI** — HTTP client to the daemon.
3. **TUI** — same API, SSE event stream. Closing it does not close tunnels.

Local IPC: HTTP over a Unix socket (`0600`) or a Windows named pipe restricted to the current user. Authorize with peer credentials (e.g. `SO_PEERCRED` / equivalent). No local gRPC.

If the daemon socket is missing, the CLI asks the OS service manager to start it. If no service is installed, it prints `passerelle service install` rather than detaching a child as the primary mechanism. `passerelle daemon` runs in the foreground for debug.

`open` is ephemeral (survives terminal close, not reboot). `--persist` writes the tunnel into the client config and restores it on daemon start.

Origin dial: `127.0.0.1` by default, never the hostname `localhost`. `--host` must resolve to loopback unless later explicitly widened.

## Rationale

This is the Tailscale/Docker model: a privileged-for-the-user long-running process, a cheap CLI, a UI that can come and go. Homebrew then ships a formula that installs the launchd plist; Ubuntu desktops get a user unit; servers are unrelated (they run `passerelle-gateway`).

A true Windows Service as the only path would force admin rights on a developer laptop. User-level supervision matches the threat model (expose *my* localhost, as *me*).

## Consequences

- All mutating commands go through the daemon; tests can drive the IPC API without a TTY.
- Config lives in the platform user config dir; the private key does not (see ADR 004).
- Packaging (launchd plist, systemd user unit, a logon task) is part of the product, not an afterthought.
