# Native backend feasibility (Phase 0)

This is an isolated test module using pinned official WireGuard Go libraries. It
is not the agent backend. `wireguard-integration.yml` runs the test natively on
Ubuntu 24.04, macOS 15 and Windows Server 2022; `fail-fast` is disabled. A backend
pass does not complete Phase 1 agent integration.

The Linux script creates two kernel WireGuard peers in separate network
namespaces. macOS creates a real utun interface using official wireguard-go.
Windows uses a real WireGuardNT tunnel service. For macOS and Windows, this helper
provides the second peer entirely in a userspace network stack: its tunnel IP is
not assigned to any host adapter. Both sides initiate TCP connections and check
received payloads, alongside native handshake/transfer counters. Each probe also
restarts the native tunnel and asserts cleanup. The Windows reference peer uses
`conn.NewStdNetBind`; the default Windows ring bind failed the earlier experiment.

Prerequisites are installed for testing only:

- Unix `wg`: official `wireguard-tools` v1.0.20260223, commit
  `49ce333da02056ae7b22ee2aeb6afe8aaed79b19`.
- macOS: official `wireguard-go` 0.0.20250522, commit
  `f333402bd9cbe0f3eeb02507bd14e23d7d639280`.
- Windows: official WireGuard amd64 MSI 1.1.1, pinned SHA-256 and checked valid
  Authenticode publisher. This installs the upstream application to obtain the
  probe's native tunnel service. It does **not** implement the future agent
  installer's bundled, offline driver requirement.

The CI jobs require disposable hosted runners with root/admin access. They use
no private test network or repository secrets. Keys are ephemeral, never printed,
and removed by teardown handlers. Artifacts contain only the tested commit,
runner image/version, run URL, timestamp and result; full logs stay in Actions.

Build the helper with Go 1.27.4:

```sh
go build -C tests/backendprobe -mod=readonly -o /absolute/path/pmprobe .
```

On Windows, the output path must end in `.exe`. The shell/PowerShell entry points
and prerequisite installers are in `scripts/ci`; consult the workflow for the
privileged invocation. Integration failures are failures, never skipped passes.

`connectivity-e2e.yml` currently reports **blocked** with a failing check when
manually invoked: agent NAT/IP-change tests and mixed-OS test topology are still
pending Phase 1. There is no product relay or implicit LAN between hosted jobs.
