# WireGuard reference peer and backend probes

[Agent documentation](../../README.md) · [Native integration
workflow](../../.github/workflows/wireguard-integration.yml) · [Verification
evidence](../../progress.md)

This isolated Go module uses pinned official WireGuard libraries. It provides an
independent userspace reference peer for the macOS and Windows agent integration
tests, and retains the original Phase 0 backend feasibility probes.

## Current agent integration

The native integration workflow runs the actual agent on Ubuntu 24.04, macOS 15
and Windows Server 2022, with `fail-fast` disabled.

| Platform | Agent under test | Independent peer |
| --- | --- | --- |
| Linux | Kernel WireGuard through the agent | A second agent in a separate network namespace |
| macOS | Embedded wireguard-go with a native utun | This module's userspace network stack |
| Windows | Bundled WireGuardNT through the agent | This module's userspace network stack |

The reference peer's tunnel IP is never assigned to a host adapter. Both sides
initiate TCP connections and check received payloads alongside real handshake
and transfer counters. Tests also exercise reload, restart, native services and
cleanup. See [progress.md](../../progress.md) for the exact tested commits and
current acceptance status.

The Windows reference peer uses `conn.NewStdNetBind`; the default Windows ring
bind failed the earlier feasibility experiment.

## Build the reference peer

Run from the repository root with **Go 1.27.4**:

```sh
go build -C tests/backendprobe -mod=readonly -o /absolute/path/pmprobe .
```

On Windows, use an output path ending in `.exe`. The privileged invocations are
in [scripts/ci](../../scripts/ci) and the [native integration
workflow](../../.github/workflows/wireguard-integration.yml). To run the full
Unix agent acceptance suite on an isolated test machine:

```sh
make test-integration
```

## Original Phase 0 feasibility probes

These scripts test backend availability independently of the agent:

| Platform | Probe | Native backend |
| --- | --- | --- |
| Linux | [linux-backend.sh](../../scripts/ci/linux-backend.sh) | Two kernel WireGuard peers in separate namespaces |
| macOS | [macos-backend.sh](../../scripts/ci/macos-backend.sh) | Official wireguard-go with a real utun |
| Windows | [windows-backend.ps1](../../scripts/ci/windows-backend.ps1) | Official WireGuard tunnel service |

The original probes restart the native tunnel and assert cleanup. Their
prerequisites are for testing only:

| Tool | Pinned version or revision |
| --- | --- |
| Unix `wg` | wireguard-tools `v1.0.20260223`, commit `49ce333da02056ae7b22ee2aeb6afe8aaed79b19` |
| macOS `wireguard-go` | `0.0.20250522`, commit `f333402bd9cbe0f3eeb02507bd14e23d7d639280` |
| Windows WireGuard MSI | amd64 `1.1.1`, pinned SHA-256 and checked Authenticode publisher |

The Windows feasibility probe installs the upstream application to obtain its
native tunnel service. The current agent integration instead uses the bundled,
verified WireGuardNT DLL and requires no WireGuard GUI/MSI.

## Test environment and evidence

The integration suite requires a disposable machine with root or administrator
access: it exercises networking, services and machine-wide installation paths.
Tests use no private test network or repository secrets. Keys are ephemeral,
never printed, and removed by teardown handlers.

Evidence artifacts record the tested commit, runner image/version, run URL,
timestamp and result. Full logs remain in GitHub Actions. Integration failures
are failures, never skipped passes.

A backend feasibility pass does not complete agent acceptance. Native tests
within one runner also do not prove connectivity between different OS VMs. The
[connectivity E2E workflow](../../.github/workflows/connectivity-e2e.yml)
reports a failing **blocked** check when invoked until dedicated mixed-OS and
NAT/disruption test topology is available. Managed NAT/public-endpoint recovery
belongs to Phase 3. There is no implicit LAN between hosted jobs.
