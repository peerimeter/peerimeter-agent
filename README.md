# Peerimeter Agent

A headless WireGuard mesh agent for Linux, macOS and Windows. It supports
offline static configuration and optional enrollment in a Peerimeter service.
Connections are direct WireGuard connections; there is no relay.

## CLI reference

Run `peerimeter-agent <command> --help` for command options. Use
`peerimeter-agent --help` for general options and `peerimeter-agent help` for
the full command list.

| Command | Description |
| --- | --- |
| `generate-example` | Create example mesh configs and fresh keys |
| `validate-config` | Validate a static YAML config and its key |
| `run` | Run every network YAML in `--config-dir` (or one with `--network`/`--config`) |
| `daemon` | Run configured networks and periodically sync joined networks |
| `join` | Enroll this agent in a service-managed network (`--token` or `--token-file`) |
| `sync` | Refresh all joined networks or select one with `--network-id` |
| `status` | Show all local network tunnels and native service installation/running state; use `--network` to select one |
| `wg [show]` | Show all local WireGuard interfaces and peers |
| `stop` | Stop all configured tunnels or select one with `--network` |
| `service install` | Install and register the native OS service |
| `service start` / `service stop` | Start or stop the installed service |
| `service status` | Show whether the native service is installed and running |
| `service uninstall` | Remove service registration, keeping config and keys |
| `uninstall` | Remove the tracked agent installation and managed data |
| `stun [local-udp-port]` | Probe the public UDP mapping with STUN |
| `info` | Show version, environment and resolved directories |
| `version` | Show version information |
| `check-update` | Check whether a newer version is available |
| `self-update` | Update an installed agent to the latest stable release |

Common examples:

```sh
peerimeter-agent generate-example --directory ./mesh
peerimeter-agent validate-config --config ./mesh/peer-a.yaml
sudo peerimeter-agent run --config /absolute/path/to/peer.yaml
sudo peerimeter-agent status
```

## Install

Install the latest release on Linux or macOS:

```sh
curl -fsSL https://agent.peerimeter.app/install.sh | sh
```

On Windows, run `https://agent.peerimeter.app/install.ps1` from an elevated
PowerShell session. See the [installation guide](docs/README.md#release-installation)
for version selection and install options.

## Project status

**Phase 0 complete · Phase 1 complete · Phase 2 self-update complete.** The
standalone agent, services, installers and native uninstall are verified on the
CI architectures. See the [shared progress tracker](https://github.com/peerimeter/.github/blob/main/docs/planning/progress.md)
for tested commits and remaining limitations.

## Detailed guide

The [agent guide](docs/README.md) covers source builds, installation, static
configuration, managed enrollment, services, local control, output formats,
verification and platform-specific behavior.
