# Peerimeter Agent

An offline-first, headless WireGuard mesh agent for Linux, macOS and Windows.
Configure peers with local JSON; run without an API server, enrollment, MQTT or
STUN. Direct WireGuard connections only; no relay or desktop application.

## Project status

Phase 0 is complete. Phase 1 native runtime, local control and service integration
are under verification. Previous CI passes cover the baseline and backend probes;
new agent integration results are tracked in [progress.md](progress.md).

| Platform | Native tunnel | Service manager | Privileges |
|---|---|---|---|
| Linux | Kernel WireGuard via netlink/wgctrl | systemd | root / kernel networking privileges |
| macOS | Embedded wireguard-go, native utun | launchd | root |
| Windows | Bundled official signed WireGuardNT | Windows Service | Administrator / LocalSystem |

macOS requires no separate `wg` or `wireguard-go` executable. Windows requires the
complete agent package, including its pinned `wireguard.dll`; the agent verifies
its hash and signature before creating a native adapter. No WireGuard GUI/MSI is
required. Linux must have kernel WireGuard support.

## Quick start from source

Requires exact **Go 1.27.4**. Each repository builds independently.

```sh
export GOTOOLCHAIN=go1.27.4
go test ./...
go build -o bin/peerimeter-agent ./cmd/peerimeter-agent
./bin/peerimeter-agent generate-example --directory ./local-example
./bin/peerimeter-agent validate-config --config ./local-example/peer-a.json
sudo ./bin/peerimeter-agent run --config /absolute/path/to/peer.json
```

Keys must belong to the effective runtime user. For a foreground root process,
create the examples as root or copy/protect the key with root ownership before
running. Never commit generated private keys. On Windows build
`bin/peerimeter-agent.exe` and place the verified WireGuardNT DLL beside it.

The generator creates a **new** directory with two fresh X25519 keys and paired
configs. Loopback endpoints and separate UDP ports are examples; use reachable
numeric IP:port endpoints for separate devices. Each device needs a unique mesh
address. A userspace reference peer or separate network namespaces are needed
to test encrypted traffic on one host without local routing shortcuts.

## Release installation

Phase 1 adds `install.sh` (Linux/macOS) and `install.ps1` (Windows). Published
release packages are needed before the default `latest` download can work; no
public agent release is claimed by the development CI.

The installers default to the latest stable release and detect OS/architecture.
Explicit versions and absolute installation directories are supported:

```sh
sh install.sh
sudo sh install.sh --version v0.1.0 --install-dir /usr/local/bin
sh install.sh --version latest --install-dir "$HOME/.local/bin"
```

```powershell
# Run from an elevated PowerShell terminal.
.\install.ps1
.\install.ps1 -Version v0.1.0 -InstallDir 'C:\Program Files\Peerimeter'
.\install.ps1 -Version latest -InstallDir 'D:\Tools\Peerimeter Agent'
```

Release downloads use HTTPS and the release SHA-256 manifest. This authenticates
the download origin and checks integrity; a detached agent release signature is
not claimed. The Windows DLL also has its pinned hash and official Authenticode
signature. For an offline package verified separately, supply a local archive
and its SHA-256 using `--archive`/`--sha256` or `-Archive`/`-SHA256`.
Installers replace program files only; they preserve configuration and keys.
Automatic self-update remains Phase 7.

## Offline configuration

See the [version 1 schema](schemas/static-v1.schema.json) and
[paired examples](examples/README.md). Unknown/duplicate JSON members, invalid
keys, conflicting addresses/routes and endpoints captured by tunnel routes are
rejected before changing OS state. Endpoints are numeric IPv4:port or
`[IPv6]:port`; validation never performs DNS lookups. Private keys live in
`private_key_file`, resolved relative to the configuration file.

Linux/macOS keys must be regular, singly linked files owned by the effective
runtime user, with no group/other access (normally `0600`). macOS extended ACLs
are rejected too; remove them with `chmod -N`. Windows key files require an
allowlisted owner/DACL; only the current user, SYSTEM and Administrators may have
access. Symlinks/reparse points and broadly readable keys are rejected. Parent
directories must be trusted.

## Foreground and local control

```sh
sudo peerimeter-agent run --config /absolute/path/to/peer.json
sudo peerimeter-agent status
sudo peerimeter-agent peers
sudo peerimeter-agent sync       # validate and reapply the original JSON file
sudo peerimeter-agent stop       # graceful tunnel/route cleanup
```

On Windows run the same commands from an elevated terminal. Output is JSON.
`status`/`peers` read actual local adapter state through a protected Unix socket
or Windows named pipe. `running` indicates interface state, not proven peer
connectivity; inspect real handshake timestamps and byte counters. A stopped or
unreachable agent returns an error. Control defaults to the runtime identity and, on Windows, SYSTEM/Administrators.
To delegate control without administrator privileges, start/install with
`--operator <username-or-UID>` on Unix or `--operator <account-or-SID>` on Windows.
The authorized operator can use `status`, `peers`, `sync` and `stop` without sudo
or elevation; secret files stay private. On Unix the state directory and its
parents must permit traversal; only the socket owner receives control access.

`--state-dir <absolute-directory>` selects a separate protected instance for
`run`, `status`, `peers`, `sync` and `stop`. Defaults are `/var/lib/peerimeter-agent`
(Linux), `/Library/Application Support/Peerimeter` (macOS) and
`%ProgramData%\Peerimeter` (Windows). OS-held locks reject competing managers.

Ordinary peer/endpoint changes reconcile in place without resetting unaffected
peers. Invalid updates leave the current tunnel running. Changing local network
identity or macOS/Windows addresses requires an explicit stop/start. Static mode
never contacts a control-plane API. No automatic NAT rediscovery is promised.

### Linux interface names

The default is `pm-` plus a lowercase ASCII slug of the network name; runs of
other characters become one hyphen. Slugs longer than 12 bytes use their first
five bytes (trim trailing hyphen), `-`, and the first six hex digits of SHA-256
of the immutable network ID. An empty slug uses `pm-<hash>`. Explicit names allow
ASCII letters/digits/`._-`, up to 15 bytes, excluding `.` and `..`.

`run --interface wg-prod` overrides JSON `interface.name` at initial setup.
The resolved selection persists and survives display-name changes. Implicit
renames and unrelated existing interfaces are rejected. Overrides are Linux-only;
macOS allocates an actual utun and Windows uses a stable network-derived alias.

## Native service

Install the executable in a protected stable directory first. System service
installation requires administrator/root privileges and absolute paths:

```sh
sudo peerimeter-agent service install --config /absolute/path/to/peer.json --operator alice
sudo peerimeter-agent service start
sudo peerimeter-agent status
sudo peerimeter-agent service stop
sudo peerimeter-agent service uninstall
```

Windows uses the same subcommands in an elevated terminal. Installation snapshots
the validated config/key into protected `service.json` and `service.key` under
the selected state directory; the original files stay unchanged. Edit the
protected installed config and use `sync` for later updates. Identical protected snapshots can be reused when reinstalling; different config
or key material requires an explicit migration. Failed registration rolls back
only snapshots created by that attempt. Installed secrets are never silently
overwritten. Uninstall preserves config, keys and
interface selection. Boot activation and restart on failure use the native OS
supervisor; foreground and service modes use the same tunnel runtime. One named
system service is currently supported per machine.

## Verification

```sh
make test
make lint
make build
```

GitHub Actions runs native Go 1.27.4 build, vet, race/unit and offline CLI checks
on `ubuntu-24.04`, `macos-15`, `windows-2022`. The privileged integration workflow
runs the actual agent: two Linux agents in isolated namespaces, plus macOS and
Windows agents against an independent userspace WireGuard peer, with real
handshake/traffic, reload, shutdown/restart and native service tests.

The [reference peer and original backend probes](tests/backendprobe/README.md)
remain separate from agent acceptance. Mixed-OS VM connectivity and NAT/IP-change
recovery require dedicated topology and remain unverified; separate hosted jobs
are not a LAN. No cross-compilation result is treated as native connectivity
proof. See [progress.md](progress.md) for exact tested commits and limitations.
