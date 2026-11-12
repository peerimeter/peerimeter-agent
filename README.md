# Peerimeter Agent

An offline-first, headless WireGuard mesh agent for Linux, macOS and Windows.
Configure peers with local JSON and run direct WireGuard connections without an
API server, enrollment, MQTT or STUN. No relay or desktop application.

[Install](#release-installation) · [Build](#quick-start-from-source) ·
[Configure](#offline-configuration) · [Commands](#foreground-and-local-control)
· [Services](#native-service) · [Remove](#full-removal-versus-service-removal) ·
[Verify](#verification)

## Project status

**✅ Phase 0 complete · ✅ Phase 1 complete · ⬜ Phase 2 not started**

The offline agent, directory separation, migration, services, installers and full
uninstall passed native tests and independent review.
Linux/macOS/Windows agent links, local control, native services and installers
are verified for the CI architectures below. Exact code SHAs, run links and
remaining limitations are tracked in [progress.md](progress.md).

| Platform (native CI architecture) | Native tunnel | Service manager | Runtime privileges |
| --- | --- | --- | --- |
| Linux (amd64) | Kernel WireGuard via netlink/wgctrl | systemd | root / kernel networking privileges |
| macOS (arm64) | Embedded wireguard-go, native utun | launchd | root |
| Windows (amd64) | Bundled official signed WireGuardNT | Windows Service | Administrator / LocalSystem |

macOS requires no separate `wg` or `wireguard-go` executable. Windows requires
the complete agent package, including its pinned `wireguard.dll`; the agent
verifies its hash and signature before creating a native adapter. No WireGuard
GUI/MSI is required. Linux must have kernel WireGuard support.

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
address. A userspace reference peer or separate network namespaces are needed to
test encrypted traffic on one host without local routing shortcuts.

## Release installation

Install scripts are hosted at [agent.peerimeter.app](https://agent.peerimeter.app):
`install.sh` for Linux/macOS and `install.ps1` for Windows. A public release is
required before the default latest-release install can succeed.
The site is published from this repository's `docs/` directory on `main`; its
latest-release label is loaded directly from GitHub Releases when the page opens.

Linux and macOS releases provide a direct executable and a checksummed license
notices file (for example, `peerimeter-agent-linux-x86_64`). Windows releases
provide a ZIP with the executable, signed WireGuardNT DLL and notices (for
example, `peerimeter-agent-windows-x86_64.zip`).

The installers default to the latest stable release and detect OS/architecture.
Release asset names follow the Nix system naming convention (`x86_64` and
`aarch64`) and do not include the version; the installer selects the version
from the release tag. Explicit versions and absolute installation directories
are supported:

### Linux and macOS

```sh
# Install the latest release to a user-owned directory without sudo.
curl -fsSL https://agent.peerimeter.app/install.sh | sh -s -- --install-dir "$HOME/.local/bin"

# Select a version and install it system-wide.
curl -fsSL https://agent.peerimeter.app/install.sh | sudo sh -s -- --version v0.1.0 --install-dir /usr/local/bin

# Termux can use its standard writable prefix without a directory permission override.
curl -fsSL https://agent.peerimeter.app/install.sh | sh -s -- --install-dir "$PREFIX/bin"

# Running the checked-out script also works:
sh install.sh --version latest --install-dir "$HOME/.local/bin"
```

### Windows

```powershell
# Run from an elevated PowerShell terminal.
.\install.ps1
.\install.ps1 -Version v0.1.0 -InstallDir 'C:\Program Files\Peerimeter'
.\install.ps1 -Version latest -InstallDir 'D:\Tools\Peerimeter Agent'
# The legacy -AllowInsecureInstallDir switch remains accepted for compatibility.
```

### Package verification

Release downloads use HTTPS and the release SHA-256 manifest. This authenticates
the download origin and checks integrity; a detached agent release signature is
not claimed. The Windows DLL also has its pinned hash and official Authenticode
signature. For an offline Unix install, supply a local binary and notices file
with `--binary`, `--notices`, `--sha256` and `--notices-sha256`; Windows accepts
a local ZIP with `-Archive` and `-SHA256`. Installers replace program files
only; they preserve configuration and keys. Installation ancestor owner and
permission checks are disabled; symbolic links and reparse points remain
rejected. Key files and managed inventory files retain their private-file checks.
Automatic self-update remains Phase 7.

### Publishing a release

Start **Actions → Publish release → Run workflow** on `main`. The workflow
uses the pinned `ietf-tools/semver-action` to read Conventional Commits since
the latest stable tag: `feat` bumps minor, patch-level changes bump patch, and
breaking changes bump major. If commits do not call for a version bump, package
and release jobs are skipped. Native installer checks run on Linux, macOS and
Windows; GoReleaser cross-builds both `x86_64` and `aarch64` assets for all
three platforms, creates the Windows ZIP and `SHA256SUMS`, and publishes the
matching version tag and release. It does not reject or rewrite commits during
normal CI.

## Offline configuration

See the [version 1 schema](schemas/static-v1.schema.json) and [paired
examples](examples/README.md). Unknown/duplicate JSON members, invalid keys,
conflicting addresses/routes and endpoints captured by tunnel routes are
rejected before changing OS state. Endpoints are numeric IPv4:port or
`[IPv6]:port`; validation never performs DNS lookups. Private keys live in
`private_key_file`, resolved relative to the configuration file.

Linux/macOS keys must be regular, singly linked files owned by the effective
runtime user, with no group/other access (normally `0600`). macOS extended ACLs
are rejected too; remove them with `chmod -N`. Windows key files require an
allowlisted owner/DACL; only the current user, SYSTEM and Administrators may
have access. Symlinks/reparse points and broadly readable keys are rejected.
Parent directories must be trusted.

## Foreground and local control

```sh
sudo peerimeter-agent run --config /absolute/path/to/peer.json
sudo peerimeter-agent status
sudo peerimeter-agent peers
sudo peerimeter-agent sync       # validate and reapply the original JSON file
sudo peerimeter-agent stop       # graceful tunnel/route cleanup
```

On Windows, run the same commands from an elevated terminal.

| Command | Output or action |
| --- | --- |
| `status` | JSON describing the local agent and adapter |
| `peers` | Human-readable WireGuard peer list |
| `peers --json` | Peer data for automation |
| `sync` | Validate and reapply the original configuration |
| `stop` | Stop the tunnel and clean up routes |

`status`/`peers` read actual local adapter state through a protected Unix socket
or Windows named pipe. `running` indicates interface state, not proven peer
connectivity; inspect real handshake timestamps and byte counters. A stopped or
unreachable agent returns an error.

### Delegate local control

Control defaults to the runtime identity and, on Windows, SYSTEM/Administrators.
To delegate control without administrator privileges, start/install with
`--operator <username-or-UID>` on Unix or `--operator <account-or-SID>` on
Windows. The authorized operator can use `status`, `peers`, `sync` and `stop`
without sudo or elevation; secret files stay private. On Unix the state
directory and its parents must permit traversal; only the socket owner receives
control access.

### Configuration, durable state and disposable runtime

| Platform | Config and private keys (`--config-dir`) | Persistent state (`--state-dir`) | Local control (`--runtime-dir`) |
| --- | --- | --- | --- |
| Linux | `/etc/peerimeter` | `/var/lib/peerimeter-agent` | `/run/peerimeter-agent` |
| macOS | `/etc/peerimeter` | `/Library/Application Support/Peerimeter` | `/var/run/peerimeter-agent` |
| Windows | `%ProgramData%\Peerimeter` | `%ProgramData%\Peerimeter` | `%ProgramData%\Peerimeter` |

Overrides must be absolute. Unix directories are separate; on Windows an
explicit `--state-dir` also supplies the default config/runtime location unless
overridden. `run --config <file>` uses the original file directly and never
relocates it; without `--config`, the installed `config-dir/service.json` is
used. Relative key references remain relative to the original JSON file.

Control commands use the selected `--runtime-dir`; custom runtime paths must be
supplied consistently. Persistent state locks prevent two managers for one state
across different runtime overrides, and a runtime lock prevents two states from
sharing a live control endpoint. Stopping removes disposable control resources;
keys and interface identity survive in their respective directories.

Ordinary peer/endpoint changes reconcile in place without resetting unaffected
peers. Invalid updates leave the current tunnel running. Changing local network
identity or macOS/Windows addresses requires an explicit stop/start. Static mode
never contacts a control-plane API. No automatic NAT rediscovery is promised.

### Linux interface names

The build-time default prefix is centralized in `ifname.DefaultPrefix` (`pm-`).
The default name is that prefix plus a lowercase ASCII slug of the network name;
runs of other characters become one hyphen. Slugs longer than 12 bytes use their
first five bytes (trim trailing hyphen), `-`, and the first six hex digits of
SHA-256 of the immutable network ID. An empty slug uses `pm-<hash>`. Explicit
names allow ASCII letters/digits/`._-`, up to 15 bytes, excluding `.` and `..`.

`run --interface wg-prod` overrides JSON `interface.name` at initial setup. The
resolved selection persists and survives display-name changes. Implicit renames
and unrelated existing interfaces are rejected. Overrides are Linux-only; macOS
allocates an actual utun and Windows uses a stable network-derived alias.

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

Windows uses the same subcommands in an elevated terminal. Replace `alice` with
an existing authorized local account. Installation snapshots the validated
config/key into protected `service.json` and `service.key` under the
configuration directory; the original files stay unchanged. Edit the protected
installed config and use `sync` for later updates.

Identical protected snapshots can be reused when reinstalling; different config
or key material requires an explicit migration. Failed registration rolls back
only snapshots created by that attempt. Installed secrets are never silently
overwritten. `service uninstall` preserves config, keys and interface selection.
Boot activation and restart on failure use the native OS supervisor; foreground
and service modes use the same tunnel runtime. One named system service is
currently supported per machine.

### Migrate the earlier combined Unix layout

After upgrading the executable in its protected stable path, migrate an older
combined state directory explicitly:

```sh
sudo peerimeter-agent service migrate --state-dir /var/lib/peerimeter-agent \
  --config-dir /etc/peerimeter --runtime-dir /run/peerimeter-agent --operator alice
sudo peerimeter-agent service start
```

Migration validates ownership and destination conflicts before stopping the old
service. It preserves keys, interface selection and ownership identity;
successful registration moves only the old installed snapshots. Original
operator configs stay outside this migration. On failure old credentials remain
available for retry.

### Full removal versus service removal

`service uninstall` removes only service registration and preserves
configuration and keys. Top-level `uninstall` explicitly deletes all resources
tracked as owned by that installation, including installed identity and keys:

```sh
sudo peerimeter-agent uninstall --dry-run
sudo peerimeter-agent uninstall
# Select an installation in a custom program directory:
sudo peerimeter-agent uninstall --install-dir '/opt/Peerimeter Agent' --dry-run
```

Installers write a protected installation inventory. Full removal refuses
arbitrary untracked paths, preserves unrelated files and original source
configs, stops the owned service/agent first, and verifies ownership/locks
before deletion. Windows uses a bounded helper after the running executable
exits; a `pending` result names a temporary receipt reporting eventual removal
or remaining failures. The shared system WireGuard driver is preserved. Repeated
removal is safe; partial failures remain reportable and retryable. Removal and
migration are natively verified; see [progress.md](progress.md) for exact tested
commits and remaining limits.

## CLI output

Peer listing is refactored from the [wgshow
example](https://github.com/zer0go/wgctrl-go/blob/47ad6fc7d7a95296fe893b49c1d4584b4eb6ac40/cmd/wgshow/main.go),
with [MIT attribution](third_party/wgshow/README.md). It shows public keys,
endpoints, AllowedIPs, handshake age, traffic and keepalive. Private and
preshared keys never enter the renderer. Missing handshakes and clock skew are
explicit.

Cobra provides contextual `--help` and `completion bash|zsh|fish|powershell`.
Commands live in separate files under `internal/cli` (`root.go`, `run.go`,
`version.go`, `service_*.go`, etc.). `version` prints the orbit/P ASCII logo and
human-readable build details, with terminal-aware pink/purple color. Use
`version --json` for automation, `--color never` for plain output or `--color
always` to force ANSI; automatic color respects `NO_COLOR` and pipes.

Runtime logs use colored console formatting by default when stderr is an
interactive terminal. Set `PEERIMETER_LOG_FORMAT` to `text` for uncolored
logfmt output or `json` for structured JSON logs. Console mode respects
`NO_COLOR` and does not emit ANSI codes when output is piped:

```sh
PEERIMETER_LOG_FORMAT=json peerimeter-agent run --config ./peer.json
PEERIMETER_LOG_FORMAT=text peerimeter-agent run --config ./peer.json
```

In PowerShell, set it for the current session with
`$env:PEERIMETER_LOG_FORMAT = 'json'` or `'text'` before starting the agent.

## Verification

### Local checks

```sh
make test
make lint
make build
```

### GitHub Actions

GitHub Actions runs native Go 1.27.4 build, vet, race/unit and offline CLI
checks on `ubuntu-24.04`, `macos-15`, `windows-2022`. The privileged integration
workflow runs the actual agent: two Linux agents in isolated namespaces, plus
macOS and Windows agents against an independent userspace WireGuard peer, with
real handshake/traffic, reload, shutdown/restart and native service tests.

The [reference peer and original backend probes](tests/backendprobe/README.md)
remain separate from agent acceptance. Mixed-OS VM connectivity and
NAT/IP-change recovery require dedicated topology and remain unverified;
separate hosted jobs are not a LAN. No cross-compilation result is treated as
native connectivity proof. See [progress.md](progress.md) for exact tested
commits and limitations.

## STUN port probe

The standalone STUN command reports the UDP endpoint observed by a STUN server.
Pass a local port to bind it explicitly, or omit the port to let the operating
system select an available one:

```sh
peerimeter-agent stun
peerimeter-agent stun 51820
peerimeter-agent stun --server stun.l.google.com:19302 51820
```

By default, the command tries `stun.l.google.com:19302`, `stun1.l.google.com:19302`,
and `stun2.l.google.com:19302` in order, advancing when a server fails. The
`--server` option selects one server and disables fallback. The JSON result
includes the bound local address and the mapped public address. A STUN mapping
alone does not establish WireGuard connectivity or promise NAT traversal.
