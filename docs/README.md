# Peerimeter Agent: Detailed Guide

A headless WireGuard mesh agent for Linux, macOS and Windows, with optional service API integration for sharing network and node configuration.
Static mode configures peers with local YAML and runs direct WireGuard
connections without an API server, enrollment, MQTT or STUN. No relay or
desktop application.

[Install](#release-installation) · [Build](#quick-start-from-source) ·
[Configure](#offline-configuration) · [Commands](#foreground-and-local-control)
· [Services](#native-service) · [Remove](#full-removal-versus-service-removal) ·
[Verify](#verification)

## Project status

**✅ Phase 0 complete · ✅ Phase 1 complete · ✅ Phase 2 self-update complete**

The standalone agent, directory separation, migration, services, installers and full
uninstall passed native tests and independent review.
Linux/macOS/Windows agent links, local control, native services and installers
are verified for the CI architectures below. Exact code SHAs, run links and
remaining limitations are tracked in the [shared project progress
tracker](https://github.com/peerimeter/.github/blob/main/docs/planning/progress.md).

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
./bin/peerimeter-agent validate-config --config ./local-example/peer-a.yaml
sudo ./bin/peerimeter-agent run --config /absolute/path/to/peer.yaml
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

Use `generate-example --directory ./mesh --peers 3` for three configs, each
listing the other two peers. When generating on one target machine, add
`--stun-peer 1` (or its one-based peer number) to probe that machine's public
UDP mapping and place it in the other generated configs. The remaining remote
endpoints still require their actual reachable addresses; see
[the examples guide](../examples/README.md).

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
are supported. By default, root installs put the executable in `/usr/local/bin`,
notices in `/usr/local/share/doc/peerimeter-agent`, and inventory and installer
locks in `/var/lib/peerimeter-agent-install` so the lock remains available after reboot.
User installs use `~/.local/bin`, XDG data/state directories, and a lock in the
persistent state directory. Windows stores program files under Program Files
and per-install metadata under `ProgramData\Peerimeter\Installations`. When a
custom Unix `--install-dir` is selected without the other directory flags, its
inventory, lock and documentation go into a sibling `.peerimeter` resource
directory. The binary locates default inventory from the current user's state
directory (or the system state directory for root installs); running it as a
different user therefore does not fall back to another user's inventory. A
protected `.install.ref` is written beside the binary only
when a non-default `--data-dir` is selected.

Both installers report progress as they resolve or download the release, verify
the package, install files and register the protected `.install.yaml` inventory.
Inventories from older releases are read and converted when the installation is
next registered or updated.

### Linux and macOS

```sh
# Install the latest release using root or per-user directory defaults.
curl -fsSL https://agent.peerimeter.app/install.sh | sh

# Override resource directories when needed.
curl -fsSL https://agent.peerimeter.app/install.sh | sh -s -- --install-dir "$HOME/.local/bin" --doc-dir "$HOME/.local/share/doc/peerimeter-agent" --data-dir "$HOME/.local/state/peerimeter-agent" --lock-dir "$HOME/.local/state/peerimeter-agent"

# Select a version and install it system-wide.
curl -fsSL https://agent.peerimeter.app/install.sh | sudo sh -s -- --version v0.1.0

# Termux can use its standard writable prefix without a directory permission override.
curl -fsSL https://agent.peerimeter.app/install.sh | sh -s -- --install-dir "$PREFIX/bin"

# Running the checked-out script also works:
sh docs/install.sh --version latest --install-dir "$HOME/.local/bin" --doc-dir "$HOME/.local/share/doc/peerimeter-agent" --data-dir "$HOME/.local/state/peerimeter-agent" --lock-dir "$HOME/.local/state/peerimeter-agent"
```

### Windows

```powershell
# Run from an elevated PowerShell terminal.
# Download and run the hosted installer.
Invoke-WebRequest -Uri https://agent.peerimeter.app/install.ps1 -OutFile install.ps1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\install.ps1

# From a repository checkout only:
.\docs\install.ps1
.\docs\install.ps1 -Version v0.1.0 -InstallDir 'C:\Program Files\Peerimeter'
.\docs\install.ps1 -Version latest -InstallDir 'D:\Tools\Peerimeter Agent'
.\docs\install.ps1 -DocDir 'D:\Peerimeter\Docs' -DataDir 'D:\Peerimeter\State' -LockDir 'D:\Peerimeter\Locks'
```

The process-scoped execution policy applies only to this PowerShell session.
Organization Group Policy may still block scripts; follow your organization's
policy in that case.

The installer adds the installation directory to the machine PATH. Open a new
PowerShell window to run `peerimeter-agent` or its short alias `pma` by name.
On Linux and macOS, the installer creates `pma` as a symlink beside the agent
binary. Full uninstall with the current release removes the alias and, on Windows, the PATH entry. Uninstallers from releases before alias support do not remove .

### Package verification

Release downloads use HTTPS and the release SHA-256 manifest. This authenticates
the download origin and checks integrity; a detached agent release signature is
not claimed. The Windows DLL also has its pinned hash and official Authenticode
signature. For an offline Unix install, supply a local binary and notices file
with `--binary`, `--notices`, `--sha256` and `--notices-sha256`; Windows accepts
a local ZIP with `-Archive` and `-SHA256`. Installers replace program files
only; they preserve configuration and keys. Installation ancestor owner and
permission checks are disabled; unexpected symbolic links and reparse points
remain rejected. The managed Unix `pma` symlink must point directly to the
adjacent agent binary. Key files and managed inventory files retain their
private-file checks.
`peerimeter-agent self-update` explicitly updates a registered installation to
the latest stable release. It displays the current and latest versions, then
asks for confirmation before upgrading. In a terminal, a Yes/No selector is
shown with Yes selected by default; use `y`/`n`, arrows, or Enter. Non-terminal
input accepts `y` or `yes`. Pass `--yes` to skip the prompt. If no new version
is available, it reports that without prompting. The command selects
the package for the current OS and CPU, then checks it against the release
`SHA256SUMS` file downloaded over HTTPS. This is an integrity check using the
GitHub release trust channel; it does not claim a detached release signature.
The latest-release check uses a TUI spinner in a terminal. During the update, a
spinner appears above a progress bar that advances across steps without
resetting; redirected output uses start/completion lines. With
`--json`, progress stays on stderr and the final result remains on stdout.
Startup checks may notify about an update, but never replace a running agent.

```sh
peerimeter-agent self-update       # show versions and ask before upgrading
peerimeter-agent self-update --yes # upgrade without prompting
```

With `--json`, the result includes the current and latest version; the
confirmation prompt is written to stderr so stdout remains valid JSON.

The updater verifies the protected installation inventory and each recorded
program-file hash before making changes. It replaces only those inventoried
files, preserving the recorded install, documentation, data and lock
directories and all configuration, keys, state, runtime paths and service
profiles. A running foreground profile prevents an update. For managed
services, it stops the service and waits for the agent to release its profile
locks before updating program files. It then starts the service and waits for
the local status endpoint. If the updated service does not become
ready, it restores the previous files and inventory hashes and restarts the
previous service. The update needs the same filesystem and service privileges
as the existing installation. On Windows, a helper launched from the verified
new package replaces the running executable after the update command exits;
the bundled WireGuardNT DLL must remain byte-for-byte identical and retains its
existing pinned hash and Authenticode checks.

The update replaces program files only; it does not migrate or delete
installation data. Linux and macOS finish the update synchronously. Windows
reports that the helper has started; the helper completes replacement and
service readiness checks in the background. Use `peerimeter-agent status` to
confirm the service is running. The updater records each multi-file replacement
in the install lock directory. If Windows recovery is needed, `self-update`
starts a separate protected helper and reports `recovery_scheduled`; that helper
restores the recorded files after the installed process exits. Uninstall refuses
to proceed while recovery is pending.
Recovery is operator-triggered rather than an automatic boot action.

### Publishing a release

Push release commits to `main` to start **Peerimeter CI and Release**. The
workflow uses the lockfile-verified `ietf-tools/semver-action` to read
Conventional Commits since the latest stable tag: `feat` bumps minor,
patch-level changes bump patch, and breaking changes bump major. If commits do
not call for a version bump, the release job is skipped. Manually running the
workflow runs CI and creates package artifacts using the selected input version,
but does not publish a GitHub release. Native installer checks run on Linux,
macOS and Windows; GoReleaser cross-builds both `x86_64` and `aarch64` assets
for all three platforms, creates the Windows ZIP and `SHA256SUMS`, and publishes
the matching version tag and release. It does not reject or rewrite commits
during normal CI.

## Offline configuration

See the [version 1 schema](../schemas/static-v1.schema.json) and [paired
examples](../examples/README.md). Unknown or duplicate YAML fields, invalid keys,
conflicting addresses/routes and endpoints captured by tunnel routes are
rejected before changing OS state. Endpoints are numeric IPv4:port or
`[IPv6]:port`; validation never performs DNS lookups. Private keys live in
`private_key_file`, resolved relative to the configuration file.
`network.cidr` is an optional canonical private IPv4 prefix for service-managed
networks; when supplied it must be between `/8` and `/30`. Offline static
configurations do not need it.

Linux/macOS keys must be regular, singly linked files owned by the effective
runtime user, with no group/other access (normally `0600`). macOS extended ACLs
are rejected too; remove them with `chmod -N`. Windows key files require an
allowlisted owner/DACL; only the current user, SYSTEM and Administrators may
have access. Symlinks/reparse points and broadly readable keys are rejected.
Parent directories must be trusted.

## Managed enrollment with join

To register with a network created in the service API and save its managed
configuration, run:

```sh
cat /secure/join-token.txt | sudo peerimeter-agent join
```

`join` generates a local WireGuard key if needed, registers its public key and
the default-route physical interface's addresses, then receives a tunnel IPv4
address from the network's API-configured CIDR. It selects a peer's LAN address
when the reported CIDRs overlap; otherwise it uses that peer's STUN-observed
public UDP mapping. It saves the managed configuration as
`<config-dir>/<network-id>.yaml` and the service credential, then exits without
starting a tunnel. To start it separately, run
`sudo peerimeter-agent daemon --config /etc/peerimeter/<network-id>.yaml` on
Linux or macOS. Starting the tunnel requires administrator/root privileges.
An installed service continues using its `service.yaml` snapshot and does not
load this per-network file. Install or update the native service to run the
daemon, which syncs its active joined network every five minutes by default.
The key, config, and shared service credential are stored in protected local
files. To refresh registration, repeat the same token and any original
`--node-id` and `--listen-port` values.
Without `--node-id`, the node ID defaults to the machine hostname; without
`--listen-port`, the port defaults to 51820. Changing either on a later Join
can register a different node or update the peer port. The shared token remains
stored after the command exits. If a `run` process is active, restart it after
changing `--node-id` or `--listen-port`; a running process keeps its loaded
configuration. Removing the protected
`state-dir/managed/<network-id>.token` file only deletes the local credential;
the service-side node record remains. There is not yet a `leave` command or
server-side node revocation API.

Join tokens require HTTPS by default, while HTTP URLs on `localhost` or a
loopback IP are allowed automatically for local development. For a non-local
service using plain HTTP, pass `--allow-insecure-http` to `join`. This sends the
shared enrollment token without TLS and should only be used on a trusted
network.

The dashboard uses the service-wide API key for management. An agent's join
token is scoped to its selected network. STUN is probed on the configured WireGuard
listen port during registration. If STUN is unavailable, same-LAN peers
can still connect. UDP hole punching is best-effort and direct-only: symmetric
NATs and UDP-blocking firewalls can prevent a connection. TURN/relay fallback
is not included. A CIDR match only chooses a LAN candidate; a WireGuard
handshake is still needed to verify reachability. Static `run --config` remains
fully independent of the service API.
Overlapping RFC1918 ranges do not prove that two machines share a reachable LAN;
if an unreachable LAN candidate is selected, join currently does not fall back
to the public endpoint automatically.
The advertised STUN mapping is captured during `join`; the current agent does
not re-probe it while the tunnel owns the UDP port, so a later public NAT
mapping change needs a new join/restart. If the system's default route uses a
virtual/VPN interface and no physical default route can be selected, `join`
fails closed instead of reporting another interface's addresses.

## Foreground and local control

```sh
sudo peerimeter-agent daemon --config /absolute/path/to/peer.yaml
sudo peerimeter-agent status
sudo peerimeter-agent status --watch
sudo peerimeter-agent sync       # refresh joined peers and reconcile the tunnel
sudo peerimeter-agent stop       # graceful tunnel/route cleanup
```

On Windows, run the same commands from an elevated terminal.

Use `run` instead of `daemon` when you want the tunnel without scheduled sync.
The daemon runs the same foreground tunnel and calls `sync` every five minutes
by default. Change the period with `--sync-interval` (for example,
`--sync-interval 2m`). A failed sync is logged and retried at the next interval;
it does not stop the tunnel. The native service installed by `service install`
uses `daemon` automatically.

For a network joined with `join`, `sync` refreshes this node's primary physical
interface and local addresses in its service registration, then downloads the
latest peer list and applies it to the configuration currently used by the
running agent. It verifies that the selected network matches the running
network. `--config`, when used, must identify that same active file; sync
refuses to update a different file. On Windows, sync also refuses UNC paths
for the active configuration. With one joined network, it is selected
automatically; with multiple networks, pass `--network-id`. Older joins may
need `--api-url` and `--node-id` once. Without saved service metadata, `sync`
keeps its local behavior and reloads the current configuration.

While the WireGuard tunnel owns its UDP listen port, `sync` cannot bind that
port for a STUN probe. In that case it preserves the last registered public
endpoint while publishing fresh local interface addresses. A changed public
NAT mapping therefore still requires a later successful endpoint probe; STUN
does not guarantee reachability.

| Command | Output or action |
| --- | --- |
| `status` | Readable local agent and adapter state; `--watch` refreshes continuously (`--json` for scripts) |
| `wg` / `wg show` | Traditional WireGuard-style interface and peer listing |
| `sync` | Refresh the joined node registration and peer list when available, then reconcile the tunnel; otherwise reload local configuration |
| `daemon` | Run the tunnel and sync periodically (default: every five minutes; set `--sync-interval` to change it) |
| `stop` | Stop the tunnel and clean up routes |

`status` reads actual local adapter state through a protected Unix socket or
Windows named pipe. `running` indicates interface state, not proven peer
connectivity; inspect real handshake timestamps and byte counters. A stopped or
unreachable agent returns an error.

`status --watch` refreshes the live status view every two seconds until you press
`q` or Ctrl-C. Set `--interval` to change the refresh period. With `--json`, watch
mode emits newline-delimited status snapshots until interrupted.

### Delegate local control

Control defaults to the runtime identity and, on Windows, SYSTEM/Administrators.
To delegate control without administrator privileges, start/install with
`--operator <username-or-UID>` on Unix or `--operator <account-or-SID>` on
Windows. The authorized operator can use `status`, `sync` and `stop`
without sudo or elevation; secret files stay private. On Unix the state
directory and its parents must permit traversal; only the socket owner receives
control access.

### Configuration, durable state and disposable runtime

| Platform | Config and private keys (`--config-dir`) | Persistent state (`--state-dir`) | Local control (`--runtime-dir`) |
| --- | --- | --- | --- |
| Linux, non-root | `$XDG_CONFIG_HOME/peerimeter-agent` (default `~/.config/peerimeter-agent`) | `$XDG_STATE_HOME/peerimeter-agent` (default `~/.local/state/peerimeter-agent`) | `$XDG_RUNTIME_DIR/peerimeter-agent` (state directory fallback) |
| macOS, non-root | `$XDG_CONFIG_HOME/peerimeter-agent` (default `~/.config/peerimeter-agent`) | `$XDG_STATE_HOME/peerimeter-agent` (default `~/.local/state/peerimeter-agent`) | `$XDG_RUNTIME_DIR/peerimeter-agent` (state directory fallback) |
| Linux, root | `/etc/peerimeter` | `/var/lib/peerimeter-agent` | `/run/peerimeter-agent` |
| macOS, root | `/etc/peerimeter` | `/Library/Application Support/Peerimeter` | `/var/run/peerimeter-agent` |
| Windows | `%ProgramData%\Peerimeter` | `%ProgramData%\Peerimeter` | `%ProgramData%\Peerimeter` |

Overrides must be absolute. Unix directories are separate; on Windows an
explicit `--state-dir` also supplies the default config/runtime location unless
overridden. `run --config <file>` uses the original file directly and never
relocates it; without `--config`, the installed `config-dir/service.yaml` is
used. Relative key references remain relative to the original YAML file.

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

`run --interface wg-prod` overrides YAML `interface.name` at initial setup. The
resolved selection persists and survives display-name changes. Implicit renames
and unrelated existing interfaces are rejected. Overrides are Linux-only; macOS
allocates an actual utun and Windows uses a stable network-derived alias.
The selected network and interface are stored in the private state file
`network.yaml`; an existing `network.json` is converted on the next run.

## Native service

Install the executable in a protected stable directory first. System service
installation requires administrator/root privileges and absolute paths:

```sh
sudo peerimeter-agent service install --config /absolute/path/to/peer.yaml --operator alice
sudo peerimeter-agent service start
sudo peerimeter-agent status
sudo peerimeter-agent service stop
sudo peerimeter-agent service uninstall
```

Windows uses the same subcommands in an elevated terminal. Replace `alice` with
an existing authorized local account. Installation snapshots the validated
config/key into protected `service.yaml` and `service.key` under the
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
# Per-user installation: run as the user who installed it. Choose one:
peerimeter-agent uninstall
peerimeter-agent uninstall --yes
peerimeter-agent uninstall --purge

# Root installation: choose one:
sudo peerimeter-agent uninstall
sudo peerimeter-agent uninstall --yes
sudo peerimeter-agent uninstall --purge

# Select a root installation in a custom program directory:
sudo peerimeter-agent uninstall --install-dir '/opt/Peerimeter Agent'
```

Use `--purge` instead of the standard uninstall when you also want to remove
all contents of the tracked state, config and runtime directories.

Installers write a protected installation inventory. Full removal refuses
arbitrary untracked paths, preserves unrelated files and original source
configs by default, stops the owned service/agent first, and verifies
ownership/locks before deletion. `--purge` additionally removes all contents
inside the recorded state, config, and runtime directories. Windows uses a
bounded helper after the running executable exits; a `pending` result names a
temporary receipt reporting eventual removal or remaining failures. The shared
system WireGuard driver is preserved. Repeated removal is safe; partial failures
remain reportable and retryable. Removal and
migration are natively verified; see the [shared project progress
tracker](https://github.com/peerimeter/.github/blob/main/docs/planning/progress.md)
for exact tested commits and remaining limits.

Without `--yes`, uninstall lists the files and directories to be removed and
asks for confirmation with the same terminal selector; non-terminal input
accepts `y` or `yes`. `--yes` skips the prompt for scripted use. Original source
config files outside the recorded directories remain untouched.

## CLI output

The traditional `wg show` listing (also the default for `wg`) is refactored from the [wgshow
example](https://github.com/zer0go/wgctrl-go/blob/47ad6fc7d7a95296fe893b49c1d4584b4eb6ac40/cmd/wgshow/main.go),
with [MIT attribution](../third_party/wgshow/README.md). It shows public keys,
endpoints, AllowedIPs, handshake age, traffic and keepalive. Private and
preshared keys never enter the renderer. Missing handshakes and clock skew are
explicit.

`status` uses responsive Lip Gloss tables for interface details and peer state.
Watch mode refreshes the view in place and exits with `q` or Ctrl-C. `wg` keeps
the traditional interface and peer listing. Example generation, validation,
service actions, sync, stop, uninstall and STUN also use tables. No extra branded heading is added. Help retains Cobra's
standard layout, and `version` retains its original unboxed, gradient-colored logo.
Runtime diagnostics continue to use console logging; completion output remains
valid shell code.

Use `--color auto|always|never` on any command; automatic color respects `NO_COLOR`,
`TERM=dumb` and redirected output. Plain output keeps the readable layout without
ANSI styling. `--json` bypasses result styling. `wg` and `wg show` return the
public peer array; `status` returns the complete public status snapshot.

```sh
peerimeter-agent status --watch
peerimeter-agent status --watch --interval 5s
peerimeter-agent wg          # defaults to wg show
peerimeter-agent wg show --color never
peerimeter-agent status --watch --json
```

Cobra provides contextual `--help` and `completion bash|zsh|fish|powershell`.
Root help renders environment variables and resolved directory paths in TUI
tables; `peerimeter-agent info` shows the same tables (or JSON with `--json`).
Running `peerimeter-agent` without arguments prints the version banner first,
then the help, and checks GitHub Releases. When a newer stable release is
available, it shows a boxed update notice recommending
`peerimeter-agent self-update`. `peerimeter-agent check-update` runs the same
check explicitly and supports `--json` (`current_version`, `latest_version`,
`update_available`, and, when available, the release URL and `update_command`);
`--help` never makes a network request. The automatic check has a short timeout
and does not prevent help from appearing when GitHub is unavailable.
Commands live in separate files under `internal/cli` (`root.go`, `run.go`,
`version.go`, `service_*.go`, etc.). `version` prints the orbit/P ASCII logo and
human-readable build details, with terminal-aware pink/purple color. Use
`version --json` for automation, `--color never` for plain output or `--color
always` to force ANSI; automatic color respects `NO_COLOR` and pipes.

Runtime logs use concise console formatting by default: uppercase level,
message and `key=value` attributes, without timestamps. For example,
`ERROR unknown error param1=test`. Levels are colored when stderr is an
interactive terminal. Set `PEERIMETER_LOG_FORMAT` to `text` for uncolored
console output or `json` for structured JSON logs. Console mode respects
`NO_COLOR` and does not emit ANSI codes when output is piped:

```sh
PEERIMETER_LOG_FORMAT=json peerimeter-agent run --config ./peer.yaml
PEERIMETER_LOG_FORMAT=text peerimeter-agent run --config ./peer.yaml
```

In PowerShell, set it for the current session with
`$env:PEERIMETER_LOG_FORMAT = 'json'` or `'text'` before starting the agent.

Static config loading errors include the file path and underlying operating system
or YAML decoding error. Add `--debug` to include the captured source stack trace:

```sh
peerimeter-agent validate-config --config ./peer-a.yaml --debug
```

Stack traces are omitted by default. Config values and private key contents remain
excluded from validation errors.

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

The [reference peer and original backend probes](../tests/backendprobe/README.md)
remain separate from agent acceptance. Mixed-OS VM connectivity and
NAT/IP-change recovery require dedicated topology and remain unverified;
separate hosted jobs are not a LAN. No cross-compilation result is treated as
native connectivity proof. See the [shared project progress
tracker](https://github.com/peerimeter/.github/blob/main/docs/planning/progress.md)
for exact tested commits and limitations.

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
`--server` option selects one server and disables fallback. The command prints
the bound local address and mapped public address in console format; pass
`--json` for machine-readable output. A STUN mapping alone does not establish
WireGuard connectivity or promise NAT traversal.

Command results default to readable console text, including example generation,
configuration validation, service actions, sync, stop and uninstall. Use `--json`
when a script needs the machine-readable result. For `run`, `--json` selects
newline-delimited structured JSON runtime logs on stderr; it does not change the
agent's normal stdout output. `PEERIMETER_LOG_FORMAT` controls diagnostic logs
unless `--json` is supplied. Config files use YAML; the local control protocol
remains JSON.

STUN uses a Bubble Tea progress indicator in an interactive terminal and prints
a table containing the STUN server, local address and mapped address on completion.
Press `q`, Escape or Ctrl+C to cancel. Redirected output and `TERM=dumb` use a
plain table without terminal control sequences; `stun --json` skips the UI.
