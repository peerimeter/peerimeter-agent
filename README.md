# peerimeter-agent

Headless, offline-first WireGuard mesh agent for Linux, macOS and Windows.
Independent Go module; no API/service repository is needed. Requires **Go 1.27.4**.

Phase 0 implements the strict static JSON contract, protected key handling,
Linux interface-name resolution, CLI validation, foreground lifecycle interfaces
and native CI. **The agent does not create tunnels or install services yet.**
`run`, `status` and `peers` currently return an explicit unavailable error (exit 3).
Real native tunnel and service implementations are Phase 1.

```sh
export GOTOOLCHAIN=go1.27.4
go test ./...
go vet ./...
go build -o bin/peerimeter-agent ./cmd/peerimeter-agent
./bin/peerimeter-agent version
./bin/peerimeter-agent generate-example --directory ./local-example
./bin/peerimeter-agent validate-config --config ./local-example/peer-a.json
./bin/peerimeter-agent validate-config --config ./local-example/peer-b.json
```

On Windows build `bin/peerimeter-agent.exe` and invoke that executable. The
example generator creates a **new** directory, two fresh X25519 keys and paired
JSON configs; it refuses to reuse a destination. Endpoints use loopback and
separate ports for a future same-host test; replace these with numeric reachable
IP:port endpoints for separate devices. Never commit generated private keys.
See [the version 1 schema](schemas/static-v1.schema.json) and
[example details](examples/README.md). Validation opens and checks the referenced
private key; relative key paths resolve against the configuration directory.
Commands output JSON and errors never echo configuration input or key content.
Static validation performs no network access (including DNS).

Private files on Linux/macOS must be regular, singly linked files owned by the
current effective user, with no group/other permissions (normally `0600`).
macOS extended ACLs are also rejected; remove them with `chmod -N`. Inherited
ACLs are checked before writing any new key bytes.
Windows uses a protected DACL at file creation; key loading checks the opened
file's owner and actual DACL. Only the current user, SYSTEM and Administrators
may have access. Null DACLs, broadly readable files and symlinks/reparse points
are rejected. Store keys in a trusted parent directory: ancestor directories
must not be writable by untrusted users. The eventual privileged service must
own or be explicitly authorized to read its keys.

Linux names derive from `pm-` plus lowercase ASCII letters/digits from the
network display name; runs of other characters become one hyphen. If the slug
exceeds 12 bytes use its first five bytes (trim trailing hyphen), `-`, and the
first six lowercase hexadecimal digits of SHA-256 of the immutable network ID.
An empty slug uses `pm-` plus the hash. Explicit names allow ASCII letters,
digits, `.`, `_`, `-`, at most 15 bytes, excluding `.` and `..`.
`--interface` overrides JSON `interface.name` at initial setup; both are
Linux-only. Phase 1 will persist the resolved choice and check actual OS and
managed-name collisions before interface creation; hash suffixes alone cannot
guarantee collision freedom.

GitHub Actions runs native build/unit/race/CLI checks on `ubuntu-24.04`,
`macos-15` and `windows-2022`. All jobs use exact Go 1.27.4. The separate
`wireguard-integration.yml` currently tests **backend feasibility**, with real
handshake, traffic in both directions, restart and teardown. These probes use
official WireGuard backends and a reference peer, not the unfinished agent.
See [probe instructions and pinned prerequisites](tests/backendprobe/README.md).
`connectivity-e2e.yml` deliberately reports **blocked** when dispatched until
Phase 1 and the required reachable test topology exist; it cannot establish
mixed-OS connectivity merely by scheduling separate runner VMs.

`make test`, `make lint` and `make build` cover the local baseline. Native
privileged scripts are documented in the probe README. `make test-integration`
and `make test-network` fail explicitly until the appropriate native setup/test
path is selected or implemented. No relay, control-plane calls, enrollment,
STUN, MQTT, web UI or updater is included in Phase 0.
