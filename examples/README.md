These two JSON files demonstrate the version 1 contract. They contain public
example keys and references to **absent private key files**. They are templates;
they cannot establish a tunnel as checked in.

Generate a fresh matching pair of configs and protected private keys locally:

```sh
go run ./cmd/peerimeter-agent generate-example --directory ./local-example
go run ./cmd/peerimeter-agent validate-config --config ./local-example/peer-a.json
go run ./cmd/peerimeter-agent validate-config --config ./local-example/peer-b.json
```

Run from the repository root. Do not commit `local-example` or its private keys.
Key paths inside the configs resolve relative to the config file, so working
directory changes do not change which credentials are loaded. The generator
refuses to overwrite an existing destination.

The loopback endpoints illustrate a same-machine test. Before deployment on two
machines, change each peer's endpoint to the other machine's reachable numeric
IPv4:port or `[IPv6]:port`. Each file describes one local interface and the other
peer. Public keys, AllowedIPs and ports must match the remote config. All three
platforms accept the same config when `interface.name` is omitted. Linux supports
an optional local name override; macOS and Windows reject it.

`validate-config` performs offline structural and semantic validation and checks
the private key's permissions. The schema in `schemas/static-v1.schema.json` is
for editors and structural validators; the Go validator also checks unicast
addresses, canonical AllowedIPs, overlapping routes, local address conflicts,
duplicate keys/endpoints, numeric endpoints, endpoint routing loops and platform
constraints. Endpoints must stay outside all tunnel address prefixes and peer
AllowedIPs; broad routes that capture the WireGuard transport are rejected. Private
keys stay in protected files. Validation errors omit raw input values.

Phase 0 does not yet create native interfaces. A successful config validation
or generated fixture is not evidence of an established WireGuard tunnel.
