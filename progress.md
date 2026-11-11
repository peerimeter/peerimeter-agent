# Agent implementation progress

## Current status

Phase 0 complete: baseline natively verified on all three platforms with Go 1.27.4, including backend feasibility. Phase 1 is next and remains not started; operational run/status/peers are its native/IPC runtime requirements.
No agent-managed WireGuard tunnel or service implementation is claimed.

## Phase checklist

| Phase | Status |
|---|---|
| 0 — Static contract and cross-platform baseline | Complete |
| 1 — Native offline WireGuard agent and services | Not started |
| 2 — Service, enrollment, sync | Not started |
| 3 — NAT and recovery | Not started |
| 4 — Browser dashboard | Not started |
| 5 — External client gateways | Not started |
| 6 — Resilience and packaging | Not started |
| 7 — Hardening and agent self-update | Not started |

## Completed implementation

- Independent `github.com/peerimeter/peerimeter-agent` module, Go 1.27.4.
- Strict version 1 static JSON contract and JSON schema; two public-only templates
  and `generate-example` for fresh paired protected keys/configs.
- Numeric endpoint validation without DNS; duplicate/overlap checks, transport
  route-recursion prevention, private-key references relative to config files.
- Linux deterministic safe interface-name derivation and ownership-check helper.
- POSIX key owner/mode/link checks; Windows handle-based owner/DACL validation
  and protected ACL creation; key material omitted from diagnostic errors.
- `validate-config`, `generate-example`, `version` are functional offline.
  `run`, `status`, `peers` explicitly return unavailable (exit 3) pending Phase 1.
- Testable platform backend/session contracts and cancellation/cleanup lifecycle.
- Three independent workflows: native baseline, real backend feasibility, and
  explicitly blocked connectivity E2E until agent/topology implementation.

## Tests executed

- Local Go 1.27.4 automatic toolchain downloaded, but even `go version` terminates
  with signal SIGSEGV (exit 139) in this Termux/Nix ARM64 environment.
- Diagnostic fallback only: installed Go 1.26.4 using a temporary alternate
  manifest outside this repo passed `go test ./...`, `go vet ./...`, CLI build
  and generated-example/validation smoke tests. This is **not** Go 1.27.4 proof.
- All three workflows pass actionlint; Bash scripts pass `bash -n`.
- Pinned official Unix `wg` source built locally successfully.
- Local race check is unavailable: ThreadSanitizer rejects this ARM64 VMA layout.
- Native runner results are recorded below with the exact tested code commit.

## Verification matrix

| Runner | Build/unit/CLI | Backend handshake/traffic/restart/cleanup | Agent connectivity/E2E |
|---|---|---|---|
| ubuntu-24.04 | passed | passed | not run |
| macos-15 | passed | passed | not run |
| windows-2022 | passed | passed | not run |

## Limitations and next actions

Run the exact-version native matrix and backend feasibility workflow on GitHub;
record tested commit, run links and artifacts. Native backend feasibility does
not prove agent integration. Implement real adapters, persisted interface
selection and actual OS collision checks, foreground runtime, local IPC and
service management in Phase 1. Windows installer must bundle the official signed
WireGuardNT component and work offline; the test-only official MSI install is
not the product installer. NAT/IP-change and mixed-OS agent E2E remain blocked.
No `peerimeter-service` implementation before the offline agent milestone.

## Decisions

No relay or desktop UI. No static-mode API/MQTT/STUN dependency. See README for
the exact interface-name algorithm and trusted-parent key storage requirement.
Go 1.27.4 is pinned by project requirement. Self-update belongs to Phase 7.

## Native evidence — 2026-11-11, commit ebb4a1f880e39e2ca1003d9551c185a76ee81069

- [Native CI](https://github.com/peerimeter/peerimeter-agent/actions/runs/42942950063):
  Linux and macOS passed exact Go 1.27.4 build, vet, race tests and CLI smoke.
  Windows failed at the shell version/format gate before tests. Follow-up adds
  LF checkout policy, CR normalization and visible formatting diagnostics.
- [WireGuard backend feasibility](https://github.com/peerimeter/peerimeter-agent/actions/runs/42942949983):
  all three platforms passed actual native interface/route creation, authenticated
  handshake, traffic initiated in both directions, restart and cleanup. This is
  backend feasibility, not agent integration or mixed-OS connectivity.
- Follow-up adds macOS opened-descriptor extended ACL checks and native ACL tests.
  All modified code needs a new native CI run before claiming verification.

## Follow-up native evidence — 2026-11-11

[Native CI](https://github.com/peerimeter/peerimeter-agent/actions/runs/42943244505)
passed on **all three** runners at tested commit
`ef0abfcf23c385355f383eeda69509eb33dc2962`: exact Go 1.27.4, formatting,
vet, race/unit tests, build, version, fresh protected example generation and
both configurations validated offline. The Windows gate failure from the initial
run is resolved. macOS extended-ACL tests pass natively, including inherited
read ACL rejection before key bytes are written. Windows DACL positive/negative
tests also pass natively.

Backend feasibility remains verified at
`ebb4a1f880e39e2ca1003d9551c185a76ee81069`, separate from the CLI test commit.
Ubuntu x64 image `20261101.360.1`, macOS ARM64 image `20261104.0514.1`, Windows x64
image `20261101.353.1`. Backend prerequisites and exact source/MSI pins are in
`tests/backendprobe/README.md`; evidence artifacts contain no secret material.
No agent connectivity, service lifecycle or cross-OS connectivity pass is claimed.

Next: implement the real Phase 1 adapters/IPC so `run`, `status`, `peers` and
service commands become operational. The other Phase 0 checklist items are
implemented and natively tested. The service repository remains unstarted.

## Phase boundary clarification — 2026-11-11

The planning contract now separates the implemented Phase 0 command/argument
surface, functional offline validation and testable lifecycle/backend interfaces
from the operational `run`, local `status`/`peers`, IPC and services required in
Phase 1. The earlier decision to hold Phase 0 open for these runtime commands is
superseded. Phase 0 is complete using the native evidence above; Phase 1 remains
not started. This is a scheduling/documentation correction with no new runtime
implementation or test pass claimed. Runtime-dependent commands still return
explicit unavailable errors until native backends are implemented.
