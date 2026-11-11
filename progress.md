# Agent implementation progress

## Current status

Phase 0 in progress. First native Go 1.27.4 CI run passed Linux/macOS and failed Windows; backend feasibility passed all three OSes.
No agent-managed WireGuard tunnel or service implementation is claimed.

## Phase checklist

| Phase | Status |
|---|---|
| 0 — Static contract and cross-platform baseline | In progress |
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
- No native runner result is recorded until the actual workflow runs complete.

## Verification matrix

| Runner | Build/unit/CLI | Backend handshake/traffic/restart/cleanup | Agent connectivity/E2E |
|---|---|---|---|
| ubuntu-24.04 | passed | passed | not run |
| macos-15 | passed | passed | not run |
| windows-2022 | failed | passed | not run |

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
