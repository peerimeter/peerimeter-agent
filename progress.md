# Agent implementation progress

## Current status

✅ Phase 0 complete. ✅ Phase 1 complete after native verification and independent
review at `091bd40d115c7371e1c0f4cd0f18fb8f3ab71ca2`. ⬜ Phase 2 has not started.
Exact native evidence, review outcome and limitations are recorded below.

## Phase checklist

**Phase status:** ✅ Complete · 🔄 In progress · ⬜ Not started · ⛔ Blocked.
A passed test alone does not mean the phase is complete; Phase 1 and later also require the independent review gate.

| Phase | Status |
|---|---|
| 0 — Static contract and cross-platform baseline | ✅ Complete |
| 1 — Native offline WireGuard agent and services | ✅ Complete |
| 2 — Service, enrollment, sync | ⬜ Not started |
| 3 — NAT and recovery | ⬜ Not started |
| 4 — Browser dashboard | ⬜ Not started |
| 5 — External client gateways | ⬜ Not started |
| 6 — Resilience and packaging | ⬜ Not started |
| 7 — Hardening and agent self-update | ⬜ Not started |

## Completed implementation

- Independent `github.com/peerimeter/peerimeter-agent` module, Go 1.27.4.
- Strict version 1 static JSON contract and JSON schema; two public-only templates
  and `generate-example` for fresh paired protected keys/configs.
- Numeric endpoint validation without DNS; duplicate/overlap checks, transport
  route-recursion prevention, private-key references relative to config files.
- Linux deterministic safe interface-name derivation and ownership-check helper.
- POSIX key owner/mode/link checks; Windows handle-based owner/DACL validation
  and protected ACL creation; key material omitted from diagnostic errors.
- `validate-config`, `generate-example`, `version`, native `run`, protected local
  `status`, `peers`, `sync` and `stop` are operational. Cobra supplies help and
  completion. Systemd/launchd/SCM services and protected operator access work.
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

| Runner | Build/unit/CLI | Backend handshake/traffic/restart/cleanup | Native agent integration |
|---|---|---|---|
| ubuntu-24.04 | passed | passed | passed |
| macos-15 | passed | passed | passed |
| windows-2022 | passed | passed | passed |

## Limitations and next actions

Mixed-OS VM agent pairs and disruption/NAT recovery are not run. Linux integration
uses two agents in isolated namespaces; macOS/Windows use a native agent and an
independent userspace peer. Linux amd64, macOS arm64 and Windows amd64 are native
verified; other packaged architectures are cross-build only. One named native
service is currently supported per machine. Address changes on macOS/Windows
require explicit stop/start. Self-update remains Phase 7.

No public agent release has been published. Native installer tests exercise
latest/pinned URL resolution through explicit fixtures and install/execute real
packages; live `latest` downloads need a published release. Next choose a first
release or Phase 2 when requested. The service repository remains unstarted.

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

## Phase 1 implementation — native verification pending

Implemented actual Linux kernel/netlink/wgctrl, embedded macOS utun/wireguard-go,
and Windows WireGuardNT adapters with real snapshots and safe peer diff/reconcile.
Local protected Unix/named-pipe control supports status, peers, sync and stop;
OS-held state locks prevent competing managers. Linux name/ownership persistence
supports restarts. Systemd, launchd and SCM registration/lifecycle use the same
foreground runtime and protected installed config/key copies. Integration scripts
now exercise the actual agent, not only the independent backend probes.

Local diagnostic Go 1.26.4 with an external alternate manifest and CGO disabled
passed unit tests and Windows/macOS cross-builds. Exact Go 1.27.4 native unit/race,
real traffic/restart/cleanup and native service tests are required next. Installer,
release packaging and README work are in progress. No Phase 1 pass is claimed yet.

## Phase 1 first native runs and review fixes — 2026-11-11

- Native Go 1.27.4 unit/build/CLI jobs passed on all three platforms at
  `f4ac9a9bd4eee664560424b40b7776f265bd8678`
  ([run](https://github.com/peerimeter/peerimeter-agent/actions/runs/42947273846)).
- Actual macOS agent/utun traffic, reload/restart/cleanup and launchd lifecycle
  passed at `97875e80090541b0bd4687803f4b65b3abacdfa5`
  ([job](https://github.com/peerimeter/peerimeter-agent/actions/runs/42946353008/job/130280013296)).
- Initial Linux agent startup failed because RTM_NEWLINK omitted the interface
  alias. Explicit LinkSetAlias plus a regression fake fixed it. Actual two-agent
  traffic, in-place updates, invalid config preservation, graceful/SIGKILL recovery
  and systemd lifecycle passed at `b9feda7569396167d934d6c7b0b96318db8e5d83`
  ([job](https://github.com/peerimeter/peerimeter-agent/actions/runs/42947133477/job/130282512144)).
- Initial Windows build used nonexistent FILE_ADD_* constants; aliases corrected.
  The next actual agent/WireGuardNT and SCM traffic/restart assertions passed,
  but final cleanup failed on SYSTEM-owned metadata. The job remains **failed**
  ([job](https://github.com/peerimeter/peerimeter-agent/actions/runs/42947133477/job/130282511680)).
  Follow-up inherits admin ACLs for metadata and bounds privileged test cleanup.
- Independent reviewer `/root/phase1_review` (parent model inherited; concrete
  model identifier unavailable) found two P2 acceptance/correctness issues:
  failed service registration prevented retry/reinstall, and nonadmin operator
  control was unavailable. Implemented protected snapshot reuse/rollback with
  regression tests, plus explicit `--operator` delegation retaining private keys.
  Unix verifies peer UID even if socket permissions are widened; Windows uses
  client-only pipe rights. Final independent re-review is pending.
- Cobra v1.10.2 now owns CLI subcommands/flags/help/completion; parse errors remain
  redacted. Unix/PowerShell installers and six target release packages are ready
  for native CI, including pinned signed offline WireGuardNT and license notices.
- New native unit/integration/installer checks are pending after these changes.
  ✅ Phase 0 remains complete; 🔄 Phase 1 is not closed before native verification
  and independent follow-up review. Mixed-OS VM links remain not run. No release
  has been published; latest/pinned installer URL tests use explicit local fixtures.

## Verified Phase 1 core evidence — 2026-11-11 (expanded phase remains open)

- [Native unit/build/CLI](https://github.com/peerimeter/peerimeter-agent/actions/runs/42948951660): all three passed at `4246c6bea040bfa41a0bd506f0df501310a20367`, exact Go 1.27.4, vet/race/unit, static config/key permissions, Cobra help/completion.
- [Actual agent integration](https://github.com/peerimeter/peerimeter-agent/actions/runs/42948600470): all three passed at `04648b92b7bdc3635fdf12b56d2729667130538a`. Real authenticated handshake and traffic, in-place peer changes, invalid reload preservation, graceful restart/cleanup, systemd/launchd/SCM lifecycle and protected config/key preservation. Linux also verifies SIGKILL recovery, UID-based delegated control and authorization even after socket permission widening; Windows verifies a real nonadmin operator and private-key read denial.
- [Packages/installers](https://github.com/peerimeter/peerimeter-agent/actions/runs/42948951604): all six OS/architecture artifacts built at `4246c6b`; native Linux/macOS/Windows installer checks passed. Actual Unix archive installation and installed binary version/toolchain verified; actual Windows ZIP includes signed pinned WireGuardNT with no separate GUI/MSI. Tests cover latest/pinned URL fixtures, offline archives, custom/spaced paths, invalid checksums, preservation and Windows rollback. No public release was published.
- `4246c6b` differs from `04648b9` only by the extra Unix actual-package test step; runtime sources are identical. Runner images: Ubuntu 24.04 x64 `20261101.360.1`; macOS 15 arm64 `20261104.0514.1`; Windows 2022 x64 `20261101.353.1` (recorded in evidence artifacts).
- Independent reviewer `/root/phase1_review` **passed** final code at `4246c6bea040bfa41a0bd506f0df501310a20367`. Parent model was inherited; concrete model identifier unavailable. No blocking findings remain. Four findings fixed and rechecked: failed install retry/reinstall, delegated nonadmin IPC, Cobra/service script arguments, and concurrent installer snapshot rollback. The latter has a barrier-controlled regression test that failed before the lock fix and passed afterward. Review is independent of platform implementation agents.
- Prior failures are preserved in agent progress.md: Linux alias initialization, Windows FILE_ADD_* constants, SYSTEM metadata cleanup ACLs, stale service script flags and Python Windows UTF-8 decoding; all resolved in the successful runs above.
- ✅ Phase 0 complete; 🔄 Phase 1 in progress; ⬜ Phase 2 not started. Historical “Phase 1 pending” entries above are superseded by this dated completion record.

## 🔄 Phase 1 scope extension — plan commit a022780

The current plan adds mandatory Unix config/state/runtime directory separation,
safe migration and a complete top-level uninstall with dry-run, installation
inventory and native removal tests. These were not part of the implementation
reviewed at 4246c6b and are not complete. The independent review caught the overly
broad checklist marking before it was committed. Phase 1 remains in progress;
all earlier core test passes remain valid evidence, not full-phase completion.

## 🔄 Extended Phase 1 implementation — native gate pending

The current working increment implements the new a022780 requirements: separate
Unix config/state/runtime layouts and explicit legacy service migration; protected
installation inventories; top-level full uninstall/dry-run with ownership-bound
resource deletion, read-only preview, safe retries and a bounded Windows removal
helper reporting pending/result receipts. service uninstall still preserves keys.

Additional user requests are implemented: centralized ifname.DefaultPrefix,
Cobra command-per-file factories, orbit/P ASCII version branding with terminal
pink/purple and `version --json`, and refactored wgshow-style public peer rendering
with `peers --json`. MIT source attribution/license is included with packages.

Early independent review found and drove fixes for deferred-removal startup
races, runtime ownership confusion and unhealthy-network shutdown. Startup leases,
durable Removing state, bound runtime/profile markers, health-independent identity
IPC, held state/runtime locks and teardown callbacks now enforce these boundaries.
Regression tests cover them; native tests additionally exercise two installed
agents sharing a runtime, queued old executables, defaults/custom paths, actual
legacy-binary migration, complete removal and preservation of unrelated/source data.

Local diagnostic Go 1.26.4 tests/vet passed using the external alternate manifest,
CGO disabled and a private logical /tmp (the Termux physical TMPDIR ancestors are
correctly rejected as writable). Windows/macOS builds passed. These are not the
required native Go 1.27.4 evidence: new native CI and final independent review are
pending. ✅ Phase 0 remains complete; 🔄 Phase 1 remains open until those gates pass.

## Closing review and native follow-up — 2026-11-11

At `8f247070fb6c4ff571c0de58b8c85196f4d1d9da`,
[Native CI](https://github.com/peerimeter/peerimeter-agent/actions/runs/42998147614)
passed exact Go 1.27.4 vet/race/unit/build/CLI checks on all three platforms.
[Integration](https://github.com/peerimeter/peerimeter-agent/actions/runs/42998147627)
and [package/installer tests](https://github.com/peerimeter/peerimeter-agent/actions/runs/42998147753)
failed; follow-up corrects legacy profile planning before configuration claim,
Windows helper SHA-256 hashing without PowerShell module dependencies, Unix
installer symlink expectations and macOS default resource ancestor preparation.
Product trusted-path checks remain enforced.

Independent reviewer `/root/phase1_review` reviewed exact `8f24707` (inherited
parent model; concrete model identifier unavailable). Config ownership, runtime
identity, migration tracking and held Windows deletion guards passed review.
The remaining blocker requires detecting service registrations belonging to this
executable even when an upgraded pre-inventory installation has no service
profile. Follow-up adds a conservative pre-deletion guard and regression tests.
Final independent delta review and fresh native runs are still required.

## ✅ Phase 1 accepted — 2026-11-11

Final tested and independently reviewed implementation:
`091bd40d115c7371e1c0f4cd0f18fb8f3ab71ca2`. Subsequent completion records and
README status updates change documentation only.

| Gate | Linux amd64 | macOS arm64 | Windows amd64 |
| --- | --- | --- | --- |
| [Native Go 1.27.4 CI](https://github.com/peerimeter/peerimeter-agent/actions/runs/43002033268) — format, vet, race/unit, build and CLI | passed | passed | passed |
| [Actual WireGuard agent integration](https://github.com/peerimeter/peerimeter-agent/actions/runs/43002033188) | passed | passed | passed |
| [Native packages and installers](https://github.com/peerimeter/peerimeter-agent/actions/runs/43002033328) | passed | passed | passed |

All six Linux/macOS/Windows amd64/arm64 packages built successfully. Native
receipts report the exact final SHA and images Ubuntu 24.04 x64
`20261101.360.1`, macOS 15 arm64 `20261104.0514.1`, Windows 2022 x64
`20261101.353.1`.

Expanded acceptance includes default/custom/spaced config/state/runtime paths,
Unix reboot-style runtime recreation and live migration from actual `4246c6b`
legacy services, ownership-bound configuration/runtime claims, protected
operator access, read-only removal previews, live full removal, changed-file
refusal, retries/idempotency and unrelated/source credential preservation.
Windows additionally verifies signed bundled WireGuardNT, standard ProgramData
ACLs, custom ProgramData program paths and bounded executable self-removal.
All four agent READMEs have consistent navigation, headings, tables, code blocks
and verified local links; stale backend probe descriptions were corrected.
Cobra file organization, centralized prefix, branded version/color/JSON and
refactored public wgshow peer presentation with MIT attribution are complete.

Independent reviewer `/root/phase1_review` **passed code review and final phase
acceptance** at the exact SHA above after inspecting native receipts and Windows
logs. The reviewer inherited the parent model; a concrete model identifier is
unavailable. All blocking findings are resolved: cross-installation config/runtime
ownership, removal/startup exclusion and Windows lock deletion, unhealthy-state
shutdown, provisional migration tracking, untracked native service detection and
ambiguous registration refusal. Native follow-up also fixed asynchronous legacy
shutdown, explicit private test fixtures, PowerShell helper hashing and narrow
standard shared-root ACL handling. No blocking or deferred code findings remain.

Limits remain explicit: Linux tests two actual agents in isolated namespaces;
macOS/Windows test the native agent against an independent userspace WireGuard
peer. Mixed-OS VM links and NAT/network-disruption recovery are **not run**;
other packaged architectures are cross-build only. No public release was
published, so live latest-release downloads remain unverified (URL resolution is
fixture-tested with actual native packages). These limits belong to the later
network/resilience/release work and are not claims of verified connectivity.

✅ Phase 0 complete · ✅ Phase 1 complete · ⬜ Phase 2 not started.

## 🔄 Phase 1 add-on: STUN probe command

Implemented `peerimeter-agent stun [local-udp-port]` with the standard-library RFC
5389 UDP Binding exchange. Omitting the port binds an OS-assigned available port;
passing a port binds it explicitly. The command emits JSON with the bound local
address and STUN-mapped public endpoint, supports `--server`, handles IPv4/IPv6
servers, validates responses and closes the socket. README usage is documented.

A local Go 1.26.4 diagnostic build passed with the external temporary manifest;
Windows amd64 and macOS arm64 cross-builds passed. The installed Go 1.27.4
segfaults in this Termux/Nix environment, so native Go 1.27.4 CI is pending.
No live STUN request or native per-OS port test was run in this turn. Phase 1's
original accepted scope remains complete; STUN add-on native review/verification
is pending.
