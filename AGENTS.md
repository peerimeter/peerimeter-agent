# Repository guidance

This is the independent `peerimeter-agent` Go repository. The sibling `../.github` directory is a separate Git repository. Its `docs/planning/` directory contains the project plan, additional requirements, progress tracker, and historical Codex handoff. Consult those documents for scope and decisions, then check this repository's current code, `README.md`, and `progress.md` for actual behavior and verification.

## Project map

- `cmd/peerimeter-agent/`: CLI entry point; `internal/cli/`: Cobra commands and local orchestration.
- `internal/config/` and `schemas/static-v1.schema.json`: versioned static JSON configuration and validation.
- `internal/secret/`, `internal/installstate/`, `internal/paths/`: private keys, installation state, and directory rules.
- `internal/agent/`, `internal/platform/`, `internal/local/`, `internal/service/`: runtime, OS WireGuard backends, local control, and native services.
- `internal/stunprobe/`: standalone UDP STUN probe; `internal/presentation/`: peer output.
- `examples/`: static configuration examples; `docs/`: published installer site and install scripts.
- `.github/workflows/`: native CI, integration, packaging, release, and connectivity availability checks; `scripts/ci/`: their supporting scripts.
- `README.md`: operating instructions; `progress.md`: agent-specific evidence and limitations.

## Development

- Use Go `1.27.4` as pinned by `go.mod` and `.go-version`. The module must build independently of a future service repository.
- Current operation is offline static JSON with direct WireGuard peers. There is no enrollment or control-plane API. STUN reports an observed UDP mapping; it does not establish connectivity or guarantee traversal through NAT/firewalls.
- Preserve Linux, macOS, and Windows behavior. Changes to config, keys, interfaces, services, installation, or cleanup need careful platform-specific review. Never weaken secret-file permissions or ownership checks to make a test pass.
- Run checks relevant to a code change: `make lint`, `make test`, and `make build` for general Go changes; use the native integration workflows and `make test-integration` when network or service behavior changes and the required environment is available. Report unavailable or blocked native checks honestly. `make test-network` currently records an unavailable mixed-OS/NAT topology.
- Do not commit private keys, tokens, generated configs containing secrets, or production credentials. Keep examples clearly separate from usable credentials.
- Commits and pushes to a feature/PR branch are allowed. Use Conventional Commits messages, such as `feat(agent): support multiple generated peers` or `fix(stun): handle failed probes`. Open a PR for review; do not push work directly to `main` unless explicitly requested.
- For phase-completion claims, follow the independent review and evidence requirements in `../.github/docs/planning/plan.md`; record the actual reviewed SHA and native results in the relevant progress tracker.
