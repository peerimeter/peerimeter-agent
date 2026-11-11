export GOTOOLCHAIN := go1.27.4

.PHONY: test lint build test-integration test-network

test:
	go test ./...
lint:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal)"
build:
	go build -o bin/peerimeter-agent ./cmd/peerimeter-agent
test-integration:
	@echo 'Run the WireGuard backend feasibility GitHub workflow; see README.md for native scripts.'
	@exit 1
test-network:
	@echo 'blocked: Phase 1 agent tunnel implementation and reachable mixed-OS test infrastructure required.'
	@exit 1
