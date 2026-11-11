
.PHONY: test lint build test-integration test-network

test:
	go test ./...
lint:
	go vet ./...
	@test -z "$$(gofmt -l cmd internal)"
build:
	go build -o bin/peerimeter-agent ./cmd/peerimeter-agent
test-integration:
	bash scripts/ci/run-agent-integration.sh
test-network:
	@echo 'blocked: mixed-OS and NAT/disruption topology is not configured; use test-integration for native agent links.'
	@exit 1
