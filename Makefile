# Crust Makefile

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BINARY_NAME = crust
BUILD_DIR = build
LDFLAGS = -ldflags "-s -w -X main.Version=$(VERSION)"

# Platforms for release
PLATFORMS = darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

.PHONY: all build clean test test-unit test-e2e test-all test-data release install lint vulncheck semgrep help build-bpf install-bpf uninstall-bpf

all: build

## Build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

## Run unit tests
test: test-unit

test-unit:
	go test -v ./...

## Run E2E sandbox tests
test-e2e: test-data
	go test -v -tags=sandbox_e2e -timeout=5m ./internal/sandbox/...

## Run all tests (unit + E2E)
test-all: test-unit test-e2e
	@echo "All tests complete"

## Create test data for E2E tests
test-data:
	@if [ ! -d /test-data ]; then \
		echo "Creating test data..."; \
		sudo mkdir -p /test-data/.ssh /test-data/secrets /test-data/project; \
		echo "SECRET=test" | sudo tee /test-data/.env > /dev/null; \
		echo "LOCAL=test" | sudo tee /test-data/.env.local > /dev/null; \
		echo "fake-rsa-key" | sudo tee /test-data/.ssh/id_rsa > /dev/null; \
		echo "fake-ed25519" | sudo tee /test-data/.ssh/id_ed25519 > /dev/null; \
		echo '{"key":"secret"}' | sudo tee /test-data/secrets/credentials.json > /dev/null; \
		echo "password: test" | sudo tee /test-data/secrets/secrets.yaml > /dev/null; \
		echo "package main" | sudo tee /test-data/project/main.go > /dev/null; \
		echo "# README" | sudo tee /test-data/project/README.md > /dev/null; \
		echo "hello" | sudo tee /test-data/project/data.txt > /dev/null; \
		sudo chmod -R 755 /test-data; \
		sudo chown -R $$USER /test-data 2>/dev/null || true; \
		echo "Test data created at /test-data"; \
	fi

## Run Go linter
lint:
	golangci-lint run ./...

## Check dependencies for known vulnerabilities
vulncheck:
	govulncheck ./...

## Run semgrep SAST scan
semgrep:
	semgrep scan --config auto .

## Build bpf-helper binary (Linux only)
build-bpf:
	go build $(LDFLAGS) -o bpf-helper ./cmd/bpf-helper/

## Install bpf-helper and systemd service
install-bpf: build-bpf
	@if [ "$$(uname -s)" != "Linux" ]; then echo "bpf-helper is Linux-only"; exit 1; fi
	sudo install -d /usr/libexec/crust
	sudo install -m 755 bpf-helper /usr/libexec/crust/bpf-helper
	sudo cp init/crust-bpf@.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "Installed bpf-helper to /usr/libexec/crust/"
	@echo ""
	@echo "Enable for your user:"
	@echo "  sudo systemctl enable --now crust-bpf@$$(whoami).service"

## Uninstall bpf-helper and systemd service
uninstall-bpf:
	@if [ "$$(uname -s)" != "Linux" ]; then echo "bpf-helper is Linux-only"; exit 1; fi
	-sudo systemctl stop "crust-bpf@$$(whoami).service" 2>/dev/null
	-sudo systemctl disable "crust-bpf@$$(whoami).service" 2>/dev/null
	-sudo rm -f /usr/libexec/crust/bpf-helper
	-sudo rm -f /etc/systemd/system/crust-bpf@.service
	-sudo rm -rf "/etc/systemd/system/crust-bpf@$$(whoami).service.d"
	sudo systemctl daemon-reload
	@echo "Uninstalled bpf-helper"

## Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f bpf-helper
	rm -rf $(BUILD_DIR)

## Install to /usr/local/bin
install: build
	sudo mv $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

## Build release tarball for current platform
release: clean
	@mkdir -p $(BUILD_DIR)
	@os=$$(go env GOOS); \
	arch=$$(go env GOARCH); \
	output=$(BUILD_DIR)/$(BINARY_NAME)-$(VERSION)-$$os-$$arch; \
	mkdir -p $$output; \
	echo "Building $$os/$$arch..."; \
	CGO_ENABLED=1 go build $(LDFLAGS) -o $$output/$(BINARY_NAME) .; \
	tar -czf $$output.tar.gz -C $$output $(BINARY_NAME); \
	rm -rf $$output; \
	echo "Created: $$output.tar.gz"

## Show help
help:
	@echo "Crust Makefile"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build for current platform"
	@echo "  test            Run unit tests (alias for test-unit)"
	@echo "  test-unit       Run unit tests"
	@echo "  test-e2e        Run E2E sandbox tests"
	@echo "  test-all        Run all tests (unit + E2E)"
	@echo "  lint            Run Go linter"
	@echo "  vulncheck       Check deps for known CVEs (govulncheck)"
	@echo "  semgrep         Run semgrep SAST scan"
	@echo "  clean           Clean build artifacts"
	@echo "  install         Install to /usr/local/bin"
	@echo "  build-bpf       Build bpf-helper (Linux only)"
	@echo "  install-bpf     Install bpf-helper + systemd service"
	@echo "  uninstall-bpf   Remove bpf-helper + systemd service"
	@echo "  release         Build release tarball"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION    Release version (default: git tag or 'dev')"
