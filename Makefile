SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := bin/tor-relay-setup
SHELL_SCRIPTS := install.sh docs/demo/demo-env.sh scripts/install-dev-tools.sh
export PATH := $(CURDIR)/.tools/bin:$(PATH)

.PHONY: help check build test cover lint vuln integration demo snapshot tools clean

help: ## Show this help
	@awk -F ':.*## ' '/^[a-z-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

check: lint test vuln ## Everything CI runs locally, except containers

build: ## Build a static binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/tor-relay-setup

test: ## Unit and dry-run tests with the race detector
	go test -race -count=1 ./...

cover: ## Test coverage report (coverage.html)
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	go tool cover -func=coverage.out | tail -1

tools: ## Install the pinned golangci-lint, ShellCheck and shfmt into .tools/
	scripts/install-dev-tools.sh

lint: tools ## golangci-lint (incl. gofmt/goimports), ShellCheck and shfmt
	golangci-lint run ./...
	shellcheck $(SHELL_SCRIPTS)
	shfmt --diff $(SHELL_SCRIPTS)

vuln: ## Known-vulnerability scan of the module and its dependencies
	go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...

integration: ## Real Tor apt setup, keygen and tor --verify-config in a Debian container
	CGO_ENABLED=0 go test -c -tags integration -o bin/itest ./internal/integration
	docker run --rm -v "$(CURDIR)/bin/itest:/itest:ro" debian:trixie /itest -test.v

demo: build ## Re-record docs/assets/*.gif with VHS (needs vhs, ttyd, ffmpeg)
	PATH="$(CURDIR)/bin:$$PATH" vhs docs/demo/setup.tape
	PATH="$(CURDIR)/bin:$$PATH" vhs docs/demo/console.tape

snapshot: ## Local release build with GoReleaser (no publish)
	goreleaser release --snapshot --clean

clean: ## Remove build output and the local toolchain
	rm -rf bin dist coverage.out coverage.html .tools
