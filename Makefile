SHELL := /usr/bin/env bash
.SHELLFLAGS := -euo pipefail -c

SCRIPT := setup-tor-guard-relay.sh
SHELL_FILES := $(SCRIPT) $(wildcard scripts/*.sh tests/*.bash tests/*.bats tests/integration/*.sh)
export PATH := $(CURDIR)/.tools/bin:$(PATH)

.PHONY: help check tools lint fmt test integration dist render-screenshots clean

help: ## Show this help
	@awk -F ':.*## ' '/^[a-z-]+:.*## / { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

check: lint test ## Lint and run every local test suite (CI minus containers)

tools: ## Install the pinned shellcheck, shfmt and bats into .tools/
	scripts/install-dev-tools.sh

lint: tools ## Bash syntax, ShellCheck, and shfmt formatting check
	bash -n $(SCRIPT)
	shellcheck $(SHELL_FILES)
	shfmt --diff $(SHELL_FILES)

fmt: tools ## Rewrite shell files with shfmt
	shfmt --write $(SHELL_FILES)

test: tools ## Unit, stubbed-system, and end-to-end dry-run suites
	bats --timing tests/
	python3 -m py_compile scripts/render-readme-screenshots.py

integration: ## Real Tor apt install + tor --verify-config in a Debian container
	docker run --rm -v "$(CURDIR):/src:ro" -w /src debian:trixie tests/integration/tor-repo.sh

dist: ## Build release assets and SHA256SUMS into dist/
	rm -rf dist && mkdir -p dist
	install -m 0755 $(SCRIPT) dist/$(SCRIPT)
	cd dist && sha256sum $(SCRIPT) > SHA256SUMS && sha256sum --check SHA256SUMS

render-screenshots: ## Re-render README screenshots from /tmp/tor-relay-dry-run.txt
	python3 scripts/render-readme-screenshots.py /tmp/tor-relay-dry-run.txt

clean: ## Remove build output and the local toolchain
	rm -rf dist .tools
