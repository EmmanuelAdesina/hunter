# hunter - personal bug-bounty opportunity monitor
#
# Every target is a thin wrapper around `go`. Behaviour lives in the binary, not
# here, so that what CI runs and what runs locally cannot drift apart.

BINARY  := bin/hunter
PKG     := ./cmd/hunter
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

# The scan runs on the VPS as a systemd timer; see deploy/. A static Linux
# binary is what gets installed there.
LINUX_BINARY := bin/hunter-linux

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets.
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the binary.
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)
	@echo "built $(BINARY)"

.PHONY: test
test: ## Run the test suite.
	go test -count=1 ./...

.PHONY: race
race: ## Run the test suite under the race detector. Requires cgo and a C compiler.
	@command -v gcc >/dev/null 2>&1 || { \
		echo "the race detector needs cgo and a C compiler (gcc); skipping" >&2; exit 1; }
	CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: cover
cover: ## Run tests and report coverage.
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -n 1

.PHONY: fmt
fmt: ## Format the tree.
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if anything is unformatted.
	@unformatted="$$(gofmt -l . | grep -v '^$$' || true)"; \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet.
	go vet ./...

.PHONY: check
check: fmt-check vet build test ## Everything CI runs before building.

.PHONY: linux
linux: ## Build the static Linux binary the VPS runs.
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 		go build -trimpath -ldflags "$(LDFLAGS)" -o $(LINUX_BINARY) $(PKG)
	@echo "built $(LINUX_BINARY)"

.PHONY: deploy
deploy: linux ## Build and copy the Linux binary plus the deploy files to a host.
	@echo "run: scp $(LINUX_BINARY) deploy/ <host>:/tmp/ && ssh <host> 'sudo BINARY=/tmp/hunter-linux ./install.sh'"

.PHONY: validate
validate: build ## Validate the profile.
	$(BINARY) validate-config

.PHONY: fixtures
fixtures: build ## Re-parse the recorded upstream fixtures.
	$(BINARY) test-fixtures

.PHONY: scan
scan: build ## Run a dry-run scan against the live source.
	./scripts/local-scan.sh

.PHONY: scan-live
scan-live: build ## Run a scan that can send email. Requires the delivery variables.
	./scripts/local-scan.sh --live

.PHONY: programs
programs: build ## List known programs.
	$(BINARY) programs

.PHONY: eligible
eligible: build ## List programs the profile accepts.
	$(BINARY) programs --eligible

.PHONY: alerts
alerts: build ## List recorded alerts.
	$(BINARY) alerts

.PHONY: clean
clean: ## Remove build output. State and fixtures are left alone.
	rm -rf bin dist coverage.out
