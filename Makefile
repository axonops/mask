.DEFAULT_GOAL := help
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

GO           ?= go
GOBIN        ?= $(shell $(GO) env GOPATH)/bin
GOLANGCI     ?= $(GOBIN)/golangci-lint
GOIMPORTS    ?= $(GOBIN)/goimports
GOVULNCHECK  ?= $(GOBIN)/govulncheck
GORELEASER   ?= goreleaser

GO_FILES     := $(shell find . -type f -name '*.go' -not -path './.git/*' 2>/dev/null)
PKG          := ./...
BDD_PKG      := ./tests/bdd/...
COVER_OUT    := coverage.out
COVER_HTML   := coverage.html

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage: make \033[36m<target>\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: check
check: fmt-check vet lint tidy-check test test-bdd coverage security ## Run the full quality gate (mirrors CI)

.PHONY: test
test: ## Run unit tests with race detector
	$(GO) test -race -count=1 $(PKG)

.PHONY: test-bdd
test-bdd: ## Run BDD tests
	@if [ -d tests/bdd ]; then \
		$(GO) test -race -count=1 -tags bdd $(BDD_PKG); \
	else \
		echo "tests/bdd not present yet — skipping BDD run"; \
	fi

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI) run $(PKG)

.PHONY: vet
vet: ## Run go vet
	$(GO) vet $(PKG)

.PHONY: fmt
fmt: ## Auto-format Go source files
	$(GO) fmt $(PKG)
	@if command -v $(GOIMPORTS) >/dev/null 2>&1; then $(GOIMPORTS) -w $(GO_FILES); fi

.PHONY: fmt-check
fmt-check: ## Fail if any Go file is unformatted
	@out=$$(gofmt -s -l .); if [ -n "$$out" ]; then echo "gofmt diff:"; echo "$$out"; exit 1; fi
	@if command -v $(GOIMPORTS) >/dev/null 2>&1; then out=$$($(GOIMPORTS) -l .); if [ -n "$$out" ]; then echo "goimports diff:"; echo "$$out"; exit 1; fi; fi

.PHONY: bench
bench: ## Run benchmarks
	$(GO) test -bench=. -benchmem -run=^$$ $(PKG)

.PHONY: coverage
coverage: ## Generate coverage profile and HTML report for the library
	$(GO) test -race -coverprofile=$(COVER_OUT) -covermode=atomic .
	$(GO) tool cover -func=$(COVER_OUT) | tail -1
	$(GO) tool cover -html=$(COVER_OUT) -o $(COVER_HTML)

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go mod tidy would modify go.mod or go.sum
	@cp go.mod go.mod.bak
	@[ -f go.sum ] && cp go.sum go.sum.bak || true
	@$(GO) mod tidy
	@if ! diff -q go.mod go.mod.bak >/dev/null; then mv go.mod.bak go.mod; [ -f go.sum.bak ] && mv go.sum.bak go.sum || true; echo "go.mod drift — run 'make tidy'"; exit 1; fi
	@if [ -f go.sum ] && [ -f go.sum.bak ] && ! diff -q go.sum go.sum.bak >/dev/null; then mv go.sum.bak go.sum; mv go.mod.bak go.mod; echo "go.sum drift — run 'make tidy'"; exit 1; fi
	@rm -f go.mod.bak go.sum.bak

.PHONY: security
security: ## Run govulncheck
	@if command -v $(GOVULNCHECK) >/dev/null 2>&1; then \
		$(GOVULNCHECK) $(PKG); \
	else \
		echo "govulncheck not installed — skipping (install: go install golang.org/x/vuln/cmd/govulncheck@latest)"; \
	fi

.PHONY: release-check
release-check: ## Validate GoReleaser config without releasing
	$(GORELEASER) check

.PHONY: clean
clean: ## Remove generated test and coverage artefacts
	$(GO) clean -testcache
	rm -f $(COVER_OUT) $(COVER_HTML)
