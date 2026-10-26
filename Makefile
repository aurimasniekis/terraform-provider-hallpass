SHELL         := /usr/bin/env bash
GO            ?= go
BIN           := bin
VERSION       ?= dev
LDFLAGS       := -s -w -X main.version=$(VERSION)
TFPLUGINDOCS  ?= $(GO) run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0
GOLANGCI_LINT ?= golangci-lint

# HallPass source the acceptance tests run against (exported read-only from a local checkout).
HALLPASS_REPO   ?= ../hallpass
HALLPASS_COMMIT ?= 536a2e7

.DEFAULT_GOAL := help
.PHONY: help build install test testacc lint fmt vet docs docs-check hallpass-src hallpass-bin example clean

help: ## List targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-13s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build bin/terraform-provider-hallpass
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/terraform-provider-hallpass .

install: ## go install the provider (for dev_overrides)
	$(GO) install -trimpath -ldflags '$(LDFLAGS)' .

test: ## Unit tests (client against httptest, schema and config validation)
	$(GO) test ./...

testacc: hallpass-bin ## Acceptance tests against a real `hallpass serve` started by TestMain
	TF_ACC=1 $(GO) test ./... -count=1 -timeout 30m $(TESTARGS)

vet: ## go vet
	$(GO) vet ./...

lint: ## golangci-lint
	$(GOLANGCI_LINT) run ./...

fmt: ## Format Go and Terraform sources
	$(GOLANGCI_LINT) fmt ./...
	terraform fmt -recursive examples

docs: ## Generate docs/ with tfplugindocs
	$(TFPLUGINDOCS) generate --provider-name hallpass

docs-check: docs ## Fail when generated docs are out of date (needs git)
	$(TFPLUGINDOCS) validate --provider-name hallpass
	git diff --exit-code -- docs

hallpass-src: ## Export HallPass at HALLPASS_COMMIT into .hallpass-src (read-only use of HALLPASS_REPO)
	rm -rf .hallpass-src && mkdir -p .hallpass-src
	git -C $(HALLPASS_REPO) archive $(HALLPASS_COMMIT) | tar -x -C .hallpass-src

hallpass-bin: ## Build bin/hallpass from .hallpass-src (no web UI needed)
	@test -d .hallpass-src || $(MAKE) hallpass-src
	cd .hallpass-src && CGO_ENABLED=0 $(GO) build -o ../$(BIN)/hallpass ./cmd/hallpass

example: build hallpass-bin ## Run examples/complete (init/plan/apply/destroy) against a throwaway HallPass
	scripts/verify-example.sh

clean: ## Remove build output
	rm -rf $(BIN) dist .hallpass-src
