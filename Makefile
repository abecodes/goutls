.DEFAULT_GOAL := help
# To avoid includes breaking the makefile_list, a copy is created
MAKE_FILE := $(lastword $(MAKEFILE_LIST))

# ====================
# Create help output
help:
	@grep $(if $(filter Darwin,$(shell uname -s)), -E, -P) '^[a-zA-Z_-]+:.*?## .*$$' $(MAKE_FILE) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
.PHONY: help
# ====================
# Formatting and linging

fmt: ## Format code with [gofumpt](https://github.com/mvdan/gofumpt)
	@gofumpt -d -w .
.PHONY: fmt

lint: fmt ## Lint code
	@revive -config revive.toml -formatter stylish -exclude ./vendor/... ./...
.PHONY: lint

vet: fmt ## Check parameters and assignments
	@go vet ./...
.PHONY: vet

shadow: fmt ## Check for shadowed variables
	@shadow ./...
.PHONY: vet

static: fmt ## Check common statics
	@staticcheck -f stylish ./...
.PHONY: vet

prepare: lint vet shadow static ## Execute all format and lint the code
.PHONY: prepare

