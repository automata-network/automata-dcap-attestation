.DEFAULT_GOAL := help
TAG ?= $(shell git rev-parse --short HEAD)


.PHONY: help
help: ## Display this help message
	@./help.sh "$(MAKEFILE_LIST)"


.PHONY: lint
lint: ## Run Linting Checks
	@cargo clippy -- -D warnings


.PHONY: fmt
fmt: ## Format the code
	@cargo fmt

.PHONY: test
test: ## Run the tests
	@cargo test

.PHONY: build
build: ## Build the project
	@cargo build
	@cargo test