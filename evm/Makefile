# Configuration
VERIFIER ?= etherscan
VERIFIER_URL ?= 
ETHERSCAN_API_KEY ?= verifyContract
SIMULATED ?=
KEYSTORE_PATH ?= keystores/dcap_prod
PRIVATE_KEY ?=
QUOTE_VERIFIER_VERSION ?= 

# Required environment variables check
check_env:
ifdef RPC_URL
	$(eval CHAIN_ID := $(shell cast chain-id --rpc-url $(RPC_URL)))
	@echo "Chain ID: $(CHAIN_ID)"
else 
	$(error RPC_URL is not set)
endif

# Get the Owner's Wallet Address
get_owner:
ifdef PRIVATE_KEY
	$(eval OWNER := $(shell cast wallet address --private-key $(PRIVATE_KEY)))
else
	$(eval KEYSTORE_PASSWORD := $(shell read -s -p "Enter keystore password: " pwd; echo $$pwd))
	$(eval OWNER := $(shell cast wallet address --keystore $(KEYSTORE_PATH) --password $(KEYSTORE_PASSWORD) \
		|| (echo "Improper wallet configuration"; exit 1)))
endif
	@echo "\nWallet Owner: $(OWNER)"

# Deployment targets
deploy-router: check_env get_owner
	@echo "Deploying PCCSRouter..."
	@OWNER=$(OWNER) \
		ETHERSCAN_API_KEY=$(ETHERSCAN_API_KEY) \
		forge script DeployRouter \
		--rpc-url $(RPC_URL) \
		$(if $(PRIVATE_KEY), --private-key $(PRIVATE_KEY), \
		--keystore $(KEYSTORE_PATH) --password $(KEYSTORE_PASSWORD)) \
		$(if $(SIMULATED),, --broadcast) \
		-vv
	@echo "PCCSRouter deployed"

deploy-attestation: check_env get_owner
	@echo "Deploying AutomataDCAPAttestationFee..."
	@OWNER=$(OWNER) \
		ETHERSCAN_API_KEY=$(ETHERSCAN_API_KEY) \
		forge script AttestationScript \
		--sig "deployEntrypoint()" \
		--rpc-url $(RPC_URL) \
		$(if $(PRIVATE_KEY), --private-key $(PRIVATE_KEY), \
		--keystore $(KEYSTORE_PATH) --password $(KEYSTORE_PASSWORD)) \
		$(if $(SIMULATED),, --broadcast) \
		-vv \
	@echo "AutomataDCAPAttestationFee deployed"

deploy-verifier: 
ifndef QUOTE_VERIFIER_VERSION
	$(error QUOTE_VERIFIER_VERSION is not set)
else
	@echo "Deploying QuoteVerifierV$(QUOTE_VERIFIER_VERSION)..."
	@OWNER=$(OWNER) \
		ETHERSCAN_API_KEY=$(ETHERSCAN_API_KEY) \
		forge script DeployV$(QUOTE_VERIFIER_VERSION) \
		--rpc-url $(RPC_URL) \
		$(if $(PRIVATE_KEY), --private-key $(PRIVATE_KEY), \
		--keystore $(KEYSTORE_PATH) --password $(KEYSTORE_PASSWORD)) \
		$(if $(SIMULATED),, --broadcast) \
		-vv
	@echo "QuoteVerifierV$(QUOTE_VERIFIER_VERSION) deployed"
endif

# deploy all verifiers with the versions we support
deploy-all-verifiers: check_env get_owner
	@make deploy-verifier QUOTE_VERIFIER_VERSION=3 OWNER=$(OWNER) ETHERSCAN_API_KEY=$(ETHERSCAN_API_KEY) RPC_URL=$(RPC_URL) PRIVATE_KEY=$(PRIVATE_KEY) KEYSTORE_PATH=$(KEYSTORE_PATH) KEYSTORE_PASSWORD=$(KEYSTORE_PASSWORD) SIMULATED=$(SIMULATED)
	@make deploy-verifier QUOTE_VERIFIER_VERSION=4 OWNER=$(OWNER) ETHERSCAN_API_KEY=$(ETHERSCAN_API_KEY) RPC_URL=$(RPC_URL) PRIVATE_KEY=$(PRIVATE_KEY) KEYSTORE_PATH=$(KEYSTORE_PATH) KEYSTORE_PASSWORD=$(KEYSTORE_PASSWORD) SIMULATED=$(SIMULATED)

deploy-all: deploy-router deploy-attestation deploy-all-verifiers
	@echo "Deployment completed"

verify-all: check_env
	@echo "Verifying PCCSRouter, AutomataDCAPAttestation and Verifier contracts..."
	@if [ ! -f deployment/$(CHAIN_ID)/dcap.json ]; then \
		echo "Deployment not found."; \
		exit 1; \
	fi
	@for contract in PCCSRouter AutomataDcapAttestationFee V3QuoteVerifier V4QuoteVerifier; do \
		addr=$$(jq -r ".$$contract" deployment/$(CHAIN_ID).json); \
		if [ "$$addr" != "null" ]; then \
			echo "Verifying $$contract at $$addr..."; \
			forge verify-contract \
				--rpc-url $(RPC_URL) \
				--verifier $(VERIFIER) \
				--watch \
				$(if $(VERIFIER_URL),--verifier-url $(VERIFIER_URL) \
				, --etherscan-api-key $(ETHERSCAN_API_KEY)) \
				$$addr \
				src/automata_pccs/$$contract.sol:$$contract || true; \
		fi \
	done

# Utility targets
clean:
	forge clean

# Help target
help:
	@echo "Available targets:"
	@echo "  deploy-router          Deploy PCCSRouter"
	@echo "  deploy-attestation     Deploy AutomataDcapAttestationFee"
	@echo "  deploy-verifier        Deploy QuoteVerifier, must specify QUOTE_VERIFIER_VERSION"
	@echo "  deploy-all-verifiers   Deploy all QuoteVerifier contracts with versions that are currently supported"
	@echo "  deploy-all             Deploy all contracts"
	@echo "  verify-all             Verify all contracts"
	@echo "  clean                  Remove build artifacts"
	@echo ""
	@echo "Wallet environment variables: (you only need to set one)"
	@echo "  PRIVATE_KEY         Private key for wallet"
	@echo "  KEYSTORE_PATH       Path to keystore directory"
	@echo ""
	@echo "Required environment variables:"
	@echo "  RPC_URL             RPC URL for the target network"
	@echo ""
	@echo "Optional environment variables:"
	@echo "  VERIFIER            Contract verifier (default: etherscan)"
	@echo "  VERIFIER_URL        Custom verifier API URL"
	@echo "  ETHERSCAN_API_KEY   API key for contract verification"
	@echo "  SIMULATED           Simulate deployment (default: false)"
	@echo ""
	@echo "Example usage:"
	@echo "  make deploy-all RPC_URL=xxx"
	@echo "  make verify-all RPC_URL=xxx ETHERSCAN_API_KEY=xxx"

.PHONY: check_env clean help deploy-% verify-%
