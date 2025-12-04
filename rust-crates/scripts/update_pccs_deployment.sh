#!/bin/bash

# Script to update PCCS deployment addresses from the automata-on-chain-pccs repository
# Usage: ./update_pccs_deployment.sh [--local] [branch_or_commit] [chain_id1] [chain_id2] ...
# If no branch/commit is specified, defaults to 'main'
# If no chain IDs are specified, updates all available chain IDs
# Use --local to fetch from the local submodule instead of remote repository

set -e

# Configuration
PCCS_REPO_URL="https://api.github.com/repos/automata-network/automata-on-chain-pccs/contents/deployment"
RAW_BASE_URL="https://raw.githubusercontent.com/automata-network/automata-on-chain-pccs"
# LOCAL_SUBMODULE_PATH="./lib/automata-on-chain-pccs/deployment"
DEPLOYMENT_DIR="./libraries/network-registry/deployment/current"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [--local] [branch_or_commit] [chain_id1] [chain_id2] ..."
    echo ""
    echo "Options:"
    echo "  --local, -l       Use local submodule instead of remote repository"
    echo ""
    echo "Arguments:"
    echo "  branch_or_commit  Git branch or commit hash to fetch from (default: main)"
    echo "                    Only applies to remote mode; ignored in local mode"
    echo "  chain_id          Specific chain IDs to update (default: all available)"
    echo ""
    echo "Examples:"
    echo "  $0                    # Update all chains from remote main branch"
    echo "  $0 main               # Update all chains from remote main branch"
    echo "  $0 dev                # Update all chains from remote dev branch"
    echo "  $0 --local            # Update all chains from local submodule"
    echo "  $0 -l 1 137           # Update chains 1 and 137 from local submodule"
    echo "  $0 abc123 1 137       # Update chains 1 and 137 from remote commit abc123"
    echo "  $0 main 56 8453       # Update chains 56 and 8453 from remote main branch"
}

# Parse command line arguments
BRANCH_OR_COMMIT="main"
USE_LOCAL=false
SPECIFIC_CHAIN_IDS=()

if [ $# -eq 1 ] && [ "$1" = "--help" -o "$1" = "-h" ]; then
    show_usage
    exit 0
fi

# Check for --local flag
if [ $# -ge 1 ] && [ "$1" = "--local" -o "$1" = "-l" ]; then
    USE_LOCAL=true
    shift
fi

if [ $# -ge 1 ]; then
    if [ "$USE_LOCAL" = true ]; then
        # In local mode, all remaining args are chain IDs
        SPECIFIC_CHAIN_IDS=("$@")
    else
        # In remote mode, first arg is branch/commit, rest are chain IDs
        BRANCH_OR_COMMIT="$1"
        shift
        if [ $# -ge 1 ]; then
            SPECIFIC_CHAIN_IDS=("$@")
        fi
    fi
fi

if [ "$USE_LOCAL" = true ]; then
    print_info "Using local submodule: $LOCAL_SUBMODULE_PATH"
else
    print_info "Using remote repository with branch/commit: $BRANCH_OR_COMMIT"
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
if ! command_exists curl; then
    print_error "curl is required but not installed."
    exit 1
fi

if ! command_exists jq; then
    print_error "jq is required but not installed. Please install jq to continue."
    exit 1
fi

# Create deployment directory if it doesn't exist
if [ ! -d "$DEPLOYMENT_DIR" ]; then
    print_info "Creating deployment directory: $DEPLOYMENT_DIR"
    mkdir -p "$DEPLOYMENT_DIR"
fi

# Function to get available chain IDs from the local submodule
get_available_chain_ids_local() {
    print_info "Fetching available chain IDs from local submodule..." >&2
    
    if [ ! -d "$LOCAL_SUBMODULE_PATH" ]; then
        print_error "Local submodule not found at: $LOCAL_SUBMODULE_PATH" >&2
        print_error "Please ensure the automata-on-chain-pccs submodule is initialized" >&2
        return 1
    fi
    
    # Find all .json files and extract chain IDs (remove .json extension)
    find "$LOCAL_SUBMODULE_PATH" -name "*.json" -type f -exec basename {} \; | sed 's/\.json$//' | sort -n
}

# Function to get available chain IDs from the remote repository
get_available_chain_ids_remote() {
    local ref="$1"
    print_info "Fetching available chain IDs from repository..." >&2
    
    local response
    if ! response=$(curl -s "$PCCS_REPO_URL?ref=$ref" 2>/dev/null); then
        print_error "Failed to fetch deployment list from repository" >&2
        return 1
    fi
    
    # Check if the response is valid JSON
    if ! echo "$response" | jq empty 2>/dev/null; then
        print_error "Invalid response from GitHub API. Branch/commit '$ref' may not exist." >&2
        print_error "Response: $response" >&2
        return 1
    fi
    
    # Extract chain IDs (remove .json extension)
    echo "$response" | jq -r '.[].name | select(endswith(".json")) | sub("\\.json$"; "")'
}

# Function to get available chain IDs based on mode (local or remote)
get_available_chain_ids() {
    if [ "$USE_LOCAL" = true ]; then
        get_available_chain_ids_local
    else
        get_available_chain_ids_remote "$1"
    fi
}

# Function to update a single chain's deployment from local submodule
update_chain_deployment_local() {
    local chain_id="$1"
    
    # Debug output
    if [ -z "$chain_id" ]; then
        print_error "update_chain_deployment_local called with empty chain_id"
        return 1
    fi
    
    local source_file="$LOCAL_SUBMODULE_PATH/$chain_id.json"
    local target_dir="$DEPLOYMENT_DIR/$chain_id"
    local target_file="$target_dir/onchain_pccs.json"
    
    print_info "Updating chain ID: $chain_id (from local submodule)"
    
    # Check if source file exists
    if [ ! -f "$source_file" ]; then
        print_error "Source file not found: $source_file"
        return 1
    fi
    
    # Create target directory if it doesn't exist
    if [ ! -d "$target_dir" ]; then
        print_info "Creating directory: $target_dir"
        mkdir -p "$target_dir"
    fi
    
    # Check if the source file is valid JSON
    if ! jq empty "$source_file" 2>/dev/null; then
        print_error "Invalid JSON in source file: $source_file"
        return 1
    fi
    
    # Check if the file contains expected PCCS contract addresses
    if ! jq -e '.AutomataDaoStorage' "$source_file" >/dev/null 2>&1; then
        print_warning "Source file for chain ID $chain_id doesn't contain expected PCCS contracts"
    fi
    
    # Copy file to target location
    cp "$source_file" "$target_file"
    
    print_success "Updated $target_file"
    
    # Show a summary of what was updated
    local contract_count
    contract_count=$(jq 'keys | length' "$target_file")
    print_info "  Contains $contract_count contract addresses"
}

# Function to update a single chain's deployment from remote repository
update_chain_deployment_remote() {
    local chain_id="$1"
    local ref="$2"
    
    # Debug output
    if [ -z "$chain_id" ]; then
        print_error "update_chain_deployment called with empty chain_id"
        return 1
    fi
    
    local source_url="$RAW_BASE_URL/$ref/deployment/$chain_id.json"
    local target_dir="$DEPLOYMENT_DIR/$chain_id"
    local target_file="$target_dir/onchain_pccs.json"
    
    print_info "Updating chain ID: $chain_id (from remote repository)"
    
    # Create target directory if it doesn't exist
    if [ ! -d "$target_dir" ]; then
        print_info "Creating directory: $target_dir"
        mkdir -p "$target_dir"
    fi
    
    # Download the deployment file
    local temp_file
    temp_file=$(mktemp)
    
    if ! curl -s "$source_url" -o "$temp_file"; then
        print_error "Failed to download deployment for chain ID: $chain_id"
        rm -f "$temp_file"
        return 1
    fi
    
    # Check if the downloaded file is valid JSON
    if ! jq empty "$temp_file" 2>/dev/null; then
        print_error "Invalid JSON downloaded for chain ID: $chain_id"
        print_error "URL: $source_url"
        rm -f "$temp_file"
        return 1
    fi
    
    # Check if the file contains expected PCCS contract addresses
    if ! jq -e '.AutomataDaoStorage' "$temp_file" >/dev/null 2>&1; then
        print_warning "Downloaded file for chain ID $chain_id doesn't contain expected PCCS contracts"
    fi
    
    # Move temp file to target location
    mv "$temp_file" "$target_file"
    
    print_success "Updated $target_file"
    
    # Show a summary of what was updated
    local contract_count
    contract_count=$(jq 'keys | length' "$target_file")
    print_info "  Contains $contract_count contract addresses"
}

# Function to update a single chain's deployment based on mode (local or remote)
update_chain_deployment() {
    local chain_id="$1"
    local ref="$2"
    
    if [ "$USE_LOCAL" = true ]; then
        update_chain_deployment_local "$chain_id"
    else
        update_chain_deployment_remote "$chain_id" "$ref"
    fi
}

# Main execution
main() {
    print_info "Starting PCCS deployment update..."
    
    # Determine which chain IDs to update
    local chain_ids_to_update=()
    
    if [ ${#SPECIFIC_CHAIN_IDS[@]} -eq 0 ]; then
        print_info "No specific chain IDs provided, fetching all available chain IDs..."
        
        # Get all available chain IDs from the repository
        local available_chain_ids
        if ! available_chain_ids=$(get_available_chain_ids "$BRANCH_OR_COMMIT"); then
            print_error "Failed to get available chain IDs"
            exit 1
        fi
        
        if [ -z "$available_chain_ids" ]; then
            print_error "No chain IDs found in the repository"
            exit 1
        fi
        
        # Convert to array
        while IFS= read -r chain_id; do
            if [ -n "$chain_id" ]; then
                chain_ids_to_update+=("$chain_id")
            fi
        done <<< "$available_chain_ids"
        
        print_info "Found ${#chain_ids_to_update[@]} chain IDs to update"
    else
        chain_ids_to_update=("${SPECIFIC_CHAIN_IDS[@]}")
        print_info "Updating ${#chain_ids_to_update[@]} specified chain IDs"
    fi
    
    # Update each chain ID
    local success_count=0
    local error_count=0
    
    for chain_id in "${chain_ids_to_update[@]}"; do
        if update_chain_deployment "$chain_id" "$BRANCH_OR_COMMIT"; then
            ((success_count++))
        else
            ((error_count++))
        fi
    done
    
    # Summary
    echo ""
    print_info "Update Summary:"
    print_success "  Successfully updated: $success_count chain(s)"
    
    if [ $error_count -gt 0 ]; then
        print_error "  Failed to update: $error_count chain(s)"
        exit 1
    fi
    
    print_success "All PCCS deployments updated successfully!"
}

# Run main function
main