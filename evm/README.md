# Automata DCAP Attestation on EVM Guide

## Integration

To integrate your contract with Automata DCAP Attestation, you need to first install [Foundry](https://book.getfoundry.sh/getting-started/installation).

Add to your dependency, by running:

```bash
forge install automata-network/automata-dcap-attestation
```

Then, add the following to your `remappings.txt`

```
@automata-network/dcap-attestation/=lib/automata-dcap-attestation/contracts/
```

## Example

```solidity
import "@automata-network/dcap-attestation/AutomataDcapAttestationFee.sol";

contract ExampleDcapContract {

    AutomataDcapAttestationFee attest;

    constructor(address _attest) {
        attest = AutomataDcapAttestationFee(_attest);
    }

    // On-Chain Attestation example
    function attestOnChain(bytes calldata quote) public {
        (bool success, bytes memory output) = attest.verifyAndAttestOnChain(quote);

        if (success) {
            // ... implementation to handle successful attestations
        } else {
            string memory errorMessage = string(output);
            // ... implementation to handle failed attestations
        }
    }

    // SNARK Attestation example
    // ZkCoProcessorType can either be RiscZero or Succinct
    function attestWithSnark(
        bytes calldata output,
        ZkCoProcessorType zkvm,
        bytes calldata proofBytes
    ) public 
    {
        (bool success, bytes memory output) = attest.verifyAndAttestWithZKProof(
            output,
            zkvm,
            proofBytes
        );

        if (success) {
            // ... implementation to handle successful attestations
        } else {
            string memory errorMessage = string(output);
            // ... implementation to handle failed attestations
        }
    }

}
```

---

## BUIDL 🛠️

### Getting Started

Clone this repo, by running the following command:

```bash
git clone https://github.com/automata-network/automata-dcap-attestation.git --recurse-submodules
```

Before you begin, make sure to create a copy of the `.env` file with the example provided. Then, please provide any remaining variables that are missing.

```bash
cp env/.testnet.env.example .env #or you can make a copy from examples for any network
```

### Building With Foundry

Compile the contracts:

```bash
forge build
```

Testing the contracts:

```bash
forge test
```

To view gas report, pass the `--gas-report` flag.

To provide additional test cases, please include those in the `/forge-test` directory.

To provide additional scripts, please include those in the `/forge-script` directory.

### Deployment Scripts

#### Deploy the PCCS Router:

```bash
forge script DeployRouter --rpc-url $RPC_URL --broadcast -vvvv
```

#### Deploy Automata DCAP Attestation Entrypoint:

```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "deployEntrypoint()"
```

### Automata DCAP Entrypoint zkVM Configuration

RiscZero:
```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "onfigureZk(uint8,address,bytes32)" 1 $RISC0_VERIFIER $DCAP_RISCZERO_IMAGE_ID
```

SP1:
```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "onfigureZk(uint8,address,bytes32)" 2 $SP1_VERIFIER_GATEWAY $DCAP_SUCCINCT_VKEY
```

#### Deploy Quote Verifier(s):

```bash
forge script DeployV3 --rpc-url $RPC_URL --broadcast -vvvv
```

The naming format for the script is simply `DeployV{x}`, where `x` is the quote version supported by the verifier. Currently, we only support V3 and V4 quotes.

#### Add QuoteVerifier(s) to the Entrypoint contract:

```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "configVerifier(address)" <verifier-address>
```

#### Grant QuoteVerifier(s) READ permission from the PCCS Router

```bash
forge script DeployRouter --rpc-url $RPC_URL --broadcast -vvvv --sig "setAuthorizedCaller(address,bool)" <verifier-address> true
```