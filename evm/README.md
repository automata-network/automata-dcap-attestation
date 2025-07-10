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

Before beginning with contract deployment, it is recommended that you store your wallet key as an encrypted keystore using [`cast wallet import`](https://book.getfoundry.sh/reference/cast/cast-wallet-import)

```bash
cast wallet import -k keystores dcap_prod --interactive
```

You may also simply pass your wallet key to the `PRIVATE_KEY` environment variable, but we do not recommend doing this with production keys.

#### Deploy the PCCS Router:

```bash
make deploy-router RPC_URL=<rpc-url>
```

#### Deploy Automata DCAP Attestation Entrypoint:

```bash
make deploy-attestation RPC_URL=<rpc-url>
```

### Automata DCAP Entrypoint zkVM Configuration

| zkVM | zkVM Selector | zkVM Program ID |
| --- | --- | --- |
| RiscZero | 1 | `0x6fa1a1ed0813923aecc7b2734fa9823802d9a0975096a8e2774dbd59a753e6e0` |
| SP1 | 2 | `0x004b1c0509dc0eee05ad437e3600027bd8cb3fbb03b29bf9cd839ae2e684c749` |

```bash
make config-zk RPC_URL=<rpc-url> ZKVM_SELECTOR=<number> ZKVM_VERIFIER_ADDRESS=<address> ZKVM_PROGRAM_IDENTIFIER=<identifier>
```

#### Deploy Quote Verifiers For All Supported Versions:

```bash
make deploy-all-verifiers RPC_URL=<rpc-url>
```
Currently, we only support V3 and V4 quotes.

#### Deploy Quote Verifier For A Specific Version

```bash
make deploy-verifier RPC_URL=<rpc-url> QUOTE_VERIFIER_VERSION=<ver>
```

#### Add QuoteVerifier(s) to the Entrypoint contract:

```bash
make config-verifier RPC_URL=<rpc-url> QUOTE_VERIFIER_VERSION=<ver>
```

> ℹ️ **NOTE**: This command automatically grants the Quote Verifier read access to the PCCS Router.


#### Explicitly Granting or Revoking the access privilege for the specified caller address to the PCCS Router

```bash
make config-router RPC_URL=<rpc-url> CALLER_ADDRESS=<address> AUTHORIZED=<true | false>
```
