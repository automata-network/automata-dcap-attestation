# Automata DCAP Attestation

## Summary

Automata DCAP Attestation consists of three parts:

- PCCS Router: A central contract to read collaterals from [`automata-on-chain-pccs`](https://github.com/automata-network/automata-on-chain-pccs)

- Automata DCAP Attestation: This is the entrypoint contract for users to submit a quote to be verified. This contract parses the Quote header to identify the version, which then forwards the quote to the respective QuoteVerifier contract.

- Quote Verifier(s): This contract provides the full implementation on verifying a given quote specific to its version. This contract is intended to be called only from the Automata DCAP Attestation contract.

## On-Chain vs RiscZero Attestations

Automata DCAP Attestation contract implements two attestation methods available to users. Here is a quick comparison:

|  | On-Chain | SNARK Proof with RiscZero |
| --- | --- | --- |
| Quote Verification Time | Instant | Proving takes 2 - 5 minutes, instant verification |
| Gas Cost | ~4M gas | 300k gas |
| Execution | Runs fully on-chain | The execution runs in a Guest program on Bonsai, which is then issued with a [Receipt](https://dev.risczero.com/api/zkvm/receipts). Verifiers should make sure the Receipt contains the expected Image ID, which can be generated directly from the Guest source code. After a successful execution of the Guest program, the proof is sent on-chain to be verified. |

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

### Example

```solidity
import "@automata-network/dcap-attestation/AutomataDcapAttestation.sol";

contract ExampleDcapContract {

    AutomataDcapAttestation attest;

    constructor(address _attest) {
        attest = AutomataDcapAttestation(_attest);
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

    // RiscZero Attestation example
    function attestWithRiscZero(bytes calldata journal, bytes calldata seal) public 
    {
        (bool success, bytes memory output) = attest.verifyAndAttestWithZKProof(
            journal,
            seal
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

To execute the DCAP RiscZero Guest Program and fetch proofs from Bonsai, we recommend checking out the [DCAP Bonsai Demo CLI](https://github.com/automata-network/dcap-bonsai-cli).

---

# BUIDL 🛠️

## Getting Started

Clone this repo, by running the following command:

```bash
git clone git@github.com:automata-network/automata-dcap-attestation.git --recurse-submodules
```

Before you begin, make sure to create a copy of the `.env` file with the example provided. Then, please provide any remaining variables that are missing.

```bash
cp .env.example .env
```

---

## Building With Foundry

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

Deploy the PCCS Router:

```bash
forge script DeployRouter --rpc-url $RPC_URL --broadcast -vvvv
```

Deploy Automata DCAP Attestation Entrypoint:

```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "deployEntrypoint()"
```

Deploy Quote Verifier(s):

```bash
forge script DeployV3 --rpc-url $RPC_URL --broadcast -vvvv
```

The naming format for the script is simply `DeployV{x}`, where `x` is the quote version supported by the verifier. Currently, we only support V3 and V4 quotes.

Whitelist QuoteVerifier(s) in the Entrypoint contract:

```bash
forge script AttestationScript --rpc-url $RPC_URL --broadcast -vvvv --sig "configVerifier(address)" <verifier-address>
```

#### Deployment Information

The ImageID currently used for the DCAP RiscZero Guest Program is `4052beb38db7869b15596d53c2d5c02c9307faffca9215e69b0f0d0e1812a6c2`.

| Contract | Network | Address |
| --- | --- | --- |
| `PCCSRouter.sol` | testnet | 0xbFDeE7A1f1bFA2267cD0DA50BE76D8c4a3864543 |
|  | mainnet (preview) | 0xb76834729717868fa203b9D90fc88F859A4E594D |
| `AutomataDcapAttestation.sol` | testnet | 0xefE368b17D137E86298eec8EbC5502fb56d27832 |
|  | mainnet (preview) | 0xE26E11B257856B0bEBc4C759aaBDdea72B64351F |
| `V3QuoteVerifier.sol` | testnet | 0x67042d171b8b7da1a4a98df787bdce79190dac3c |
|  | mainnet (preview) | 0xF38a49322cAA0Ead71D4B1cF2afBb6d02BE5FC96 |
| `V4QuoteVerifier.sol` | testnet | 0x921b8f6ec83e405b715111ec1ae8b54a3ea063eb |
|  | mainnet (preview) | 0xfF47ecA64898692a86926CDDa794807be3f6567D |