<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Go DCAP

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

With Go DCAP, you can request ZK proofs of a quote verification from ZK Prover Network, then verify directly on-chain in native Go.

# Features

Go DCAP currently provides the following main features:

* Provides a fee estimate on quote / zk proof verification:

Use either:

`Portal.EstimateBaseFeeVerifyOnChain` to estimate the fee to verify quotes fully on-chain 

**OR**

`Portal.EstimateBaseFeeVerifyAndAttestWithZKProof` to estimate the fee to verify ZK Proof of the Quote Verification executed in a zkVM.

* Generates ZkProof from a Remote Prover Network

Currently integrates both RiscZero Bonsai and Succinct SP1 Remote Prover Networks.

Use `Portal.GenerateZkProof` to fetch proofs. To specify the zkVM, pass either `zkdcap.ZkTypeRiscZero` or `zkdcap.ZkTypeSuccinct`.

* ABI Encoder for user-defined Solidity function

The `Callback` object is a required argument for either verification methods to allow `DCAP Portal` to perform a callback on the user contract after a successful DCAP Quote / ZK Proof verification. The calldata must be explicitly provided in the `Callback` object. 

Use the `NewCallbackFromAbiJSON` function to generate the ABI-encoded calldata.

* Invoke the `verifyAndAttestOnChain()` or `verifyAndAttestWithZKProof` contract methods natively in GO

Use either:

`Portal.VerifyAndAttestOnChain` to verify DCAP quotes fully on-chain.

**OR**

`Portal.VerifyAndAttestWithZKProof`to verify ZK Proof of a given DCAP attestation.

# Usage

Simplified snippet to show how you can integrate your code with Go DCAP.

```go
func main() {
    // Initiation
    portal, err := godcap.NewDcapPortal(ctx,
        godcap.WithNetwork(registry.AutomataTestnet()),
        godcap.WithPrivateKey(privateKeyStr),
    )
    // error handling

    // generate the callback
    callback := NewCallbackFromAbiJSON(ContractABI).
        .WithParams("functionName", param1, param2, ...)
        .WithTo(contractAddress)
        .WithValue(wei)

    var tx *types.Transaction

    // Option1: verify with zkproof
    {
        // generate proof
        var zkProofType zkdcap.ZkType // zkdcap.ZkTypeRiscZero or zkdcap.ZkTypeSuccinct
        zkproof, err := portal.GenerateZkProof(ctx, zkProofType, quote)
        // error handling

        tx, err = portal.VerifyAndAttestWithZKProof(nil, zkproof, callback)
        // error handling
    }

    // Option2: verify on chain
    {   
        tx, err = portal.VerifyAndAttestOnChain(nil, quote, callback)
        // error handling
    }

    receipt := <-portal.WaitTx(ctx, tx)
    fmt.Printf("%#v\n", receipt)
}
```


# Examples

Note: `VerifiedCounter` can be found [here](../dcap-portal/src/examples/VerifiedCounter.sol)

<details>
<summary>Verify on chain</summary>

```go
func VerifyAndAttestOnChain(ctx context.Context, quote []byte, privateKeyStr string) error {
    // Create a new DCAP portal instance
    portal, err := godcap.NewDcapPortal(ctx,
        godcap.WithNetwork(registry.AutomataTestnet()),
        godcap.WithPrivateKey(privateKeyStr),
    )
    if err != nil {
        return err
    }

    // setup a callback function when the verification success
    //  function setNumber(uint256 newNumber) public fromDcapPortal
    callback := NewCallbackFromAbiJSON(VerifiedCounter.VerifiedCounterABI)
        .WithParams("setNumber", big.NewInt(10))
        .WithTo(verifiedCounterAddr)

    // Verify the quote on chain
    tx, err := portal.VerifyAndAttestOnChain(nil, quote, callback)
    if err != nil {
        return err
    }

    // waiting for the transaction receipt
    receipt := <-portal.WaitTx(ctx, tx)
    fmt.Printf("%#v\n", receipt)
}
```

</details>

<details>
<summary>Verify with Risc0 ZkProof</summary>

```go
//
// Make sure you export the API key to BONSAI_API_KEY
//   export BONSAI_API_KEY=${API_KEY}

func VerifyWithRisc0ZkProof(ctx context.Context, quote []byte, privateKeyStr string) error {
    // Create a new DCAP portal instance
    portal, err := godcap.NewDcapPortal(ctx,
        godcap.WithNetwork(registry.AutomataTestnet()),
        godcap.WithPrivateKey(privateKeyStr),
    )
    if err != nil {
        return err
    }

    // Generate a ZkProof using Risc0, this function will take a while to finish
    zkproof, err := portal.GenerateZkProof(ctx, zkdcap.ZkTypeRiscZero, quote)
    if err != nil {
        return err
    }

    // setup a callback function when the verification success
    //  function setNumber(uint256 newNumber) public fromDcapPortal
    callback := NewCallbackFromAbiJSON(VerifiedCounter.VerifiedCounterABI)
        .WithParams("setNumber", big.NewInt(10))
        .WithTo(verifiedCounterAddr)

    // Verify the ZkProof and attest on chain
    tx, err := portal.VerifyAndAttestWithZKProof(nil, zkproof, callback)
    if err != nil {
        return err
    }

    // waiting for the transaction receipt
    receipt := <-portal.WaitTx(ctx, tx)
    fmt.Printf("%#v\n", receipt)
}
```
</details>


<details>
<summary>Verify with Succinct ZkProof</summary>

```go

//
// Make sure you export the Succinct private key to NETWORK_PRIVATE_KEY
//   export NETWORK_PRIVATE_KEY=${KEY}

func VerifyWithSuccinctZkProof(ctx context.Context, quote []byte, privateKeyStr string) error {
    // Create a new DCAP portal instance
    portal, err := godcap.NewDcapPortal(ctx,
        godcap.WithNetwork(registry.AutomataTestnet()),
        godcap.WithPrivateKey(privateKeyStr),
    )
    if err != nil {
        return err
    }

    // Generate a ZkProof using Succinct, this function will take a while to finish
    zkproof, err := portal.GenerateZkProof(ctx, zkdcap.ZkTypeSuccinct, quote)
    if err != nil {
        return err
    }

    // setup a callback function when the verification success
    //  function setNumber(uint256 newNumber) public fromDcapPortal
    callback := NewCallbackFromAbiJSON(VerifiedCounter.VerifiedCounterABI)
        .WithParams("setNumber", big.NewInt(10))
        .WithTo(verifiedCounterAddr)

    // Verify the ZkProof and attest on chain
    tx, err := portal.VerifyAndAttestWithZKProof(nil, zkproof, callback)
    if err != nil {
        return err
    }

    // waiting for the transaction receipt
    receipt := <-portal.WaitTx(ctx, tx)
    fmt.Printf("%#v\n", receipt)
}
```

</details>

Find more examples [here](cmd/godcap/examples.go)