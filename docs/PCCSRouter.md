# PCCSRouter Documentation

This document explains the access control mechanism implemented in the `PCCSRouter` contract and describes how QuoteVerifiers can invoke methods to load collaterals from the on-chain PCCS.

---

## Overview

The `PCCSRouter` contract acts as a centralized point for contracts to retrieve collaterals from the on-chain PCCS, using various DAO contracts. It ensures that the most up-to-date PCCS DAOs are referenced and returns data in Solidity-friendly types.

---

## Access Control Mechanism

The contract implements an access control mechanism using a combination of:

1. **Ownership:**  
  The contract inherits from the `Ownable` contract (via [solady's Ownable](https://github.com/Vectorized/solady/blob/main/src/auth/Ownable.sol)) which restricts administrative functions to the owner. Methods like `setAuthorized`, `enableCallerRestriction`, and `disableCallerRestriction` are protected by the `onlyOwner` modifier.

2. **Caller Authorization:**  
  The contract maintains an internal mapping `_authorized` that tracks which addresses are permitted to read collaterals.  
   - **Initialization:**  
    In the constructor, the zero address (`address(0)`) is set as authorized. This allows for `eth_call` requests to read collaterals from the PCCS.
   - **Modification:**  
    The `setAuthorized` function allows the owner to add or remove addresses from the authorized list.
   - **Caller Restriction Toggle:**  
    The boolean `_isCallerRestricted` determines if the authorization check is active.  
    - When caller restriction is enabled (via `enableCallerRestriction`), functions secured by the `onlyAuthorized` modifier will revert if `msg.sender` is not in the authorized list.
    - Conversely, disabling caller restriction (via `disableCallerRestriction`) relaxes these checks.

3. **Read Access to `AutomataDaoStorage`:**
  The PCCS Router is the sole non-DAO contract that has direct read-access to `AutomataDaoStorage`. All external dApps must ONLY go through the PCCS Router to fetch collaterals from the [On Chain PCCS](https://github.com/automata-network/automata-on-chain-pccs).

---

## QuoteVerifier Integration

QuoteVerifiers, which are contracts responsible for verifying Intel DCAP quotes, can interact with the `PCCSRouter` to retrieve the necessary data (such as identities, collateral hashes, or certificates). Here’s how they can invoke methods to load PCCS data:

- **Authorization Setup:**  
  Before a QuoteVerifier can access PCCS data, its address must be added to the `_authorized` mapping by calling `setAuthorized`. This ensures that the QuoteVerifier is recognized as allowed to load data from the PCCS.

- **Invocation of Methods:**  
  Once authorized, QuoteVerifiers can call the read functions (e.g., `getQeIdentity`, `getFmspcTcbV2`, etc.) to:
  - Retrieve attested identity data from the `EnclaveIdentityDao`.
  - Load TCB information via `FmspcTcbDao` with necessary decoding performed within the router.
  - Fetch PCK certificate details or certificate revocation lists (CRL) from the corresponding DAO contracts.
  
  These methods internally:
  - Verify that data is still valid by checking timestamps using the `_loadDataIfNotExpired` function.
  - Return decoded and formatted data to be used by the QuoteVerifier for further verification.
