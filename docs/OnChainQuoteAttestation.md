# `AutomataDcapAttestation` On Chain Verification Workflow

This document provides a high-level overview of the full on-chain verification workflow, covering V3 SGX, V4 SGX and TDX quotes. 

We advise reading through the code and refer to [Intel's official documentation](https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/) for a deep dive into the technical details about DCAP Quote Verification.

The verification process leverages dedicated quote verifiers to attest hardware authenticity by verifying the root-of-trust and checking TCB Statuses with collaterals provided by a PCCS.

---

## Table of Content
1. [Overview](#1-overview)
2. [Quote Structure](#2-quote-structure)
3. [Quote Verification](#3-quote-verification)
4. [Output Generation and Structure](#4-output-generation-and-structure)

---

## 1. Overview

The on-chain workflow is designed to:
- Receive and parse the attestation quote.
- Forward quotes to the appropriate verifier based on the quote version.
- Quote Verification
    - QE Report Data Validation and TCB Check using QEIdentity
    - PCK Certificate Chain Verification
    - Verification of attestation signature
    - TCB Check using FMSPC TCB Info
    - (V4 TDX Quotes only): TCB Check using TDX Module
    - Determines the final TCB Status by converging all TCB Statuses from various components.
- Generate structured output indicating the verification result along with essential attestation metadata.

---

## 2. Quote Structure

### 2.1. V3 Quote Structure
- **Characteristics:**
    - Header
        - Information about the quote version, attestation key type, TEE type, Intel QE Vendor ID etc.
    - Body: Local ISV Enclave Report
    - V3Quote Auth Data, contains the attestation key and signature, QE Report, QE signature and Certification Data.
        - Currently only supports Certification Data of type 5, which contains the full PCK Certificate Chain.
- **Definition:** Detailed in `contracts/types/V3Structs.sol`.

### 2.2. V4 Quote Structure
- **Characteristics:**
    - Header
        - Information about the quote version, attestation key type, TEE type, Intel QE Vendor ID etc.
    - Body: Depending on the TEE type, SGX: Local ISV Enclave Report; TDX: TD10 Report
    - V4Quote Auth Data, contains the attestation key and signature and QE Report Certification data.
        - The QE Report Certification Data must be of type 6, which contains the QE Enclave Report, QE Signature and Type 5 Certification Data.
- **Definition:** Explained in `contracts/types/V4Structs.sol`.

---

## 3. Quote Verification

### 3.1. Quote Submission and Forwarding
- **Submission:** An external user or system submits a quote to `AutomataDcapAttestation`.
- **Forwarding:** Based on the quote version, the contract routes the verification:
  - **V3 SGX Quotes:** Processed by `V3QuoteVerifier`.
  - **V4 SGX and TDX Quotes:** Processed by `V4QuoteVerifier`.

### 3.2. Verification Process

#### 3.2.1 QE Report Data Verification

The QE Report Data must contain sha256(attestation_key || QE Authentication Data), concatenated with 32 bytes of 0x00.

Then, the `mrsigner`, `isvprodid`, `miscselect` and `attributes` values are checked against the values found in the corresponding QE Identity. This step also performs a check on the status of the **QE TCB**.

#### 3.2.2 X.509 Chain Verification

In this step, the attached PCK Certificate is parsed and verified by the `X509ChainBase` library. 

The library performs a strict assertion that the certificate chain must consist of exactly 3 X509 Certificates.

For each certificate in the chain, the following checks are performed:

- The certificate is not expired.
- The corresponding CRL is fetched via `PCCSRouter` to check for revocation status.
- Verifies the signature against the issuer's public key.

At the last iteration, it checks whether the public key matches with Intel Root CA's key.

>
> ℹ️ **Note**: This step also extracts the `fmspc` and `tcbm` values from the leaf PCK Certificate, which is essential for TCB Validation in the next step.
>

#### 3.2.3 TCB Validation

Steps to validate TCB values

The `fmspc` value obtained in Step 3.2.2 is used to fetch the appropriate TCB Info collateral via the PCCS Router.

The TCB Info contains a list of TCB Statuses with sets of CPU SVNs, known as the TCB Level. The CPU SVNs extracted from the PCK Certificate must match with the ones that is highest in the TCB Level. The status indicated in the matching TCB Level is the **FMSPC TCB** Status.

An additional step is required for TDX quotes. This involves checking the `TEE_TCB_SVN` values with the TDX Module and Identities fields found in the TCB Info. This step yields the **TDX TCB** Status.

After performing TCB Checks on various components (QE TCB, SGX TCB, and TDX TCB if applicable), the TCB Convergence Rule deduces the final TCB Status for the quote attestation.

TCB Statuses sorted from highest to lowest precedence:

QE TCB > TDX TCB (when applicable) > FMSPC TCB

For example: If the QE TCB shows `TCB_OUT_OF_DATE`, despite the FMSPC TCB showing `OK`. The TCB Status for this given quote would still be considered `TCB_OUT_OF_DATE`.

#### 3.2.4 ECDSA Verification

At this step, it has already been confirmed that the PCK Certificate can be linked to the Intel's Root Of Trust. 

There are two more signatures that need to be checked:

- The QE Report must be signed by the PCK key;
- The raw data, consisting the quote header and body must be signed by the attestation key.

Since the QE report data contains information about the attestation key, it shows that the attestation key is indeed generated in a trusted environment that runs on legitimate Intel hardware.

---

## 4. Output Generation and Structure

After successful verification, the attestation contract generates a serialized output following the structure described below:

- uint16 quote version (big-endian encoded)
- bytes4 tee (little-endian encoded)
- enum tcb status: (stored as uint8)
  - 0: OK,
  - 1: TCB_SW_HARDENING_NEEDED,
  - 2: TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED,
  - 3: TCB_CONFIGURATION_NEEDED,
  - 4: TCB_OUT_OF_DATE,
  - 5: TCB_OUT_OF_DATE_CONFIGURATION_NEEDED,
  - 6: TCB_REVOKED,
  - 7: TCB_UNRECOGNIZED
- bytes6 fmspc
- bytes[] quote body (either Local ISV Report or TD10 Report, depending on the specified TEE)
- string[] TCB Advisory IDs (abi encoded)

These values are then forwarded to downstream applications, which it will have the final decision on whether to consider the input quote to be fully compliant with their own security policy.

---
