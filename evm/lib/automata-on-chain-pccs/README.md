<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_Black%20Text%20with%20Color%20Logo.png">
    <img src="https://raw.githubusercontent.com/automata-network/automata-brand-kit/main/PNG/ATA_White%20Text%20with%20Color%20Logo.png" width="50%">
  </picture>
</div>

# Automata On Chain PCCS
[![Automata On Chain PCCS](https://img.shields.io/badge/Power%20By-Automata-orange.svg)](https://github.com/automata-network)

## Summary

This repo consists of Solidity implementation for an on-chain PCCS (Provisioning Certificate Caching Service) used in Intel DCAP (Data Center Attestation Primitives).

On-chain PCCS provides an open and permissionless service where users can freely contribute and be given easy access to collaterals for quote verification.

---

## Contracts

> ℹ️ **Note**: 
>
> The deployment addresses shown here are currently based on the latest [changes](https://github.com/automata-network/automata-on-chain-pccs/pull/9) made.
>
> To view deployments on the previous version (will be deprecated soon), you may refer to this [branch](https://github.com/automata-network/automata-on-chain-pccs/tree/v0).

There are two sets of contracts, i.e. the **Helper** and **Base**.

### Helper Contracts

The Helper contracts provide APIs for parsing collaterals and converting into Solidity structs, i.e. QEIdentity.json, TCBInfo.json, basic DER-decoder for PCK X509 leaf certificate and extensions and X509 CRLs.

#### Testnet

|  | Network | Address |
| --- | --- | --- |
| `EnclaveIdentityHelper.sol` | Automata Testnet | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://explorer-testnet.ata.network/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | Ethereum Sepolia | [0x2247B6dfE1bD9c376ECb58A68fa29603015a54a6](https://sepolia.etherscan.io/address/0x2247B6dfE1bD9c376ECb58A68fa29603015a54a6) |
|  | Ethereum Holesky | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://holesky.etherscan.io/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | Base Sepolia | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://sepolia.basescan.org/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | OP Sepolia | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://sepolia-optimism.etherscan.io/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | World Sepolia | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://worldchain-sepolia.explorer.alchemy.com/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | Arbitrum Sepolia | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://sepolia.arbiscan.io/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
| `FmspcTcbHelper.sol` | Automata Testnet | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://explorer-testnet.ata.network/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | Ethereum Sepolia | [0x4907280122325DbCeba657210Df2E3EE0e853cD0](https://sepolia.etherscan.io/address/0x4907280122325DbCeba657210Df2E3EE0e853cD0) |
|  | Ethereum Holesky | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://holesky.etherscan.io/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | Base Sepolia | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://sepolia.basescan.org/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | OP Sepolia | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://sepolia-optimism.etherscan.io/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | World Sepolia | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://worldchain-sepolia.explorer.alchemy.com/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | Arbitrum Sepolia | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://sepolia.arbiscan.io/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
| `PCKHelper.sol` | Automata Testnet | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://explorer-testnet.ata.network/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | Ethereum Sepolia | [0x0a5abD0E175aF826c4c61d1f9b3741014555F05f](https://sepolia.etherscan.io/address/0x0a5abD0E175aF826c4c61d1f9b3741014555F05f) |
|  | Ethereum Holesky | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://holesky.etherscan.io/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | Base Sepolia | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://sepolia.basescan.org/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | OP Sepolia | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://sepolia-optimism.etherscan.io/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | World Sepolia | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://worldchain-sepolia.explorer.alchemy.com/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | Arbitrum Sepolia | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://sepolia.arbiscan.io/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
| `X509CRLHelper.sol` | Automata Testnet | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://explorer-testnet.ata.network/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | Ethereum Sepolia | [0x5E73f17BD87A191158E2626F67a772A9971B225B](https://sepolia.etherscan.io/address/0x5E73f17BD87A191158E2626F67a772A9971B225B) |
|  | Ethereum Holesky | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://holesky.etherscan.io/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | Base Sepolia | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://sepolia.basescan.org/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | OP Sepolia | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://sepolia-optimism.etherscan.io/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | World Sepolia | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://worldchain-sepolia.explorer.alchemy.com/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | Arbitrum Sepolia | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://sepolia.arbiscan.io/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |

#### Mainnet

|  | Network | Address |
| --- | --- | --- |
| `EnclaveIdentityHelper.sol` | Automata Mainnet | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://explorer.ata.network/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | Ethereum Mainnet | [0x13BECaa512713Ac7C2d7a04ba221aD5E02D43DFE](https://etherscan.io/address/0x13BECaa512713Ac7C2d7a04ba221aD5E02D43DFE) |
|  | Base Mainnet | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://basescan.org/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | OP Mainnet | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://optimistic.etherscan.io/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
|  | World Mainnet | [0x13BECaa512713Ac7C2d7a04ba221aD5E02D43DFE](https://worldchain-mainnet.explorer.alchemy.com/address/0x13BECaa512713Ac7C2d7a04ba221aD5E02D43DFE) |
|  | Arbitrum Mainnet | [0xae27D762EED6958bc34b358bd7C78c7211fe77F8](https://arbiscan.io/address/0xae27D762EED6958bc34b358bd7C78c7211fe77F8) |
| `FmspcTcbHelper.sol` | Automata Mainnet | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://explorer.ata.network/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | Ethereum Mainnet | [0xc99bF04C31bF3d026B5B47b2574FC19C1459B732](https://etherscan.io/address/0xc99bF04C31bF3d026B5B47b2574FC19C1459B732) |
|  | Base Mainnet | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://basescan.org/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | OP Mainnet | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://optimistic.etherscan.io/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
|  | World Mainnet | [0xc99bF04C31bF3d026B5B47b2574FC19C1459B732](https://worldchain-mainnet.explorer.alchemy.com/address/0xc99bF04C31bF3d026B5B47b2574FC19C1459B732) |
|  | Arbitrum Mainnet | [0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5](https://arbiscan.io/address/0x71056B540b4E60D0E8eFb55FAd487C486B09FFF5) |
| `PCKHelper.sol` | Automata Mainnet | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://explorer.ata.network/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | Ethereum Mainnet | [0x3e2fe733E444313A93Fa3f9AEd3bB203048dDE70](https://etherscan.io/address/0x3e2fe733E444313A93Fa3f9AEd3bB203048dDE70) |
|  | Base Mainnet | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://basescan.org/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | OP Mainnet | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://optimistic.etherscan.io/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
|  | World Mainnet | [0x3e2fe733E444313A93Fa3f9AEd3bB203048dDE70](https://worldchain-mainnet.explorer.alchemy.com/address/0x3e2fe733E444313A93Fa3f9AEd3bB203048dDE70) |
|  | Arbitrum Mainnet | [0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B](https://arbiscan.io/address/0x4Aca9C0EB063401C9F5c2Fc4487DBC5ccF1C9E2B) |
| `X509CRLHelper.sol` | Automata Mainnet | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://explorer.ata.network/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | Ethereum Mainnet | [0x2567245dE6E349C8B7AA82fD6FF854b844A0aEF9](https://etherscan.io/address/0x2567245dE6E349C8B7AA82fD6FF854b844A0aEF9) |
|  | Base Mainnet | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://basescan.org/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | OP Mainnet | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://optimistic.etherscan.io/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |
|  | World Mainnet | [0x2567245dE6E349C8B7AA82fD6FF854b844A0aEF9](https://worldchain-mainnet.explorer.alchemy.com/address/0x2567245dE6E349C8B7AA82fD6FF854b844A0aEF9) |
|  | Arbitrum Mainnet | [0x6e204fEAe40F668a06E78a83b66185FFC8892DDA](https://arbiscan.io/address/0x6e204fEAe40F668a06E78a83b66185FFC8892DDA) |

### Base libraries and Automata DAO contracts

The base contracts are libraries that provide the Data Access Object (DAO) APIs with similar designs inspired from the [Design Guide for Intel SGX PCCS](https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf).

Base contracts are dependent on Helper contracts to parse collaterals, and contains implementation of basic collateral authenticity check functions for upserts. Smart contract developers are encouraged to extend the base contracts to build their own custom implementation of on-chain PCCS.

Our DAO implementation can be found in the [`automata_pccs`](./src/automata_pccs/) directory.

#### Testnet

|  | Network | Address |
| --- | --- | --- |
| `AutomataEnclaveIdentityDao.sol` | Automata Testnet | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://explorer-testnet.ata.network/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | Ethereum Sepolia | [0x5eFDd14Bbfba36992f66a64653962BB0B8Ef1E26](https://sepolia.etherscan.io/address/0x5eFDd14Bbfba36992f66a64653962BB0B8Ef1E26) |
|  | Ethereum Holesky | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://holesky.etherscan.io/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | Base Sepolia | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://sepolia.basescan.org/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | OP Sepolia | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://sepolia-optimism.etherscan.io/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | World Sepolia | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://worldchain-sepolia.explorer.alchemy.com/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | Arbitrum Sepolia | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://sepolia.arbiscan.io/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
| `AutomataFmspcTcbDao.sol` | Automata Testnet | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://explorer-testnet.ata.network/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | Ethereum Sepolia | [0xB87a493684Bb643258Ae4887B444c6cB244db935](https://sepolia.etherscan.io/address/0xB87a493684Bb643258Ae4887B444c6cB244db935) |
|  | Ethereum Holesky | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://holesky.etherscan.io/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | Base Sepolia | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://sepolia.basescan.org/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | OP Sepolia | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://sepolia-optimism.etherscan.io/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | World Sepolia | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://worldchain-sepolia.explorer.alchemy.com/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | Arbitrum Sepolia | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://sepolia.arbiscan.io/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
| `AutomataPckDao.sol` | Automata Testnet | [0x722525B96b62e182F8A095af0a79d4EA2037795C](https://explorer-testnet.ata.network/address/0x722525B96b62e182F8A095af0a79d4EA2037795C) |
|  | Ethereum Sepolia | [0xcCfb6b78B2C30666F41c012627a74768DAACf4ab](https://sepolia.etherscan.io/address/0xcCfb6b78B2C30666F41c012627a74768DAACf4ab) |
|  | Ethereum Holesky | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://holesky.etherscan.io/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | Base Sepolia | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://sepolia.basescan.org/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | OP Sepolia | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://sepolia-optimism.etherscan.io/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | World Sepolia | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://worldchain-sepolia.explorer.alchemy.com/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | Arbitrum Sepolia | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://sepolia.arbiscan.io/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
| `AutomataPcsDao.sol` | Automata Testnet | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://explorer-testnet.ata.network/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | Ethereum Sepolia | [0x980AEAdb3fa7c2c58A81091D93A819a24A103E6C](https://sepolia.etherscan.io/address/0x980AEAdb3fa7c2c58A81091D93A819a24A103E6C) |
|  | Ethereum Holesky | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://holesky.etherscan.io/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | Base Sepolia | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://sepolia.basescan.org/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | OP Sepolia | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://sepolia-optimism.etherscan.io/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | World Sepolia | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://worldchain-sepolia.explorer.alchemy.com/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | Arbitrum Sepolia | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://sepolia.arbiscan.io/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |

#### Mainnet

|  | Network | Address |
| --- | --- | --- |
| `AutomataEnclaveIdentityDao.sol` | Automata Mainnet | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://explorer.ata.network/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | Ethereum Mainnet | [0x28111536292b34f37120861A46B39BF39187d73a](https://etherscan.io/address/0x28111536292b34f37120861A46B39BF39187d73a) |
|  | Base Mainnet | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://basescan.org/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | OP Mainnet | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://optimistic.etherscan.io/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
|  | World Mainnet | [0x28111536292b34f37120861A46B39BF39187d73a](https://worldchain-mainnet.explorer.alchemy.com/address/0x28111536292b34f37120861A46B39BF39187d73a) |
|  | Arbitrum Mainnet | [0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910](https://arbiscan.io/address/0x45f91C0d9Cf651785d93fcF7e9E97dE952CdB910) |
| `AutomataFmspcTcbDao.sol` | Automata Mainnet | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://explorer.ata.network/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | Ethereum Mainnet | [0x868c18869f68E0E0b0b7B2B4439f7fDDd0421e6b](https://etherscan.io/address/0x868c18869f68E0E0b0b7B2B4439f7fDDd0421e6b) |
|  | Base Mainnet | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://basescan.org/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | OP Mainnet | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://optimistic.etherscan.io/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
|  | World Mainnet | [0x868c18869f68E0E0b0b7B2B4439f7fDDd0421e6b](https://worldchain-mainnet.explorer.alchemy.com/address/0x868c18869f68E0E0b0b7B2B4439f7fDDd0421e6b) |
|  | Arbitrum Mainnet | [0x9c54C72867b07caF2e6255CE32983c28aFE40F26](https://arbiscan.io/address/0x9c54C72867b07caF2e6255CE32983c28aFE40F26) |
| `AutomataPckDao.sol` | Automata Mainnet | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://explorer.ata.network/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | Ethereum Mainnet | [0xeCc198936FcA3Ca1fDc97B8612B32185908917B0](https://etherscan.io/address/0xeCc198936FcA3Ca1fDc97B8612B32185908917B0) |
|  | Base Mainnet | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://basescan.org/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | OP Mainnet | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://optimistic.etherscan.io/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
|  | World Mainnet | [0xeCc198936FcA3Ca1fDc97B8612B32185908917B0](https://worldchain-mainnet.explorer.alchemy.com/address/0xeCc198936FcA3Ca1fDc97B8612B32185908917B0) |
|  | Arbitrum Mainnet | [0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82](https://arbiscan.io/address/0x31F18aA7B4cbAD7A726BCBF5AB3e286fC0b02A82) |
| `AutomataPcsDao.sol` | Automata Mainnet | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://explorer.ata.network/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | Ethereum Mainnet | [0x86f8865BCe8BE62CB8096b5B94fA3fB3a6ED330c](https://etherscan.io/address/0x86f8865BCe8BE62CB8096b5B94fA3fB3a6ED330c) |
|  | Base Mainnet | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://basescan.org/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | OP Mainnet | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://optimistic.etherscan.io/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |
|  | World Mainnet | [0x86f8865BCe8BE62CB8096b5B94fA3fB3a6ED330c](https://worldchain-mainnet.explorer.alchemy.com/address/0x86f8865BCe8BE62CB8096b5B94fA3fB3a6ED330c) |
|  | Arbitrum Mainnet | [0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1](https://arbiscan.io/address/0xcf171ACd6c0a776f9d3E1F6Cac8067c982Ac6Ce1) |

---

### #BUIDL 🛠️

- Install [Foundry](https://book.getfoundry.sh/getting-started/installation)

- Create `.env` file with the provided example.

```bash
cp env/.{network}.env.example .env
```

- Compile the contracts

```bash
forge build
```

- Run tests

```bash
forge test
```

To view gas report, pass the `--gas-report` flag.

#### Deployment

- Deploy the Helper contracts

```bash
./script/helper/deploy.sh
```

If you are having issues running the script, try changing the permission settings.

```bash
chmod +x ./script/helper/deploy.sh
```

Make sure to update `.env` file with the appropriate addresses, then run `source .env`.

- Deploy `automata-pccs`

```bash
forge script DeployAutomataDao --rpc-url $RPC_URL -vvvv --broadcast --sig "deployAll(bool)" true
```

Make sure to update `.env` file with the appropriate addresses, then run `source .env`.

Once you have deployed all Automata DAOs, you must grant them write access to [`AutomataDaoStorage`](./src/automata_pccs//shared/AutomataDaoStorage.sol) by running:

```bash
forge script ConfigureAutomataDao -rpc-url $RPC_URL -vvvv --broadcast --sig "updateStorageDao()"
```
