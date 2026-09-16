//! Additive FeeV2 bindings. Legacy generated modules are deliberately retained.
alloy::sol! {
    #[sol(rpc)]
    interface IAutomataDcapAttestationV2 {
        function verifyAndAttestOnChainV2(bytes calldata quote, uint32 tcbEval, bool minCheck)
            external payable returns (bool success, bytes output);
        function verifyAndAttestWithZKProofV2(bytes calldata journal, uint8 backend, bytes calldata proof, bytes32 identifier, uint32 tcbEval, bool minCheck)
            external payable returns (bool success, bytes output);
        function programIdentifierV2(uint8 backend) external view returns (bytes32);
        function programIdentifiersV2(uint8 backend) external view returns (bytes32[]);
        event AttestationSubmittedV2(bool success, uint8 verifierType, uint16 indexed formatMajorVersion, uint16 indexed formatMinorVersion, bytes output);
    }
    #[sol(rpc)]
    interface IAutomataDcapAttestationV2Default {
        function verifyAndAttestOnChainV2(bytes calldata quote) external payable returns (bool success, bytes output);
        function verifyAndAttestWithZKProofV2(bytes calldata journal, uint8 backend, bytes calldata proof)
            external payable returns (bool success, bytes output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::{B256, Bytes, keccak256},
        sol_types::SolCall,
    };

    #[test]
    fn explicit_modes_are_encoded_and_default_selectors_stay_unchanged() {
        for min_check in [false, true] {
            let raw = IAutomataDcapAttestationV2::verifyAndAttestOnChainV2Call {
                quote: Bytes::from(vec![1, 2]),
                tcbEval: 17,
                minCheck: min_check,
            };
            let data = raw.abi_encode();
            assert_eq!(
                &data[..4],
                &keccak256("verifyAndAttestOnChainV2(bytes,uint32,bool)")[..4]
            );
            assert_eq!(
                IAutomataDcapAttestationV2::verifyAndAttestOnChainV2Call::abi_decode(&data)
                    .unwrap()
                    .minCheck,
                min_check
            );
            let zk = IAutomataDcapAttestationV2::verifyAndAttestWithZKProofV2Call {
                journal: Bytes::new(),
                backend: 1,
                proof: Bytes::new(),
                identifier: B256::ZERO,
                tcbEval: 17,
                minCheck: min_check,
            };
            let data = zk.abi_encode();
            assert_eq!(
                &data[..4],
                &keccak256("verifyAndAttestWithZKProofV2(bytes,uint8,bytes,bytes32,uint32,bool)")
                    [..4]
            );
            assert_eq!(
                IAutomataDcapAttestationV2::verifyAndAttestWithZKProofV2Call::abi_decode(&data)
                    .unwrap()
                    .minCheck,
                min_check
            );
        }
        assert_eq!(
            IAutomataDcapAttestationV2Default::verifyAndAttestOnChainV2Call::SELECTOR,
            keccak256("verifyAndAttestOnChainV2(bytes)")[..4]
        );
        assert_eq!(
            IAutomataDcapAttestationV2Default::verifyAndAttestWithZKProofV2Call::SELECTOR,
            keccak256("verifyAndAttestWithZKProofV2(bytes,uint8,bytes)")[..4]
        );
    }
}
