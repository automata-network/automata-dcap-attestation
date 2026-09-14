//! Additive FeeV2 bindings. Legacy generated modules are deliberately retained.
alloy::sol! {
    #[sol(rpc)]
    interface IAutomataDcapAttestationV2 {
        function verifyAndAttestOnChainV2(bytes calldata quote, uint32 tcbEval)
            external payable returns (bool success, bytes output);
        function verifyAndAttestWithZKProofV2(bytes calldata journal, uint8 backend, bytes calldata proof, bytes32 identifier, uint32 tcbEval)
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
