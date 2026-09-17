# V2 deployment registry

No V2 deployments are published yet. Isolated test deployments may populate chain directories
after confirmed live readback, with a TEST_ONLY manifest; this is not real-proof acceptance
or release approval. Production promotion still requires the real-proof release gate.
Preserve legacy keys and add AutomataDcapAttestationFeeV2,
V3QuoteVerifierV2, V4QuoteVerifierV2, V5QuoteVerifierV2, PCCSRouterV2, and PCKHelperV2.
Never resolve a missing V2 address to the old Fee contract.
V2 SDK selection requires PCCSRouterV2 and never falls back to the old PCCSRouter key.

Use scripts/deploy-dcap-v2/publish-v2.mjs after isolated deployment. It also adds
PCKHelperV2 to the PCCS submodule's flat deployment/<chain>.json without replacing
PCKHelper. Existing universal verifier addresses in ZK submodules are unchanged.

The v1.1 directory is the frozen pre-V2 snapshot. The current alias is not promoted by this change.
After accepted broad rollout, synchronize selected current chain files from v2.0
in a separate approved release step; preserve frozen v1.1 and legacy keys.
