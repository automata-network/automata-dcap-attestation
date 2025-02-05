// SPDX-License-Identifier: UNLICENSED

import "../../contracts/utils/BytesUtils.sol";
import "forge-std/Script.sol";

pragma solidity ^0.8.0;

contract P256Configuration is Script {
    using BytesUtils for bytes;

    address constant RIP7212_P256_PRECOMPILE = 0x0000000000000000000000000000000000000100;
    address constant DAIMO_P256 = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    bytes constant test_pubkey =
        hex"710f9d7cb59f86798aaf92138320831b778016d02cf0f5b416a76917f85edd4d7440615935921eaaa33c66c6cf4b745e70176a391610ab14f845d7ff39b112a3";
    bytes constant test_sig =
        hex"8c6a3bb0346ec08d01b6351eeff099fd7131de48e5e569dbcd9dc3f29e08995692db2eaebd633a52fff4915d274859bbc241967c6ce3a6831e754b88066fc534";
    bytes constant test_message = hex"a9b4ac5fb82203536c408b1db1d0338c61fd0064ea2471794d435fc0e03c217f";

    function run() public virtual {
        simulateVerify();
    }

    function simulateVerify() public returns (address verifier) {
        bytes memory data = abi.encodePacked(sha256(test_message), test_sig, test_pubkey);

        bool precompileVerified = verifyWithFfi(RIP7212_P256_PRECOMPILE, data);

        if (precompileVerified) {
            console.log("P256Verifier address: ", RIP7212_P256_PRECOMPILE);
            verifier = RIP7212_P256_PRECOMPILE;
        } else {
            bool daimoVerified = verifyWithFfi(DAIMO_P256, data);
            if (daimoVerified) {
                console.log("P256Verifier address: ", DAIMO_P256);
                verifier = DAIMO_P256;
            } else {
                revert("Failed to locate a verifier.");
            }
        }
    }

    function verifyWithFfi(address verifier, bytes memory data) private returns (bool) {
        string[] memory inputs = new string[](6);
        inputs[0] = "cast";
        inputs[1] = "call";
        inputs[2] = vm.toString(verifier);
        inputs[3] = vm.toString(data);
        inputs[4] = "--rpc-url";
        inputs[5] = vm.envString("RPC_URL");

        bytes memory ret = vm.ffi(inputs);

        if (ret.length == 0) {
            return false;
        } else {
            bool out = abi.decode(ret, (bool));
            return out;
        }
    }
}
