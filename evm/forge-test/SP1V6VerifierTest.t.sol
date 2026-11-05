// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ISP1VerifierV6} from "../contracts/interfaces/ISP1VerifierV6.sol";

/// Encoding/route regression only. Zero curve points are not an accepted proof.
contract SP1V6VerifierTest is Test {
    ISP1VerifierV6 verifier;

    function setUp() public {
        verifier = ISP1VerifierV6(deployCode("SP1Groth16VerifierV6.sol:SP1Groth16VerifierV6"));
    }

    function encoded(uint256 exitCode, uint256 root) internal view returns (bytes memory) {
        uint256[8] memory points;
        return abi.encodePacked(bytes4(verifier.VERIFIER_HASH()), abi.encode(exitCode, root, uint256(0), points));
    }

    function testVersionAndEncodingMatchSdk680Circuit610() public view {
        assertEq(verifier.VERSION(), "v6.1.0");
        assertEq(verifier.VERIFIER_HASH(), 0x4388a21c687fdd5f218d7e3d13190cac4c5355818d3605fd5fb811df468ee696);
        assertEq(verifier.VK_ROOT(), 0x002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352);
        assertEq(encoded(0, uint256(verifier.VK_ROOT())).length, 356);
    }

    function testRejectWrongSelector() public {
        vm.expectRevert(
            abi.encodeWithSignature(
                "WrongVerifierSelector(bytes4,bytes4)", bytes4(0x12345678), bytes4(verifier.VERIFIER_HASH())
            )
        );
        verifier.verifyProof(bytes32(uint256(1)), hex"abcd", hex"12345678");
    }

    function testRejectFailedGuestExit() public {
        bytes memory proof = encoded(1, uint256(verifier.VK_ROOT()));
        vm.expectRevert(bytes4(keccak256("InvalidExitCode()")));
        verifier.verifyProof(bytes32(uint256(1)), hex"abcd", proof);
    }

    function testRejectWrongRecursionRoot() public {
        bytes memory proof = encoded(0, 1);
        vm.expectRevert(bytes4(keccak256("InvalidVkRoot()")));
        verifier.verifyProof(bytes32(uint256(1)), hex"abcd", proof);
    }

    function testRejectLegacyLengthAndInvalidCurveProof() public {
        bytes memory proof = encoded(0, uint256(verifier.VK_ROOT()));
        bytes memory truncated = new bytes(260);
        for (uint256 i; i < truncated.length; ++i) {
            truncated[i] = proof[i];
        }
        vm.expectRevert();
        verifier.verifyProof(bytes32(uint256(1)), hex"abcd", truncated);
        vm.expectRevert();
        verifier.verifyProof(bytes32(uint256(1)), hex"abcd", proof);
    }
}
