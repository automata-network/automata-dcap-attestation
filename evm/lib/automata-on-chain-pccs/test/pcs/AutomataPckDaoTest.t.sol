// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../pcs/PCSSetupBase.t.sol";
import {AutomataPckDao} from "../../src/automata_pccs/AutomataPckDao.sol";

contract AutomataPckDaoTest is PCSSetupBase {
    // TEMP: placeholder only, circle back on this to verify the inputs
    string constant qeid = "ad04024c9dfb382baf51ca3e5d6cb6e6";
    string constant pceid = "0000";
    string constant tcbm = "0c0c0303ffff010000000000000000000d00";
    string constant cpusvn = "0c0c100fffff01000000000000000000";
    string constant pcesvn = "0e00";

    function setUp() public override {
        super.setUp();
        pck.upsertPckCert(CA.PLATFORM, qeid, pceid, tcbm, pckDer);
        pck.upsertPlatformTcbs(qeid, pceid, cpusvn, pcesvn, tcbm);
    }

    function testGetCert() public readAsAuthorizedCaller {
        bytes memory fetchedCert = pck.getCert(qeid, cpusvn, pcesvn, pceid);
        (bytes16 qeidBytes, bytes2 pceidBytes,,, bytes18 tcbmBytes) =
            _parseStringInputs(qeid, pceid, cpusvn, pcesvn, tcbm);
        bytes32 fetchedCollateralHash = pck.getCollateralHash(pck.PCK_KEY(qeidBytes, pceidBytes, tcbmBytes));
        (bytes memory tbs,) = x509Lib.getTbsAndSig(pckDer);
        assertEq(fetchedCollateralHash, keccak256(tbs));
        assertEq(keccak256(fetchedCert), keccak256(pckDer));

        (string[] memory tcbms, bytes[] memory certs) = pck.getCerts(qeid, pceid);

        assertEq(keccak256(bytes(tcbms[0])), keccak256(bytes(tcbm)));
        assertEq(keccak256(certs[0]), keccak256(pckDer));
    }

    function testGetPlatformTcb() public readAsAuthorizedCaller {
        string memory fetchedTcbm = pck.getPlatformTcbByIdAndSvns(qeid, pceid, cpusvn, pcesvn);
        assertEq(keccak256(bytes(fetchedTcbm)), keccak256(bytes(tcbm)));
    }

    function testPckIssuerChain() public readAsAuthorizedCaller {
        (bytes memory intermediateCert, bytes memory rootCert) = pck.getPckCertChain(CA.PLATFORM);
        assertEq(keccak256(platformDer), keccak256(intermediateCert));
        assertEq(keccak256(rootDer), keccak256(rootCert));
    }

    // HELPER
    function _parseStringInputs(
        string memory qeid,
        string memory pceid,
        string memory platformCpuSvn,
        string memory platformPceSvn,
        string memory tcbm
    )
        private
        pure
        returns (
            bytes16 qeidBytes,
            bytes2 pceidBytes,
            bytes16 platformCpuSvnBytes,
            bytes2 platformPceSvnBytes,
            bytes18 tcbmBytes
        )
    {
        if (bytes(qeid).length == 32) {
            qeidBytes = bytes16(uint128(_parseUintFromHex(qeid)));
        }
        if (bytes(pceid).length == 4) {
            pceidBytes = bytes2(uint16(_parseUintFromHex(pceid)));
        }
        if (bytes(platformCpuSvn).length == 32) {
            platformCpuSvnBytes = bytes16(uint128(_parseUintFromHex(platformCpuSvn)));
        }
        if (bytes(platformPceSvn).length == 4) {
            platformPceSvnBytes = bytes2(uint16(_parseUintFromHex(platformPceSvn)));
        }
        if (bytes(tcbm).length == 36) {
            tcbmBytes = bytes18(uint144(_parseUintFromHex(tcbm)));
        }
    }

    function _parseUintFromHex(string memory s) private pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let n := mload(s)
            // Skip two if starts with '0x' or '0X'.
            let i := shl(1, and(eq(0x3078, or(shr(240, mload(add(s, 0x20))), 0x20)), gt(n, 1)))
            for {} 1 {} {
                i := add(i, 1)
                let c :=
                    byte(
                        and(0x1f, shr(and(mload(add(s, i)), 0xff), 0x3e4088843e41bac000000000000)),
                        0x3010a071000000b0104040208000c05090d060e0f
                    )
                n := mul(n, iszero(or(iszero(c), shr(252, result))))
                result := add(shl(4, result), sub(c, 1))
                if iszero(lt(i, n)) { break }
            }
            if iszero(n) {
                mstore(0x00, 0x10182796) // `ParsingFailed()`.
                revert(0x1c, 0x04)
            }
        }
    }
}
