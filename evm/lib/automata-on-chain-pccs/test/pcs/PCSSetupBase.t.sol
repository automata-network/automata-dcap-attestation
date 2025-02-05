// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "../TestSetupBase.t.sol";

import {PCSConstants} from "./PCSConstants.t.sol";
import {CA} from "../../src/Common.sol";

abstract contract PCSSetupBase is TestSetupBase, PCSConstants {
    function setUp() public virtual override {
        super.setUp();

        // insert root CA
        pcs.upsertPcsCertificates(CA.ROOT, rootDer);

        // insert root CRL
        pcs.upsertRootCACrl(rootCrlDer);

        // insert Signing CA
        pcs.upsertPcsCertificates(CA.SIGNING, signingDer);

        // insert Platform CA
        pcs.upsertPcsCertificates(CA.PLATFORM, platformDer);
    }

    function testPcsSetup() public readAsAuthorizedCaller {
        // validate RootCA attestations
        bytes32 key = pcs.PCS_KEY(CA.ROOT, false);
        bytes memory attestedData = pcs.getAttestedData(key);
        bytes32 collateralHash = pcs.getCollateralHash(key);
        (bytes memory tbs,) = x509Lib.getTbsAndSig(rootDer);
        bytes32 actualHash = keccak256(tbs);
        assertEq(actualHash, collateralHash);
        assertEq(keccak256(attestedData), keccak256(rootDer));

        // validate RootCRL attestations
        key = pcs.PCS_KEY(CA.ROOT, true);
        attestedData = pcs.getAttestedData(key);
        collateralHash = pcs.getCollateralHash(key);
        (tbs,) = x509CrlLib.getTbsAndSig(rootCrlDer);
        actualHash = keccak256(tbs);
        assertEq(actualHash, collateralHash);
        assertEq(keccak256(attestedData), keccak256(rootCrlDer));

        // validate SigningCA attestations
        key = pcs.PCS_KEY(CA.SIGNING, false);
        attestedData = pcs.getAttestedData(key);
        collateralHash = pcs.getCollateralHash(key);
        (tbs,) = x509CrlLib.getTbsAndSig(signingDer);
        actualHash = keccak256(tbs);
        assertEq(actualHash, collateralHash);
        assertEq(keccak256(attestedData), keccak256(signingDer));

        // validate PlatformCA attestations
        key = pcs.PCS_KEY(CA.PLATFORM, false);
        attestedData = pcs.getAttestedData(key);
        collateralHash = pcs.getCollateralHash(key);
        (tbs,) = x509CrlLib.getTbsAndSig(platformDer);
        actualHash = keccak256(tbs);
        assertEq(actualHash, collateralHash);
        assertEq(keccak256(attestedData), keccak256(platformDer));
    }
}
