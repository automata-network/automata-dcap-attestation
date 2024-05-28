//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {
    EnclaveIdentityHelper,
    EnclaveIdentityJsonObj,
    IdentityObj,
    EnclaveId,
    Tcb,
    EnclaveIdTcbStatus
} from "@automata-network/on-chain-pccs/helpers/EnclaveIdentityHelper.sol";
import {EnclaveIdentityDao} from "@automata-network/on-chain-pccs/bases/EnclaveIdentityDao.sol";

abstract contract EnclaveIdBase {
    EnclaveIdentityDao public enclaveIdDao;
    EnclaveIdentityHelper public enclaveIdHelper;

    constructor(address _enclaveIdDao, address _enclaveIdHelper) {
        _setEnclaveIdBaseConfig(_enclaveIdDao, _enclaveIdHelper);
    }

    function _setEnclaveIdBaseConfig(address _enclaveIdDao, address _enclaveIdHelper) internal {
        enclaveIdDao = EnclaveIdentityDao(_enclaveIdDao);
        enclaveIdHelper = EnclaveIdentityHelper(_enclaveIdHelper);
    }

    /// @dev https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47-L113
    function _verifyQEReportWithIdentity(
        EnclaveId enclaveId,
        uint256 quoteVersion,
        bytes4 enclaveReportMiscselect,
        bytes16 enclaveReportAttributes,
        bytes32 enclaveReportMrsigner,
        uint16 enclaveReportIsvprodid,
        uint16 enclaveReportIsvSvn
    ) internal view returns (bool, EnclaveIdTcbStatus status) {
        bytes32 key = keccak256(abi.encodePacked(uint256(enclaveId), uint256(quoteVersion)));
        bytes32 attestationId = enclaveIdDao.enclaveIdentityAttestations(key);
        bytes memory data = enclaveIdDao.getAttestedData(attestationId);

        (IdentityObj memory identity,,) = abi.decode(data, (IdentityObj, string, bytes));

        bool miscselectMatched = enclaveReportMiscselect & identity.miscselectMask == identity.miscselect;
        bool attributesMatched = enclaveReportAttributes & identity.attributesMask == identity.attributes;
        bool mrsignerMatched = enclaveReportMrsigner == identity.mrsigner;
        bool isvprodidMatched = enclaveReportIsvprodid == identity.isvprodid;

        bool tcbFound;
        for (uint256 i = 0; i < identity.tcb.length; i++) {
            if (identity.tcb[i].isvsvn <= enclaveReportIsvSvn) {
                tcbFound = true;
                status = identity.tcb[i].status;
                break;
            }
        }
        return (miscselectMatched && attributesMatched && mrsignerMatched && isvprodidMatched && tcbFound, status);
    }
}
