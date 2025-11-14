// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum TcbId {
    SGX,
    TDX
}

struct TcbEvalJsonObj {
    string tcbEvaluationDataNumbers;
    bytes signature;
}

interface ITcbEvalDao {
    function getTcbEvaluationObject(TcbId id) external view returns (TcbEvalJsonObj memory tcbEvalObj);

    function getTcbEvaluationDataNumbers(TcbId id) external view returns (uint256[] memory tcbEvalDataNumbers);

    function early(TcbId id) external view returns (uint32 tcbEvaluationNumber);

    function standard(TcbId id) external view returns (uint32 tcbEvaluationNumber);

    function getTcbEvalIssuerChain() external view returns (bytes memory signingCert, bytes memory rootCert);

    function upsertTcbEvaluationData(TcbEvalJsonObj calldata tcbEvalObj) external returns (bytes32 attestationId);
}
