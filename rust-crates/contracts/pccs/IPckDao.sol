// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum CA {
    ROOT,
    PROCESSOR,
    PLATFORM,
    SIGNING
}

interface IPckDao {
    function getCert(
        string calldata qeid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata pceid
    ) external view returns (bytes memory pckCert);

    function getCerts(string calldata qeid, string calldata pceid)
        external
        view
        returns (string[] memory tcbms, bytes[] memory pckCerts);

    function getPlatformTcbByIdAndSvns(
        string calldata qeid,
        string calldata pceid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn
    ) external view returns (string memory tcbm);

    function getPckCertChain(CA ca)
        external
        view
        returns (bytes memory intermediateCert, bytes memory rootCert);

    function upsertPckCert(
        CA ca,
        string calldata qeid,
        string calldata pceid,
        string calldata tcbm,
        bytes calldata cert
    ) external returns (bytes32 attestationId);

    function upsertPlatformTcbs(
        string calldata qeid,
        string calldata pceid,
        string calldata platformCpuSvn,
        string calldata platformPceSvn,
        string calldata tcbm
    ) external returns (bytes32);
}
