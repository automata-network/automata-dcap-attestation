// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

enum CA {
    ROOT,
    PROCESSOR,
    PLATFORM,
    SIGNING
}

interface IPcsDao {
    function getCertificateById(CA ca) external view returns (bytes memory cert, bytes memory crl);

    function upsertPcsCertificates(CA ca, bytes calldata cert) external returns (bytes32 attestationId);

    function upsertPckCrl(CA ca, bytes calldata crl) external returns (bytes32 attestationId);

    function upsertRootCACrl(bytes calldata rootcacrl) external returns (bytes32 attestationId);
}
