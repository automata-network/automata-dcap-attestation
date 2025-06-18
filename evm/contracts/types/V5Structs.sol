//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./CommonStruct.sol";
import "./V4Structs.sol";

struct TD15ReportBody {
    bytes16 teeTcbSvn;
    bytes mrSeam; // 48 bytes
    bytes mrsignerSeam; // 48 bytes
    bytes8 seamAttributes;
    bytes8 tdAttributes;
    bytes8 xFAM;
    bytes mrTd; // 48 bytes
    bytes mrConfigId; // 48 bytes
    bytes mrOwner; // 48 bytes
    bytes mrOwnerConfig; // 48 bytes
    bytes rtMr0; // 48 bytes
    bytes rtMr1; // 48 nytes
    bytes rtMr2; // 48 bytes
    bytes rtMr3; // 48 bytes
    bytes reportData; // 64 bytes
    bytes16 teeTcbSvn2;
    bytes mrServiceTd; // 48 bytes
}
