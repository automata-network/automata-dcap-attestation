// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

abstract contract TDXConstants {
    bytes internal mrsigner =
        hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    bytes8 internal constant attributes = 0x0000000000000000;
    bytes8 internal constant attributesMask = 0xFFFFFFFFFFFFFFFF;
    string internal moduleIdentitiesId = "TDX_01";
}
