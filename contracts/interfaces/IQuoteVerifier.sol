//SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import {IPCCSRouter} from "./IPCCSRouter.sol";
import {Header} from "../types/CommonStruct.sol";

interface IQuoteVerifier {
    /// @dev immutable
    function pccsRouter() external view returns (IPCCSRouter);

    /// @dev immutable
    function quoteVersion() external view returns (uint16);

    function verifyQuote(Header calldata, bytes calldata) external view returns (bool, bytes memory);

    function verifyJournal(bytes calldata) external view returns (bool, bytes memory);
}
