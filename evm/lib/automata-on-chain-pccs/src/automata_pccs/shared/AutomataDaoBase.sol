// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {AutomataDaoStorage} from "./AutomataDaoStorage.sol";
import {DaoBase} from "../../bases/DaoBase.sol";

abstract contract AutomataDaoBase is DaoBase {
    
    /**
     * @notice overridden the default method to check caller authorization
     * this is added as a temporary measure to only allow read operations from
     * the PCCSRouter contract (Learn more about PCCSRouter at
     * https://github.com/automata-network/automata-dcap-attestation/blob/DEV-3373/audit/contracts/PCCSRouter.sol)
     * 
     * @notice this restriction may be removed in the future
     */
    function _onFetchDataFromResolver(bytes32 key, bool hash)
        internal
        view
        virtual
        override
        returns (bytes memory data)
    {
        if (_callerIsAuthorized()) {
            data = super._onFetchDataFromResolver(key, hash);
        }
    }

    function _callerIsAuthorized() private view returns (bool authorized) {
        AutomataDaoStorage automataStorage = AutomataDaoStorage(address(resolver));
        authorized = automataStorage.paused() || automataStorage.isAuthorizedCaller(msg.sender);
    }
}
