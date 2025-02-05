// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {PcsDao, X509CRLHelper, DaoBase} from "../bases/PcsDao.sol";
import {AutomataDaoBase} from "./shared/AutomataDaoBase.sol";

contract AutomataPcsDao is AutomataDaoBase, PcsDao {
    constructor(address _storage, address _p256, address _x509, address _crl) PcsDao(_storage, _p256, _x509, _crl) {}

    function _onFetchDataFromResolver(bytes32 key, bool hash)
        internal
        view
        override(AutomataDaoBase, DaoBase)
        returns (bytes memory data)
    {
        data = super._onFetchDataFromResolver(key, hash);
    }
}
