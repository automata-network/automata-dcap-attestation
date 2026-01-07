// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package AutomataPcsDao

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// AutomataPcsDaoMetaData contains all meta data concerning the AutomataPcsDao contract.
var AutomataPcsDaoMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_storage\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_p256\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_x509\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_crl\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"P256_VERIFIER\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"PCS_KEY\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"},{\"name\":\"isCrl\",\"type\":\"bool\",\"internalType\":\"bool\"}],\"outputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"crlLib\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractX509CRLHelper\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAttestedData\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"attestationData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCertificateById\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"}],\"outputs\":[{\"name\":\"cert\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"crl\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCollateralHash\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"collateralHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"resolver\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIDaoAttestationResolver\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"upsertPckCrl\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"},{\"name\":\"crl\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"attestationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upsertPcsCertificates\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"},{\"name\":\"cert\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"attestationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upsertRootCACrl\",\"inputs\":[{\"name\":\"rootcacrl\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"attestationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"x509\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"error\",\"name\":\"Certificate_Expired\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Certificate_Revoked\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"},{\"name\":\"serialNum\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"Expired_Certificates\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Invalid_Issuer_Name\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Invalid_PCK_CA\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"}]},{\"type\":\"error\",\"name\":\"Invalid_Signature\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Invalid_Subject_Name\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Missing_Certificate\",\"inputs\":[{\"name\":\"ca\",\"type\":\"uint8\",\"internalType\":\"enumCA\"}]},{\"type\":\"error\",\"name\":\"Missing_Issuer\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Root_Key_Mismatch\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TCB_Mismatch\",\"inputs\":[]}]",
}

// AutomataPcsDaoABI is the input ABI used to generate the binding from.
// Deprecated: Use AutomataPcsDaoMetaData.ABI instead.
var AutomataPcsDaoABI = AutomataPcsDaoMetaData.ABI

// AutomataPcsDao is an auto generated Go binding around an Ethereum contract.
type AutomataPcsDao struct {
	AutomataPcsDaoCaller     // Read-only binding to the contract
	AutomataPcsDaoTransactor // Write-only binding to the contract
	AutomataPcsDaoFilterer   // Log filterer for contract events
}

// AutomataPcsDaoCaller is an auto generated read-only Go binding around an Ethereum contract.
type AutomataPcsDaoCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataPcsDaoTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AutomataPcsDaoTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataPcsDaoFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AutomataPcsDaoFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataPcsDaoSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AutomataPcsDaoSession struct {
	Contract     *AutomataPcsDao   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// AutomataPcsDaoCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AutomataPcsDaoCallerSession struct {
	Contract *AutomataPcsDaoCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// AutomataPcsDaoTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AutomataPcsDaoTransactorSession struct {
	Contract     *AutomataPcsDaoTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// AutomataPcsDaoRaw is an auto generated low-level Go binding around an Ethereum contract.
type AutomataPcsDaoRaw struct {
	Contract *AutomataPcsDao // Generic contract binding to access the raw methods on
}

// AutomataPcsDaoCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AutomataPcsDaoCallerRaw struct {
	Contract *AutomataPcsDaoCaller // Generic read-only contract binding to access the raw methods on
}

// AutomataPcsDaoTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AutomataPcsDaoTransactorRaw struct {
	Contract *AutomataPcsDaoTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAutomataPcsDao creates a new instance of AutomataPcsDao, bound to a specific deployed contract.
func NewAutomataPcsDao(address common.Address, backend bind.ContractBackend) (*AutomataPcsDao, error) {
	contract, err := bindAutomataPcsDao(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AutomataPcsDao{AutomataPcsDaoCaller: AutomataPcsDaoCaller{contract: contract}, AutomataPcsDaoTransactor: AutomataPcsDaoTransactor{contract: contract}, AutomataPcsDaoFilterer: AutomataPcsDaoFilterer{contract: contract}}, nil
}

// NewAutomataPcsDaoCaller creates a new read-only instance of AutomataPcsDao, bound to a specific deployed contract.
func NewAutomataPcsDaoCaller(address common.Address, caller bind.ContractCaller) (*AutomataPcsDaoCaller, error) {
	contract, err := bindAutomataPcsDao(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataPcsDaoCaller{contract: contract}, nil
}

// NewAutomataPcsDaoTransactor creates a new write-only instance of AutomataPcsDao, bound to a specific deployed contract.
func NewAutomataPcsDaoTransactor(address common.Address, transactor bind.ContractTransactor) (*AutomataPcsDaoTransactor, error) {
	contract, err := bindAutomataPcsDao(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataPcsDaoTransactor{contract: contract}, nil
}

// NewAutomataPcsDaoFilterer creates a new log filterer instance of AutomataPcsDao, bound to a specific deployed contract.
func NewAutomataPcsDaoFilterer(address common.Address, filterer bind.ContractFilterer) (*AutomataPcsDaoFilterer, error) {
	contract, err := bindAutomataPcsDao(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AutomataPcsDaoFilterer{contract: contract}, nil
}

// bindAutomataPcsDao binds a generic wrapper to an already deployed contract.
func bindAutomataPcsDao(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := AutomataPcsDaoMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataPcsDao *AutomataPcsDaoRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataPcsDao.Contract.AutomataPcsDaoCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataPcsDao *AutomataPcsDaoRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.AutomataPcsDaoTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataPcsDao *AutomataPcsDaoRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.AutomataPcsDaoTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataPcsDao *AutomataPcsDaoCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataPcsDao.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataPcsDao *AutomataPcsDaoTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataPcsDao *AutomataPcsDaoTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.contract.Transact(opts, method, params...)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCaller) P256VERIFIER(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "P256_VERIFIER")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoSession) P256VERIFIER() (common.Address, error) {
	return _AutomataPcsDao.Contract.P256VERIFIER(&_AutomataPcsDao.CallOpts)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) P256VERIFIER() (common.Address, error) {
	return _AutomataPcsDao.Contract.P256VERIFIER(&_AutomataPcsDao.CallOpts)
}

// PCSKEY is a free data retrieval call binding the contract method 0xb13bf290.
//
// Solidity: function PCS_KEY(uint8 ca, bool isCrl) pure returns(bytes32 key)
func (_AutomataPcsDao *AutomataPcsDaoCaller) PCSKEY(opts *bind.CallOpts, ca uint8, isCrl bool) ([32]byte, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "PCS_KEY", ca, isCrl)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// PCSKEY is a free data retrieval call binding the contract method 0xb13bf290.
//
// Solidity: function PCS_KEY(uint8 ca, bool isCrl) pure returns(bytes32 key)
func (_AutomataPcsDao *AutomataPcsDaoSession) PCSKEY(ca uint8, isCrl bool) ([32]byte, error) {
	return _AutomataPcsDao.Contract.PCSKEY(&_AutomataPcsDao.CallOpts, ca, isCrl)
}

// PCSKEY is a free data retrieval call binding the contract method 0xb13bf290.
//
// Solidity: function PCS_KEY(uint8 ca, bool isCrl) pure returns(bytes32 key)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) PCSKEY(ca uint8, isCrl bool) ([32]byte, error) {
	return _AutomataPcsDao.Contract.PCSKEY(&_AutomataPcsDao.CallOpts, ca, isCrl)
}

// CrlLib is a free data retrieval call binding the contract method 0x37b8762d.
//
// Solidity: function crlLib() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCaller) CrlLib(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "crlLib")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// CrlLib is a free data retrieval call binding the contract method 0x37b8762d.
//
// Solidity: function crlLib() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoSession) CrlLib() (common.Address, error) {
	return _AutomataPcsDao.Contract.CrlLib(&_AutomataPcsDao.CallOpts)
}

// CrlLib is a free data retrieval call binding the contract method 0x37b8762d.
//
// Solidity: function crlLib() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) CrlLib() (common.Address, error) {
	return _AutomataPcsDao.Contract.CrlLib(&_AutomataPcsDao.CallOpts)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataPcsDao *AutomataPcsDaoCaller) GetAttestedData(opts *bind.CallOpts, key [32]byte) ([]byte, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "getAttestedData", key)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataPcsDao *AutomataPcsDaoSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataPcsDao.Contract.GetAttestedData(&_AutomataPcsDao.CallOpts, key)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataPcsDao.Contract.GetAttestedData(&_AutomataPcsDao.CallOpts, key)
}

// GetCertificateById is a free data retrieval call binding the contract method 0x722f1327.
//
// Solidity: function getCertificateById(uint8 ca) view returns(bytes cert, bytes crl)
func (_AutomataPcsDao *AutomataPcsDaoCaller) GetCertificateById(opts *bind.CallOpts, ca uint8) (struct {
	Cert []byte
	Crl  []byte
}, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "getCertificateById", ca)

	outstruct := new(struct {
		Cert []byte
		Crl  []byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.Cert = *abi.ConvertType(out[0], new([]byte)).(*[]byte)
	outstruct.Crl = *abi.ConvertType(out[1], new([]byte)).(*[]byte)

	return *outstruct, err

}

// GetCertificateById is a free data retrieval call binding the contract method 0x722f1327.
//
// Solidity: function getCertificateById(uint8 ca) view returns(bytes cert, bytes crl)
func (_AutomataPcsDao *AutomataPcsDaoSession) GetCertificateById(ca uint8) (struct {
	Cert []byte
	Crl  []byte
}, error) {
	return _AutomataPcsDao.Contract.GetCertificateById(&_AutomataPcsDao.CallOpts, ca)
}

// GetCertificateById is a free data retrieval call binding the contract method 0x722f1327.
//
// Solidity: function getCertificateById(uint8 ca) view returns(bytes cert, bytes crl)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) GetCertificateById(ca uint8) (struct {
	Cert []byte
	Crl  []byte
}, error) {
	return _AutomataPcsDao.Contract.GetCertificateById(&_AutomataPcsDao.CallOpts, ca)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataPcsDao *AutomataPcsDaoCaller) GetCollateralHash(opts *bind.CallOpts, key [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "getCollateralHash", key)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataPcsDao *AutomataPcsDaoSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataPcsDao.Contract.GetCollateralHash(&_AutomataPcsDao.CallOpts, key)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataPcsDao.Contract.GetCollateralHash(&_AutomataPcsDao.CallOpts, key)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCaller) Resolver(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "resolver")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoSession) Resolver() (common.Address, error) {
	return _AutomataPcsDao.Contract.Resolver(&_AutomataPcsDao.CallOpts)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) Resolver() (common.Address, error) {
	return _AutomataPcsDao.Contract.Resolver(&_AutomataPcsDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCaller) X509(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataPcsDao.contract.Call(opts, &out, "x509")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoSession) X509() (common.Address, error) {
	return _AutomataPcsDao.Contract.X509(&_AutomataPcsDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataPcsDao *AutomataPcsDaoCallerSession) X509() (common.Address, error) {
	return _AutomataPcsDao.Contract.X509(&_AutomataPcsDao.CallOpts)
}

// UpsertPckCrl is a paid mutator transaction binding the contract method 0x08854e04.
//
// Solidity: function upsertPckCrl(uint8 ca, bytes crl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactor) UpsertPckCrl(opts *bind.TransactOpts, ca uint8, crl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.contract.Transact(opts, "upsertPckCrl", ca, crl)
}

// UpsertPckCrl is a paid mutator transaction binding the contract method 0x08854e04.
//
// Solidity: function upsertPckCrl(uint8 ca, bytes crl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoSession) UpsertPckCrl(ca uint8, crl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertPckCrl(&_AutomataPcsDao.TransactOpts, ca, crl)
}

// UpsertPckCrl is a paid mutator transaction binding the contract method 0x08854e04.
//
// Solidity: function upsertPckCrl(uint8 ca, bytes crl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactorSession) UpsertPckCrl(ca uint8, crl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertPckCrl(&_AutomataPcsDao.TransactOpts, ca, crl)
}

// UpsertPcsCertificates is a paid mutator transaction binding the contract method 0x3b395455.
//
// Solidity: function upsertPcsCertificates(uint8 ca, bytes cert) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactor) UpsertPcsCertificates(opts *bind.TransactOpts, ca uint8, cert []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.contract.Transact(opts, "upsertPcsCertificates", ca, cert)
}

// UpsertPcsCertificates is a paid mutator transaction binding the contract method 0x3b395455.
//
// Solidity: function upsertPcsCertificates(uint8 ca, bytes cert) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoSession) UpsertPcsCertificates(ca uint8, cert []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertPcsCertificates(&_AutomataPcsDao.TransactOpts, ca, cert)
}

// UpsertPcsCertificates is a paid mutator transaction binding the contract method 0x3b395455.
//
// Solidity: function upsertPcsCertificates(uint8 ca, bytes cert) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactorSession) UpsertPcsCertificates(ca uint8, cert []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertPcsCertificates(&_AutomataPcsDao.TransactOpts, ca, cert)
}

// UpsertRootCACrl is a paid mutator transaction binding the contract method 0x6b1c5399.
//
// Solidity: function upsertRootCACrl(bytes rootcacrl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactor) UpsertRootCACrl(opts *bind.TransactOpts, rootcacrl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.contract.Transact(opts, "upsertRootCACrl", rootcacrl)
}

// UpsertRootCACrl is a paid mutator transaction binding the contract method 0x6b1c5399.
//
// Solidity: function upsertRootCACrl(bytes rootcacrl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoSession) UpsertRootCACrl(rootcacrl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertRootCACrl(&_AutomataPcsDao.TransactOpts, rootcacrl)
}

// UpsertRootCACrl is a paid mutator transaction binding the contract method 0x6b1c5399.
//
// Solidity: function upsertRootCACrl(bytes rootcacrl) returns(bytes32 attestationId)
func (_AutomataPcsDao *AutomataPcsDaoTransactorSession) UpsertRootCACrl(rootcacrl []byte) (*types.Transaction, error) {
	return _AutomataPcsDao.Contract.UpsertRootCACrl(&_AutomataPcsDao.TransactOpts, rootcacrl)
}
