// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package AutomataEnclaveIdentityDao

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

// EnclaveIdentityJsonObj is an auto generated low-level Go binding around an user-defined struct.
type EnclaveIdentityJsonObj struct {
	IdentityStr string
	Signature   []byte
}

// AutomataEnclaveIdentityDaoMetaData contains all meta data concerning the AutomataEnclaveIdentityDao contract.
var AutomataEnclaveIdentityDaoMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_storage\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_p256\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_pcs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_enclaveIdentityHelper\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_x509Helper\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"ENCLAVE_ID_KEY\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"version\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"EnclaveIdentityLib\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractEnclaveIdentityHelper\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"P256_VERIFIER\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"Pcs\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractPcsDao\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAttestedData\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"attestationData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCollateralHash\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"collateralHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getEnclaveIdentity\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"version\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"enclaveIdObj\",\"type\":\"tuple\",\"internalType\":\"structEnclaveIdentityJsonObj\",\"components\":[{\"name\":\"identityStr\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getEnclaveIdentityIssuerChain\",\"inputs\":[],\"outputs\":[{\"name\":\"signingCert\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rootCert\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"resolver\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIDaoAttestationResolver\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"upsertEnclaveIdentity\",\"inputs\":[{\"name\":\"id\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"version\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"enclaveIdentityObj\",\"type\":\"tuple\",\"internalType\":\"structEnclaveIdentityJsonObj\",\"components\":[{\"name\":\"identityStr\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"attestationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"x509\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"error\",\"name\":\"Enclave_Id_Expired\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Enclave_Id_Mismatch\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Incorrect_Enclave_Id_Version\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"Invalid_TCB_Cert_Signature\",\"inputs\":[]}]",
}

// AutomataEnclaveIdentityDaoABI is the input ABI used to generate the binding from.
// Deprecated: Use AutomataEnclaveIdentityDaoMetaData.ABI instead.
var AutomataEnclaveIdentityDaoABI = AutomataEnclaveIdentityDaoMetaData.ABI

// AutomataEnclaveIdentityDao is an auto generated Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDao struct {
	AutomataEnclaveIdentityDaoCaller     // Read-only binding to the contract
	AutomataEnclaveIdentityDaoTransactor // Write-only binding to the contract
	AutomataEnclaveIdentityDaoFilterer   // Log filterer for contract events
}

// AutomataEnclaveIdentityDaoCaller is an auto generated read-only Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDaoCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataEnclaveIdentityDaoTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDaoTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataEnclaveIdentityDaoFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AutomataEnclaveIdentityDaoFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataEnclaveIdentityDaoSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AutomataEnclaveIdentityDaoSession struct {
	Contract     *AutomataEnclaveIdentityDao // Generic contract binding to set the session for
	CallOpts     bind.CallOpts               // Call options to use throughout this session
	TransactOpts bind.TransactOpts           // Transaction auth options to use throughout this session
}

// AutomataEnclaveIdentityDaoCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AutomataEnclaveIdentityDaoCallerSession struct {
	Contract *AutomataEnclaveIdentityDaoCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                     // Call options to use throughout this session
}

// AutomataEnclaveIdentityDaoTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AutomataEnclaveIdentityDaoTransactorSession struct {
	Contract     *AutomataEnclaveIdentityDaoTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                     // Transaction auth options to use throughout this session
}

// AutomataEnclaveIdentityDaoRaw is an auto generated low-level Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDaoRaw struct {
	Contract *AutomataEnclaveIdentityDao // Generic contract binding to access the raw methods on
}

// AutomataEnclaveIdentityDaoCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDaoCallerRaw struct {
	Contract *AutomataEnclaveIdentityDaoCaller // Generic read-only contract binding to access the raw methods on
}

// AutomataEnclaveIdentityDaoTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AutomataEnclaveIdentityDaoTransactorRaw struct {
	Contract *AutomataEnclaveIdentityDaoTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAutomataEnclaveIdentityDao creates a new instance of AutomataEnclaveIdentityDao, bound to a specific deployed contract.
func NewAutomataEnclaveIdentityDao(address common.Address, backend bind.ContractBackend) (*AutomataEnclaveIdentityDao, error) {
	contract, err := bindAutomataEnclaveIdentityDao(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AutomataEnclaveIdentityDao{AutomataEnclaveIdentityDaoCaller: AutomataEnclaveIdentityDaoCaller{contract: contract}, AutomataEnclaveIdentityDaoTransactor: AutomataEnclaveIdentityDaoTransactor{contract: contract}, AutomataEnclaveIdentityDaoFilterer: AutomataEnclaveIdentityDaoFilterer{contract: contract}}, nil
}

// NewAutomataEnclaveIdentityDaoCaller creates a new read-only instance of AutomataEnclaveIdentityDao, bound to a specific deployed contract.
func NewAutomataEnclaveIdentityDaoCaller(address common.Address, caller bind.ContractCaller) (*AutomataEnclaveIdentityDaoCaller, error) {
	contract, err := bindAutomataEnclaveIdentityDao(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataEnclaveIdentityDaoCaller{contract: contract}, nil
}

// NewAutomataEnclaveIdentityDaoTransactor creates a new write-only instance of AutomataEnclaveIdentityDao, bound to a specific deployed contract.
func NewAutomataEnclaveIdentityDaoTransactor(address common.Address, transactor bind.ContractTransactor) (*AutomataEnclaveIdentityDaoTransactor, error) {
	contract, err := bindAutomataEnclaveIdentityDao(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataEnclaveIdentityDaoTransactor{contract: contract}, nil
}

// NewAutomataEnclaveIdentityDaoFilterer creates a new log filterer instance of AutomataEnclaveIdentityDao, bound to a specific deployed contract.
func NewAutomataEnclaveIdentityDaoFilterer(address common.Address, filterer bind.ContractFilterer) (*AutomataEnclaveIdentityDaoFilterer, error) {
	contract, err := bindAutomataEnclaveIdentityDao(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AutomataEnclaveIdentityDaoFilterer{contract: contract}, nil
}

// bindAutomataEnclaveIdentityDao binds a generic wrapper to an already deployed contract.
func bindAutomataEnclaveIdentityDao(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := AutomataEnclaveIdentityDaoMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataEnclaveIdentityDao.Contract.AutomataEnclaveIdentityDaoCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.AutomataEnclaveIdentityDaoTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.AutomataEnclaveIdentityDaoTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataEnclaveIdentityDao.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.contract.Transact(opts, method, params...)
}

// ENCLAVEIDKEY is a free data retrieval call binding the contract method 0xca108769.
//
// Solidity: function ENCLAVE_ID_KEY(uint256 id, uint256 version) pure returns(bytes32 key)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) ENCLAVEIDKEY(opts *bind.CallOpts, id *big.Int, version *big.Int) ([32]byte, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "ENCLAVE_ID_KEY", id, version)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ENCLAVEIDKEY is a free data retrieval call binding the contract method 0xca108769.
//
// Solidity: function ENCLAVE_ID_KEY(uint256 id, uint256 version) pure returns(bytes32 key)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) ENCLAVEIDKEY(id *big.Int, version *big.Int) ([32]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.ENCLAVEIDKEY(&_AutomataEnclaveIdentityDao.CallOpts, id, version)
}

// ENCLAVEIDKEY is a free data retrieval call binding the contract method 0xca108769.
//
// Solidity: function ENCLAVE_ID_KEY(uint256 id, uint256 version) pure returns(bytes32 key)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) ENCLAVEIDKEY(id *big.Int, version *big.Int) ([32]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.ENCLAVEIDKEY(&_AutomataEnclaveIdentityDao.CallOpts, id, version)
}

// EnclaveIdentityLib is a free data retrieval call binding the contract method 0x61d20bea.
//
// Solidity: function EnclaveIdentityLib() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) EnclaveIdentityLib(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "EnclaveIdentityLib")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// EnclaveIdentityLib is a free data retrieval call binding the contract method 0x61d20bea.
//
// Solidity: function EnclaveIdentityLib() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) EnclaveIdentityLib() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.EnclaveIdentityLib(&_AutomataEnclaveIdentityDao.CallOpts)
}

// EnclaveIdentityLib is a free data retrieval call binding the contract method 0x61d20bea.
//
// Solidity: function EnclaveIdentityLib() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) EnclaveIdentityLib() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.EnclaveIdentityLib(&_AutomataEnclaveIdentityDao.CallOpts)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) P256VERIFIER(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "P256_VERIFIER")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) P256VERIFIER() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.P256VERIFIER(&_AutomataEnclaveIdentityDao.CallOpts)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) P256VERIFIER() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.P256VERIFIER(&_AutomataEnclaveIdentityDao.CallOpts)
}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) Pcs(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "Pcs")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) Pcs() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.Pcs(&_AutomataEnclaveIdentityDao.CallOpts)
}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) Pcs() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.Pcs(&_AutomataEnclaveIdentityDao.CallOpts)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) GetAttestedData(opts *bind.CallOpts, key [32]byte) ([]byte, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "getAttestedData", key)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetAttestedData(&_AutomataEnclaveIdentityDao.CallOpts, key)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetAttestedData(&_AutomataEnclaveIdentityDao.CallOpts, key)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) GetCollateralHash(opts *bind.CallOpts, key [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "getCollateralHash", key)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetCollateralHash(&_AutomataEnclaveIdentityDao.CallOpts, key)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetCollateralHash(&_AutomataEnclaveIdentityDao.CallOpts, key)
}

// GetEnclaveIdentity is a free data retrieval call binding the contract method 0xf0f074f7.
//
// Solidity: function getEnclaveIdentity(uint256 id, uint256 version) view returns((string,bytes) enclaveIdObj)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) GetEnclaveIdentity(opts *bind.CallOpts, id *big.Int, version *big.Int) (EnclaveIdentityJsonObj, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "getEnclaveIdentity", id, version)

	if err != nil {
		return *new(EnclaveIdentityJsonObj), err
	}

	out0 := *abi.ConvertType(out[0], new(EnclaveIdentityJsonObj)).(*EnclaveIdentityJsonObj)

	return out0, err

}

// GetEnclaveIdentity is a free data retrieval call binding the contract method 0xf0f074f7.
//
// Solidity: function getEnclaveIdentity(uint256 id, uint256 version) view returns((string,bytes) enclaveIdObj)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) GetEnclaveIdentity(id *big.Int, version *big.Int) (EnclaveIdentityJsonObj, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetEnclaveIdentity(&_AutomataEnclaveIdentityDao.CallOpts, id, version)
}

// GetEnclaveIdentity is a free data retrieval call binding the contract method 0xf0f074f7.
//
// Solidity: function getEnclaveIdentity(uint256 id, uint256 version) view returns((string,bytes) enclaveIdObj)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) GetEnclaveIdentity(id *big.Int, version *big.Int) (EnclaveIdentityJsonObj, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetEnclaveIdentity(&_AutomataEnclaveIdentityDao.CallOpts, id, version)
}

// GetEnclaveIdentityIssuerChain is a free data retrieval call binding the contract method 0x7ecda5f0.
//
// Solidity: function getEnclaveIdentityIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) GetEnclaveIdentityIssuerChain(opts *bind.CallOpts) (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "getEnclaveIdentityIssuerChain")

	outstruct := new(struct {
		SigningCert []byte
		RootCert    []byte
	})
	if err != nil {
		return *outstruct, err
	}

	outstruct.SigningCert = *abi.ConvertType(out[0], new([]byte)).(*[]byte)
	outstruct.RootCert = *abi.ConvertType(out[1], new([]byte)).(*[]byte)

	return *outstruct, err

}

// GetEnclaveIdentityIssuerChain is a free data retrieval call binding the contract method 0x7ecda5f0.
//
// Solidity: function getEnclaveIdentityIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) GetEnclaveIdentityIssuerChain() (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetEnclaveIdentityIssuerChain(&_AutomataEnclaveIdentityDao.CallOpts)
}

// GetEnclaveIdentityIssuerChain is a free data retrieval call binding the contract method 0x7ecda5f0.
//
// Solidity: function getEnclaveIdentityIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) GetEnclaveIdentityIssuerChain() (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	return _AutomataEnclaveIdentityDao.Contract.GetEnclaveIdentityIssuerChain(&_AutomataEnclaveIdentityDao.CallOpts)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) Resolver(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "resolver")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) Resolver() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.Resolver(&_AutomataEnclaveIdentityDao.CallOpts)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) Resolver() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.Resolver(&_AutomataEnclaveIdentityDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCaller) X509(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataEnclaveIdentityDao.contract.Call(opts, &out, "x509")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) X509() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.X509(&_AutomataEnclaveIdentityDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoCallerSession) X509() (common.Address, error) {
	return _AutomataEnclaveIdentityDao.Contract.X509(&_AutomataEnclaveIdentityDao.CallOpts)
}

// UpsertEnclaveIdentity is a paid mutator transaction binding the contract method 0x30f704ea.
//
// Solidity: function upsertEnclaveIdentity(uint256 id, uint256 version, (string,bytes) enclaveIdentityObj) returns(bytes32 attestationId)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoTransactor) UpsertEnclaveIdentity(opts *bind.TransactOpts, id *big.Int, version *big.Int, enclaveIdentityObj EnclaveIdentityJsonObj) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.contract.Transact(opts, "upsertEnclaveIdentity", id, version, enclaveIdentityObj)
}

// UpsertEnclaveIdentity is a paid mutator transaction binding the contract method 0x30f704ea.
//
// Solidity: function upsertEnclaveIdentity(uint256 id, uint256 version, (string,bytes) enclaveIdentityObj) returns(bytes32 attestationId)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoSession) UpsertEnclaveIdentity(id *big.Int, version *big.Int, enclaveIdentityObj EnclaveIdentityJsonObj) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.UpsertEnclaveIdentity(&_AutomataEnclaveIdentityDao.TransactOpts, id, version, enclaveIdentityObj)
}

// UpsertEnclaveIdentity is a paid mutator transaction binding the contract method 0x30f704ea.
//
// Solidity: function upsertEnclaveIdentity(uint256 id, uint256 version, (string,bytes) enclaveIdentityObj) returns(bytes32 attestationId)
func (_AutomataEnclaveIdentityDao *AutomataEnclaveIdentityDaoTransactorSession) UpsertEnclaveIdentity(id *big.Int, version *big.Int, enclaveIdentityObj EnclaveIdentityJsonObj) (*types.Transaction, error) {
	return _AutomataEnclaveIdentityDao.Contract.UpsertEnclaveIdentity(&_AutomataEnclaveIdentityDao.TransactOpts, id, version, enclaveIdentityObj)
}
