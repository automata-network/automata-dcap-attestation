// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package AutomataFmspcTcbDao

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

// TcbInfoJsonObj is an auto generated low-level Go binding around an user-defined struct.
type TcbInfoJsonObj struct {
	TcbInfoStr string
	Signature  []byte
}

// AutomataFmspcTcbDaoMetaData contains all meta data concerning the AutomataFmspcTcbDao contract.
var AutomataFmspcTcbDaoMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"constructor\",\"inputs\":[{\"name\":\"_storage\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_p256\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_pcs\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_fmspcHelper\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_x509Helper\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"FMSPC_TCB_KEY\",\"inputs\":[{\"name\":\"tcbType\",\"type\":\"uint8\",\"internalType\":\"uint8\"},{\"name\":\"fmspc\",\"type\":\"bytes6\",\"internalType\":\"bytes6\"},{\"name\":\"version\",\"type\":\"uint32\",\"internalType\":\"uint32\"}],\"outputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"pure\"},{\"type\":\"function\",\"name\":\"FmspcTcbLib\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractFmspcTcbHelper\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"P256_VERIFIER\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"Pcs\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractPcsDao\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getAttestedData\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"attestationData\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getCollateralHash\",\"inputs\":[{\"name\":\"key\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"outputs\":[{\"name\":\"collateralHash\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getTcbInfo\",\"inputs\":[{\"name\":\"tcbType\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"fmspc\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"version\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"outputs\":[{\"name\":\"tcbObj\",\"type\":\"tuple\",\"internalType\":\"structTcbInfoJsonObj\",\"components\":[{\"name\":\"tcbInfoStr\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"getTcbIssuerChain\",\"inputs\":[],\"outputs\":[{\"name\":\"signingCert\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"rootCert\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"resolver\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"contractIDaoAttestationResolver\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"upsertFmspcTcb\",\"inputs\":[{\"name\":\"tcbInfoObj\",\"type\":\"tuple\",\"internalType\":\"structTcbInfoJsonObj\",\"components\":[{\"name\":\"tcbInfoStr\",\"type\":\"string\",\"internalType\":\"string\"},{\"name\":\"signature\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"attestationId\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"x509\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"error\",\"name\":\"Invalid_TCB_Cert_Signature\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"TCB_Expired\",\"inputs\":[]}]",
}

// AutomataFmspcTcbDaoABI is the input ABI used to generate the binding from.
// Deprecated: Use AutomataFmspcTcbDaoMetaData.ABI instead.
var AutomataFmspcTcbDaoABI = AutomataFmspcTcbDaoMetaData.ABI

// AutomataFmspcTcbDao is an auto generated Go binding around an Ethereum contract.
type AutomataFmspcTcbDao struct {
	AutomataFmspcTcbDaoCaller     // Read-only binding to the contract
	AutomataFmspcTcbDaoTransactor // Write-only binding to the contract
	AutomataFmspcTcbDaoFilterer   // Log filterer for contract events
}

// AutomataFmspcTcbDaoCaller is an auto generated read-only Go binding around an Ethereum contract.
type AutomataFmspcTcbDaoCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataFmspcTcbDaoTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AutomataFmspcTcbDaoTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataFmspcTcbDaoFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AutomataFmspcTcbDaoFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataFmspcTcbDaoSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AutomataFmspcTcbDaoSession struct {
	Contract     *AutomataFmspcTcbDao // Generic contract binding to set the session for
	CallOpts     bind.CallOpts        // Call options to use throughout this session
	TransactOpts bind.TransactOpts    // Transaction auth options to use throughout this session
}

// AutomataFmspcTcbDaoCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AutomataFmspcTcbDaoCallerSession struct {
	Contract *AutomataFmspcTcbDaoCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts              // Call options to use throughout this session
}

// AutomataFmspcTcbDaoTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AutomataFmspcTcbDaoTransactorSession struct {
	Contract     *AutomataFmspcTcbDaoTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts              // Transaction auth options to use throughout this session
}

// AutomataFmspcTcbDaoRaw is an auto generated low-level Go binding around an Ethereum contract.
type AutomataFmspcTcbDaoRaw struct {
	Contract *AutomataFmspcTcbDao // Generic contract binding to access the raw methods on
}

// AutomataFmspcTcbDaoCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AutomataFmspcTcbDaoCallerRaw struct {
	Contract *AutomataFmspcTcbDaoCaller // Generic read-only contract binding to access the raw methods on
}

// AutomataFmspcTcbDaoTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AutomataFmspcTcbDaoTransactorRaw struct {
	Contract *AutomataFmspcTcbDaoTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAutomataFmspcTcbDao creates a new instance of AutomataFmspcTcbDao, bound to a specific deployed contract.
func NewAutomataFmspcTcbDao(address common.Address, backend bind.ContractBackend) (*AutomataFmspcTcbDao, error) {
	contract, err := bindAutomataFmspcTcbDao(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AutomataFmspcTcbDao{AutomataFmspcTcbDaoCaller: AutomataFmspcTcbDaoCaller{contract: contract}, AutomataFmspcTcbDaoTransactor: AutomataFmspcTcbDaoTransactor{contract: contract}, AutomataFmspcTcbDaoFilterer: AutomataFmspcTcbDaoFilterer{contract: contract}}, nil
}

// NewAutomataFmspcTcbDaoCaller creates a new read-only instance of AutomataFmspcTcbDao, bound to a specific deployed contract.
func NewAutomataFmspcTcbDaoCaller(address common.Address, caller bind.ContractCaller) (*AutomataFmspcTcbDaoCaller, error) {
	contract, err := bindAutomataFmspcTcbDao(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataFmspcTcbDaoCaller{contract: contract}, nil
}

// NewAutomataFmspcTcbDaoTransactor creates a new write-only instance of AutomataFmspcTcbDao, bound to a specific deployed contract.
func NewAutomataFmspcTcbDaoTransactor(address common.Address, transactor bind.ContractTransactor) (*AutomataFmspcTcbDaoTransactor, error) {
	contract, err := bindAutomataFmspcTcbDao(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataFmspcTcbDaoTransactor{contract: contract}, nil
}

// NewAutomataFmspcTcbDaoFilterer creates a new log filterer instance of AutomataFmspcTcbDao, bound to a specific deployed contract.
func NewAutomataFmspcTcbDaoFilterer(address common.Address, filterer bind.ContractFilterer) (*AutomataFmspcTcbDaoFilterer, error) {
	contract, err := bindAutomataFmspcTcbDao(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AutomataFmspcTcbDaoFilterer{contract: contract}, nil
}

// bindAutomataFmspcTcbDao binds a generic wrapper to an already deployed contract.
func bindAutomataFmspcTcbDao(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := AutomataFmspcTcbDaoMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataFmspcTcbDao.Contract.AutomataFmspcTcbDaoCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.AutomataFmspcTcbDaoTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.AutomataFmspcTcbDaoTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _AutomataFmspcTcbDao.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.contract.Transact(opts, method, params...)
}

// FMSPCTCBKEY is a free data retrieval call binding the contract method 0xb63e9e7b.
//
// Solidity: function FMSPC_TCB_KEY(uint8 tcbType, bytes6 fmspc, uint32 version) pure returns(bytes32 key)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) FMSPCTCBKEY(opts *bind.CallOpts, tcbType uint8, fmspc [6]byte, version uint32) ([32]byte, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "FMSPC_TCB_KEY", tcbType, fmspc, version)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// FMSPCTCBKEY is a free data retrieval call binding the contract method 0xb63e9e7b.
//
// Solidity: function FMSPC_TCB_KEY(uint8 tcbType, bytes6 fmspc, uint32 version) pure returns(bytes32 key)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) FMSPCTCBKEY(tcbType uint8, fmspc [6]byte, version uint32) ([32]byte, error) {
	return _AutomataFmspcTcbDao.Contract.FMSPCTCBKEY(&_AutomataFmspcTcbDao.CallOpts, tcbType, fmspc, version)
}

// FMSPCTCBKEY is a free data retrieval call binding the contract method 0xb63e9e7b.
//
// Solidity: function FMSPC_TCB_KEY(uint8 tcbType, bytes6 fmspc, uint32 version) pure returns(bytes32 key)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) FMSPCTCBKEY(tcbType uint8, fmspc [6]byte, version uint32) ([32]byte, error) {
	return _AutomataFmspcTcbDao.Contract.FMSPCTCBKEY(&_AutomataFmspcTcbDao.CallOpts, tcbType, fmspc, version)
}

// FmspcTcbLib is a free data retrieval call binding the contract method 0x4ba52fa5.
//
// Solidity: function FmspcTcbLib() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) FmspcTcbLib(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "FmspcTcbLib")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// FmspcTcbLib is a free data retrieval call binding the contract method 0x4ba52fa5.
//
// Solidity: function FmspcTcbLib() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) FmspcTcbLib() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.FmspcTcbLib(&_AutomataFmspcTcbDao.CallOpts)
}

// FmspcTcbLib is a free data retrieval call binding the contract method 0x4ba52fa5.
//
// Solidity: function FmspcTcbLib() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) FmspcTcbLib() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.FmspcTcbLib(&_AutomataFmspcTcbDao.CallOpts)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) P256VERIFIER(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "P256_VERIFIER")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) P256VERIFIER() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.P256VERIFIER(&_AutomataFmspcTcbDao.CallOpts)
}

// P256VERIFIER is a free data retrieval call binding the contract method 0x536c633d.
//
// Solidity: function P256_VERIFIER() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) P256VERIFIER() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.P256VERIFIER(&_AutomataFmspcTcbDao.CallOpts)
}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) Pcs(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "Pcs")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) Pcs() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.Pcs(&_AutomataFmspcTcbDao.CallOpts)
}

// Pcs is a free data retrieval call binding the contract method 0xd88d1df6.
//
// Solidity: function Pcs() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) Pcs() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.Pcs(&_AutomataFmspcTcbDao.CallOpts)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) GetAttestedData(opts *bind.CallOpts, key [32]byte) ([]byte, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "getAttestedData", key)

	if err != nil {
		return *new([]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([]byte)).(*[]byte)

	return out0, err

}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataFmspcTcbDao.Contract.GetAttestedData(&_AutomataFmspcTcbDao.CallOpts, key)
}

// GetAttestedData is a free data retrieval call binding the contract method 0xb414d0b2.
//
// Solidity: function getAttestedData(bytes32 key) view returns(bytes attestationData)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) GetAttestedData(key [32]byte) ([]byte, error) {
	return _AutomataFmspcTcbDao.Contract.GetAttestedData(&_AutomataFmspcTcbDao.CallOpts, key)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) GetCollateralHash(opts *bind.CallOpts, key [32]byte) ([32]byte, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "getCollateralHash", key)

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataFmspcTcbDao.Contract.GetCollateralHash(&_AutomataFmspcTcbDao.CallOpts, key)
}

// GetCollateralHash is a free data retrieval call binding the contract method 0xbf721aaf.
//
// Solidity: function getCollateralHash(bytes32 key) view returns(bytes32 collateralHash)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) GetCollateralHash(key [32]byte) ([32]byte, error) {
	return _AutomataFmspcTcbDao.Contract.GetCollateralHash(&_AutomataFmspcTcbDao.CallOpts, key)
}

// GetTcbInfo is a free data retrieval call binding the contract method 0xcfbc42fb.
//
// Solidity: function getTcbInfo(uint256 tcbType, string fmspc, uint256 version) view returns((string,bytes) tcbObj)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) GetTcbInfo(opts *bind.CallOpts, tcbType *big.Int, fmspc string, version *big.Int) (TcbInfoJsonObj, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "getTcbInfo", tcbType, fmspc, version)

	if err != nil {
		return *new(TcbInfoJsonObj), err
	}

	out0 := *abi.ConvertType(out[0], new(TcbInfoJsonObj)).(*TcbInfoJsonObj)

	return out0, err

}

// GetTcbInfo is a free data retrieval call binding the contract method 0xcfbc42fb.
//
// Solidity: function getTcbInfo(uint256 tcbType, string fmspc, uint256 version) view returns((string,bytes) tcbObj)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) GetTcbInfo(tcbType *big.Int, fmspc string, version *big.Int) (TcbInfoJsonObj, error) {
	return _AutomataFmspcTcbDao.Contract.GetTcbInfo(&_AutomataFmspcTcbDao.CallOpts, tcbType, fmspc, version)
}

// GetTcbInfo is a free data retrieval call binding the contract method 0xcfbc42fb.
//
// Solidity: function getTcbInfo(uint256 tcbType, string fmspc, uint256 version) view returns((string,bytes) tcbObj)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) GetTcbInfo(tcbType *big.Int, fmspc string, version *big.Int) (TcbInfoJsonObj, error) {
	return _AutomataFmspcTcbDao.Contract.GetTcbInfo(&_AutomataFmspcTcbDao.CallOpts, tcbType, fmspc, version)
}

// GetTcbIssuerChain is a free data retrieval call binding the contract method 0xa53e7275.
//
// Solidity: function getTcbIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) GetTcbIssuerChain(opts *bind.CallOpts) (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "getTcbIssuerChain")

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

// GetTcbIssuerChain is a free data retrieval call binding the contract method 0xa53e7275.
//
// Solidity: function getTcbIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) GetTcbIssuerChain() (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	return _AutomataFmspcTcbDao.Contract.GetTcbIssuerChain(&_AutomataFmspcTcbDao.CallOpts)
}

// GetTcbIssuerChain is a free data retrieval call binding the contract method 0xa53e7275.
//
// Solidity: function getTcbIssuerChain() view returns(bytes signingCert, bytes rootCert)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) GetTcbIssuerChain() (struct {
	SigningCert []byte
	RootCert    []byte
}, error) {
	return _AutomataFmspcTcbDao.Contract.GetTcbIssuerChain(&_AutomataFmspcTcbDao.CallOpts)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) Resolver(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "resolver")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) Resolver() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.Resolver(&_AutomataFmspcTcbDao.CallOpts)
}

// Resolver is a free data retrieval call binding the contract method 0x04f3bcec.
//
// Solidity: function resolver() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) Resolver() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.Resolver(&_AutomataFmspcTcbDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCaller) X509(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _AutomataFmspcTcbDao.contract.Call(opts, &out, "x509")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) X509() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.X509(&_AutomataFmspcTcbDao.CallOpts)
}

// X509 is a free data retrieval call binding the contract method 0xec950d33.
//
// Solidity: function x509() view returns(address)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoCallerSession) X509() (common.Address, error) {
	return _AutomataFmspcTcbDao.Contract.X509(&_AutomataFmspcTcbDao.CallOpts)
}

// UpsertFmspcTcb is a paid mutator transaction binding the contract method 0xa8349fb7.
//
// Solidity: function upsertFmspcTcb((string,bytes) tcbInfoObj) returns(bytes32 attestationId)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoTransactor) UpsertFmspcTcb(opts *bind.TransactOpts, tcbInfoObj TcbInfoJsonObj) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.contract.Transact(opts, "upsertFmspcTcb", tcbInfoObj)
}

// UpsertFmspcTcb is a paid mutator transaction binding the contract method 0xa8349fb7.
//
// Solidity: function upsertFmspcTcb((string,bytes) tcbInfoObj) returns(bytes32 attestationId)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoSession) UpsertFmspcTcb(tcbInfoObj TcbInfoJsonObj) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.UpsertFmspcTcb(&_AutomataFmspcTcbDao.TransactOpts, tcbInfoObj)
}

// UpsertFmspcTcb is a paid mutator transaction binding the contract method 0xa8349fb7.
//
// Solidity: function upsertFmspcTcb((string,bytes) tcbInfoObj) returns(bytes32 attestationId)
func (_AutomataFmspcTcbDao *AutomataFmspcTcbDaoTransactorSession) UpsertFmspcTcb(tcbInfoObj TcbInfoJsonObj) (*types.Transaction, error) {
	return _AutomataFmspcTcbDao.Contract.UpsertFmspcTcb(&_AutomataFmspcTcbDao.TransactOpts, tcbInfoObj)
}
