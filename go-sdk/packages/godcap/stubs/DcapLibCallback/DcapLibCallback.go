// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package DcapLibCallback

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

// DcapLibCallbackMetaData contains all meta data concerning the DcapLibCallback contract.
var DcapLibCallbackMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"error\",\"name\":\"CALLER_NOT_DCAP_PORTAL\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"INVALID_ATTESTATION_OUTPUT\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"INVALID_BLOCKHASH\",\"inputs\":[{\"name\":\"want\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"got\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"},{\"name\":\"number\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"INVALID_BLOCKNUMBER\",\"inputs\":[{\"name\":\"current\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"got\",\"type\":\"uint256\",\"internalType\":\"uint256\"}]},{\"type\":\"error\",\"name\":\"MAGIC_NUMBER_MISMATCH\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UNKNOWN_VERSION\",\"inputs\":[{\"name\":\"\",\"type\":\"uint8\",\"internalType\":\"uint8\"}]}]",
}

// DcapLibCallbackABI is the input ABI used to generate the binding from.
// Deprecated: Use DcapLibCallbackMetaData.ABI instead.
var DcapLibCallbackABI = DcapLibCallbackMetaData.ABI

// DcapLibCallback is an auto generated Go binding around an Ethereum contract.
type DcapLibCallback struct {
	DcapLibCallbackCaller     // Read-only binding to the contract
	DcapLibCallbackTransactor // Write-only binding to the contract
	DcapLibCallbackFilterer   // Log filterer for contract events
}

// DcapLibCallbackCaller is an auto generated read-only Go binding around an Ethereum contract.
type DcapLibCallbackCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapLibCallbackTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DcapLibCallbackTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapLibCallbackFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DcapLibCallbackFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapLibCallbackSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DcapLibCallbackSession struct {
	Contract     *DcapLibCallback  // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// DcapLibCallbackCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DcapLibCallbackCallerSession struct {
	Contract *DcapLibCallbackCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts          // Call options to use throughout this session
}

// DcapLibCallbackTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DcapLibCallbackTransactorSession struct {
	Contract     *DcapLibCallbackTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts          // Transaction auth options to use throughout this session
}

// DcapLibCallbackRaw is an auto generated low-level Go binding around an Ethereum contract.
type DcapLibCallbackRaw struct {
	Contract *DcapLibCallback // Generic contract binding to access the raw methods on
}

// DcapLibCallbackCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DcapLibCallbackCallerRaw struct {
	Contract *DcapLibCallbackCaller // Generic read-only contract binding to access the raw methods on
}

// DcapLibCallbackTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DcapLibCallbackTransactorRaw struct {
	Contract *DcapLibCallbackTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDcapLibCallback creates a new instance of DcapLibCallback, bound to a specific deployed contract.
func NewDcapLibCallback(address common.Address, backend bind.ContractBackend) (*DcapLibCallback, error) {
	contract, err := bindDcapLibCallback(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DcapLibCallback{DcapLibCallbackCaller: DcapLibCallbackCaller{contract: contract}, DcapLibCallbackTransactor: DcapLibCallbackTransactor{contract: contract}, DcapLibCallbackFilterer: DcapLibCallbackFilterer{contract: contract}}, nil
}

// NewDcapLibCallbackCaller creates a new read-only instance of DcapLibCallback, bound to a specific deployed contract.
func NewDcapLibCallbackCaller(address common.Address, caller bind.ContractCaller) (*DcapLibCallbackCaller, error) {
	contract, err := bindDcapLibCallback(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DcapLibCallbackCaller{contract: contract}, nil
}

// NewDcapLibCallbackTransactor creates a new write-only instance of DcapLibCallback, bound to a specific deployed contract.
func NewDcapLibCallbackTransactor(address common.Address, transactor bind.ContractTransactor) (*DcapLibCallbackTransactor, error) {
	contract, err := bindDcapLibCallback(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DcapLibCallbackTransactor{contract: contract}, nil
}

// NewDcapLibCallbackFilterer creates a new log filterer instance of DcapLibCallback, bound to a specific deployed contract.
func NewDcapLibCallbackFilterer(address common.Address, filterer bind.ContractFilterer) (*DcapLibCallbackFilterer, error) {
	contract, err := bindDcapLibCallback(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DcapLibCallbackFilterer{contract: contract}, nil
}

// bindDcapLibCallback binds a generic wrapper to an already deployed contract.
func bindDcapLibCallback(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := DcapLibCallbackMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DcapLibCallback *DcapLibCallbackRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DcapLibCallback.Contract.DcapLibCallbackCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DcapLibCallback *DcapLibCallbackRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DcapLibCallback.Contract.DcapLibCallbackTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DcapLibCallback *DcapLibCallbackRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DcapLibCallback.Contract.DcapLibCallbackTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DcapLibCallback *DcapLibCallbackCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DcapLibCallback.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DcapLibCallback *DcapLibCallbackTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DcapLibCallback.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DcapLibCallback *DcapLibCallbackTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DcapLibCallback.Contract.contract.Transact(opts, method, params...)
}
