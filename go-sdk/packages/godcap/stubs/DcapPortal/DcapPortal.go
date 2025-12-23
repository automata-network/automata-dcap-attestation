// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package DcapPortal

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

// IDcapPortalCallback is an auto generated low-level Go binding around an user-defined struct.
type IDcapPortalCallback struct {
	Value  *big.Int
	To     common.Address
	Params []byte
}

// DcapPortalMetaData contains all meta data concerning the DcapPortal contract.
var DcapPortalMetaData = &bind.MetaData{
	ABI: "[{\"type\":\"function\",\"name\":\"UPGRADE_INTERFACE_VERSION\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"string\",\"internalType\":\"string\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"estimateBaseFeeVerifyAndAttestWithZKProof\",\"inputs\":[{\"name\":\"output\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"zkCoprocessor\",\"type\":\"uint8\",\"internalType\":\"enumIDcapAttestation.ZkCoProcessorType\"},{\"name\":\"proofBytes\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"estimateBaseFeeVerifyOnChain\",\"inputs\":[{\"name\":\"rawQuote\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[{\"name\":\"\",\"type\":\"uint256\",\"internalType\":\"uint256\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"initialize\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"_Attestationaddress\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"owner\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"address\",\"internalType\":\"address\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"proxiableUUID\",\"inputs\":[],\"outputs\":[{\"name\":\"\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}],\"stateMutability\":\"view\"},{\"type\":\"function\",\"name\":\"renounceOwnership\",\"inputs\":[],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"transferOwnership\",\"inputs\":[{\"name\":\"newOwner\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"updateAttestationAddress\",\"inputs\":[{\"name\":\"_newAttestationAddress\",\"type\":\"address\",\"internalType\":\"address\"}],\"outputs\":[],\"stateMutability\":\"nonpayable\"},{\"type\":\"function\",\"name\":\"upgradeToAndCall\",\"inputs\":[{\"name\":\"newImplementation\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"data\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"outputs\":[],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"verifyAndAttestOnChain\",\"inputs\":[{\"name\":\"rawQuote\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callback\",\"type\":\"tuple\",\"internalType\":\"structIDcapPortal.Callback\",\"components\":[{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"params\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"verifiedOutput\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callbackOutput\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"payable\"},{\"type\":\"function\",\"name\":\"verifyAndAttestWithZKProof\",\"inputs\":[{\"name\":\"output\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"zkCoprocessor\",\"type\":\"uint8\",\"internalType\":\"enumIDcapAttestation.ZkCoProcessorType\"},{\"name\":\"proofBytes\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callback\",\"type\":\"tuple\",\"internalType\":\"structIDcapPortal.Callback\",\"components\":[{\"name\":\"value\",\"type\":\"uint256\",\"internalType\":\"uint256\"},{\"name\":\"to\",\"type\":\"address\",\"internalType\":\"address\"},{\"name\":\"params\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}],\"outputs\":[{\"name\":\"verifiedOutput\",\"type\":\"bytes\",\"internalType\":\"bytes\"},{\"name\":\"callbackOutput\",\"type\":\"bytes\",\"internalType\":\"bytes\"}],\"stateMutability\":\"payable\"},{\"type\":\"event\",\"name\":\"Initialized\",\"inputs\":[{\"name\":\"version\",\"type\":\"uint64\",\"indexed\":false,\"internalType\":\"uint64\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"OwnershipTransferred\",\"inputs\":[{\"name\":\"previousOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"},{\"name\":\"newOwner\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"event\",\"name\":\"Upgraded\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"indexed\":true,\"internalType\":\"address\"}],\"anonymous\":false},{\"type\":\"error\",\"name\":\"AddressEmptyCode\",\"inputs\":[{\"name\":\"target\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"CALLBACK_FAILED\",\"inputs\":[{\"name\":\"callbackOutput\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]},{\"type\":\"error\",\"name\":\"ERC1967InvalidImplementation\",\"inputs\":[{\"name\":\"implementation\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"ERC1967NonPayable\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"FailedCall\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"INSUFFICIENT_FEE\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"InvalidInitialization\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"NotInitializing\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"OwnableInvalidOwner\",\"inputs\":[{\"name\":\"owner\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"OwnableUnauthorizedAccount\",\"inputs\":[{\"name\":\"account\",\"type\":\"address\",\"internalType\":\"address\"}]},{\"type\":\"error\",\"name\":\"REJECT_RECURSIVE_CALL\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnauthorizedCallContext\",\"inputs\":[]},{\"type\":\"error\",\"name\":\"UUPSUnsupportedProxiableUUID\",\"inputs\":[{\"name\":\"slot\",\"type\":\"bytes32\",\"internalType\":\"bytes32\"}]},{\"type\":\"error\",\"name\":\"VERIFICATION_FAILED\",\"inputs\":[{\"name\":\"output\",\"type\":\"bytes\",\"internalType\":\"bytes\"}]}]",
}

// DcapPortalABI is the input ABI used to generate the binding from.
// Deprecated: Use DcapPortalMetaData.ABI instead.
var DcapPortalABI = DcapPortalMetaData.ABI

// DcapPortal is an auto generated Go binding around an Ethereum contract.
type DcapPortal struct {
	DcapPortalCaller     // Read-only binding to the contract
	DcapPortalTransactor // Write-only binding to the contract
	DcapPortalFilterer   // Log filterer for contract events
}

// DcapPortalCaller is an auto generated read-only Go binding around an Ethereum contract.
type DcapPortalCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapPortalTransactor is an auto generated write-only Go binding around an Ethereum contract.
type DcapPortalTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapPortalFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type DcapPortalFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// DcapPortalSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type DcapPortalSession struct {
	Contract     *DcapPortal       // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// DcapPortalCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type DcapPortalCallerSession struct {
	Contract *DcapPortalCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts     // Call options to use throughout this session
}

// DcapPortalTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type DcapPortalTransactorSession struct {
	Contract     *DcapPortalTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts     // Transaction auth options to use throughout this session
}

// DcapPortalRaw is an auto generated low-level Go binding around an Ethereum contract.
type DcapPortalRaw struct {
	Contract *DcapPortal // Generic contract binding to access the raw methods on
}

// DcapPortalCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type DcapPortalCallerRaw struct {
	Contract *DcapPortalCaller // Generic read-only contract binding to access the raw methods on
}

// DcapPortalTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type DcapPortalTransactorRaw struct {
	Contract *DcapPortalTransactor // Generic write-only contract binding to access the raw methods on
}

// NewDcapPortal creates a new instance of DcapPortal, bound to a specific deployed contract.
func NewDcapPortal(address common.Address, backend bind.ContractBackend) (*DcapPortal, error) {
	contract, err := bindDcapPortal(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &DcapPortal{DcapPortalCaller: DcapPortalCaller{contract: contract}, DcapPortalTransactor: DcapPortalTransactor{contract: contract}, DcapPortalFilterer: DcapPortalFilterer{contract: contract}}, nil
}

// NewDcapPortalCaller creates a new read-only instance of DcapPortal, bound to a specific deployed contract.
func NewDcapPortalCaller(address common.Address, caller bind.ContractCaller) (*DcapPortalCaller, error) {
	contract, err := bindDcapPortal(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &DcapPortalCaller{contract: contract}, nil
}

// NewDcapPortalTransactor creates a new write-only instance of DcapPortal, bound to a specific deployed contract.
func NewDcapPortalTransactor(address common.Address, transactor bind.ContractTransactor) (*DcapPortalTransactor, error) {
	contract, err := bindDcapPortal(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &DcapPortalTransactor{contract: contract}, nil
}

// NewDcapPortalFilterer creates a new log filterer instance of DcapPortal, bound to a specific deployed contract.
func NewDcapPortalFilterer(address common.Address, filterer bind.ContractFilterer) (*DcapPortalFilterer, error) {
	contract, err := bindDcapPortal(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &DcapPortalFilterer{contract: contract}, nil
}

// bindDcapPortal binds a generic wrapper to an already deployed contract.
func bindDcapPortal(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := DcapPortalMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DcapPortal *DcapPortalRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DcapPortal.Contract.DcapPortalCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DcapPortal *DcapPortalRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DcapPortal.Contract.DcapPortalTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DcapPortal *DcapPortalRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DcapPortal.Contract.DcapPortalTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_DcapPortal *DcapPortalCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _DcapPortal.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_DcapPortal *DcapPortalTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DcapPortal.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_DcapPortal *DcapPortalTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _DcapPortal.Contract.contract.Transact(opts, method, params...)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_DcapPortal *DcapPortalCaller) UPGRADEINTERFACEVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _DcapPortal.contract.Call(opts, &out, "UPGRADE_INTERFACE_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_DcapPortal *DcapPortalSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _DcapPortal.Contract.UPGRADEINTERFACEVERSION(&_DcapPortal.CallOpts)
}

// UPGRADEINTERFACEVERSION is a free data retrieval call binding the contract method 0xad3cb1cc.
//
// Solidity: function UPGRADE_INTERFACE_VERSION() view returns(string)
func (_DcapPortal *DcapPortalCallerSession) UPGRADEINTERFACEVERSION() (string, error) {
	return _DcapPortal.Contract.UPGRADEINTERFACEVERSION(&_DcapPortal.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DcapPortal *DcapPortalCaller) Owner(opts *bind.CallOpts) (common.Address, error) {
	var out []interface{}
	err := _DcapPortal.contract.Call(opts, &out, "owner")

	if err != nil {
		return *new(common.Address), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)

	return out0, err

}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DcapPortal *DcapPortalSession) Owner() (common.Address, error) {
	return _DcapPortal.Contract.Owner(&_DcapPortal.CallOpts)
}

// Owner is a free data retrieval call binding the contract method 0x8da5cb5b.
//
// Solidity: function owner() view returns(address)
func (_DcapPortal *DcapPortalCallerSession) Owner() (common.Address, error) {
	return _DcapPortal.Contract.Owner(&_DcapPortal.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_DcapPortal *DcapPortalCaller) ProxiableUUID(opts *bind.CallOpts) ([32]byte, error) {
	var out []interface{}
	err := _DcapPortal.contract.Call(opts, &out, "proxiableUUID")

	if err != nil {
		return *new([32]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([32]byte)).(*[32]byte)

	return out0, err

}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_DcapPortal *DcapPortalSession) ProxiableUUID() ([32]byte, error) {
	return _DcapPortal.Contract.ProxiableUUID(&_DcapPortal.CallOpts)
}

// ProxiableUUID is a free data retrieval call binding the contract method 0x52d1902d.
//
// Solidity: function proxiableUUID() view returns(bytes32)
func (_DcapPortal *DcapPortalCallerSession) ProxiableUUID() ([32]byte, error) {
	return _DcapPortal.Contract.ProxiableUUID(&_DcapPortal.CallOpts)
}

// EstimateBaseFeeVerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x86691dc5.
//
// Solidity: function estimateBaseFeeVerifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) payable returns(uint256)
func (_DcapPortal *DcapPortalTransactor) EstimateBaseFeeVerifyAndAttestWithZKProof(opts *bind.TransactOpts, output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "estimateBaseFeeVerifyAndAttestWithZKProof", output, zkCoprocessor, proofBytes)
}

// EstimateBaseFeeVerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x86691dc5.
//
// Solidity: function estimateBaseFeeVerifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) payable returns(uint256)
func (_DcapPortal *DcapPortalSession) EstimateBaseFeeVerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.EstimateBaseFeeVerifyAndAttestWithZKProof(&_DcapPortal.TransactOpts, output, zkCoprocessor, proofBytes)
}

// EstimateBaseFeeVerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x86691dc5.
//
// Solidity: function estimateBaseFeeVerifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes) payable returns(uint256)
func (_DcapPortal *DcapPortalTransactorSession) EstimateBaseFeeVerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, proofBytes []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.EstimateBaseFeeVerifyAndAttestWithZKProof(&_DcapPortal.TransactOpts, output, zkCoprocessor, proofBytes)
}

// EstimateBaseFeeVerifyOnChain is a paid mutator transaction binding the contract method 0x4fbb0005.
//
// Solidity: function estimateBaseFeeVerifyOnChain(bytes rawQuote) payable returns(uint256)
func (_DcapPortal *DcapPortalTransactor) EstimateBaseFeeVerifyOnChain(opts *bind.TransactOpts, rawQuote []byte) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "estimateBaseFeeVerifyOnChain", rawQuote)
}

// EstimateBaseFeeVerifyOnChain is a paid mutator transaction binding the contract method 0x4fbb0005.
//
// Solidity: function estimateBaseFeeVerifyOnChain(bytes rawQuote) payable returns(uint256)
func (_DcapPortal *DcapPortalSession) EstimateBaseFeeVerifyOnChain(rawQuote []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.EstimateBaseFeeVerifyOnChain(&_DcapPortal.TransactOpts, rawQuote)
}

// EstimateBaseFeeVerifyOnChain is a paid mutator transaction binding the contract method 0x4fbb0005.
//
// Solidity: function estimateBaseFeeVerifyOnChain(bytes rawQuote) payable returns(uint256)
func (_DcapPortal *DcapPortalTransactorSession) EstimateBaseFeeVerifyOnChain(rawQuote []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.EstimateBaseFeeVerifyOnChain(&_DcapPortal.TransactOpts, rawQuote)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address owner, address _Attestationaddress) returns()
func (_DcapPortal *DcapPortalTransactor) Initialize(opts *bind.TransactOpts, owner common.Address, _Attestationaddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "initialize", owner, _Attestationaddress)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address owner, address _Attestationaddress) returns()
func (_DcapPortal *DcapPortalSession) Initialize(owner common.Address, _Attestationaddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.Initialize(&_DcapPortal.TransactOpts, owner, _Attestationaddress)
}

// Initialize is a paid mutator transaction binding the contract method 0x485cc955.
//
// Solidity: function initialize(address owner, address _Attestationaddress) returns()
func (_DcapPortal *DcapPortalTransactorSession) Initialize(owner common.Address, _Attestationaddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.Initialize(&_DcapPortal.TransactOpts, owner, _Attestationaddress)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DcapPortal *DcapPortalTransactor) RenounceOwnership(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "renounceOwnership")
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DcapPortal *DcapPortalSession) RenounceOwnership() (*types.Transaction, error) {
	return _DcapPortal.Contract.RenounceOwnership(&_DcapPortal.TransactOpts)
}

// RenounceOwnership is a paid mutator transaction binding the contract method 0x715018a6.
//
// Solidity: function renounceOwnership() returns()
func (_DcapPortal *DcapPortalTransactorSession) RenounceOwnership() (*types.Transaction, error) {
	return _DcapPortal.Contract.RenounceOwnership(&_DcapPortal.TransactOpts)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DcapPortal *DcapPortalTransactor) TransferOwnership(opts *bind.TransactOpts, newOwner common.Address) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "transferOwnership", newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DcapPortal *DcapPortalSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.TransferOwnership(&_DcapPortal.TransactOpts, newOwner)
}

// TransferOwnership is a paid mutator transaction binding the contract method 0xf2fde38b.
//
// Solidity: function transferOwnership(address newOwner) returns()
func (_DcapPortal *DcapPortalTransactorSession) TransferOwnership(newOwner common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.TransferOwnership(&_DcapPortal.TransactOpts, newOwner)
}

// UpdateAttestationAddress is a paid mutator transaction binding the contract method 0xb183c21f.
//
// Solidity: function updateAttestationAddress(address _newAttestationAddress) returns()
func (_DcapPortal *DcapPortalTransactor) UpdateAttestationAddress(opts *bind.TransactOpts, _newAttestationAddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "updateAttestationAddress", _newAttestationAddress)
}

// UpdateAttestationAddress is a paid mutator transaction binding the contract method 0xb183c21f.
//
// Solidity: function updateAttestationAddress(address _newAttestationAddress) returns()
func (_DcapPortal *DcapPortalSession) UpdateAttestationAddress(_newAttestationAddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.UpdateAttestationAddress(&_DcapPortal.TransactOpts, _newAttestationAddress)
}

// UpdateAttestationAddress is a paid mutator transaction binding the contract method 0xb183c21f.
//
// Solidity: function updateAttestationAddress(address _newAttestationAddress) returns()
func (_DcapPortal *DcapPortalTransactorSession) UpdateAttestationAddress(_newAttestationAddress common.Address) (*types.Transaction, error) {
	return _DcapPortal.Contract.UpdateAttestationAddress(&_DcapPortal.TransactOpts, _newAttestationAddress)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_DcapPortal *DcapPortalTransactor) UpgradeToAndCall(opts *bind.TransactOpts, newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "upgradeToAndCall", newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_DcapPortal *DcapPortalSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.UpgradeToAndCall(&_DcapPortal.TransactOpts, newImplementation, data)
}

// UpgradeToAndCall is a paid mutator transaction binding the contract method 0x4f1ef286.
//
// Solidity: function upgradeToAndCall(address newImplementation, bytes data) payable returns()
func (_DcapPortal *DcapPortalTransactorSession) UpgradeToAndCall(newImplementation common.Address, data []byte) (*types.Transaction, error) {
	return _DcapPortal.Contract.UpgradeToAndCall(&_DcapPortal.TransactOpts, newImplementation, data)
}

// VerifyAndAttestOnChain is a paid mutator transaction binding the contract method 0x52053faf.
//
// Solidity: function verifyAndAttestOnChain(bytes rawQuote, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalTransactor) VerifyAndAttestOnChain(opts *bind.TransactOpts, rawQuote []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "verifyAndAttestOnChain", rawQuote, callback)
}

// VerifyAndAttestOnChain is a paid mutator transaction binding the contract method 0x52053faf.
//
// Solidity: function verifyAndAttestOnChain(bytes rawQuote, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalSession) VerifyAndAttestOnChain(rawQuote []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.Contract.VerifyAndAttestOnChain(&_DcapPortal.TransactOpts, rawQuote, callback)
}

// VerifyAndAttestOnChain is a paid mutator transaction binding the contract method 0x52053faf.
//
// Solidity: function verifyAndAttestOnChain(bytes rawQuote, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalTransactorSession) VerifyAndAttestOnChain(rawQuote []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.Contract.VerifyAndAttestOnChain(&_DcapPortal.TransactOpts, rawQuote, callback)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x20b43de7.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalTransactor) VerifyAndAttestWithZKProof(opts *bind.TransactOpts, output []byte, zkCoprocessor uint8, proofBytes []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.contract.Transact(opts, "verifyAndAttestWithZKProof", output, zkCoprocessor, proofBytes, callback)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x20b43de7.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalSession) VerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, proofBytes []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.Contract.VerifyAndAttestWithZKProof(&_DcapPortal.TransactOpts, output, zkCoprocessor, proofBytes, callback)
}

// VerifyAndAttestWithZKProof is a paid mutator transaction binding the contract method 0x20b43de7.
//
// Solidity: function verifyAndAttestWithZKProof(bytes output, uint8 zkCoprocessor, bytes proofBytes, (uint256,address,bytes) callback) payable returns(bytes verifiedOutput, bytes callbackOutput)
func (_DcapPortal *DcapPortalTransactorSession) VerifyAndAttestWithZKProof(output []byte, zkCoprocessor uint8, proofBytes []byte, callback IDcapPortalCallback) (*types.Transaction, error) {
	return _DcapPortal.Contract.VerifyAndAttestWithZKProof(&_DcapPortal.TransactOpts, output, zkCoprocessor, proofBytes, callback)
}

// DcapPortalInitializedIterator is returned from FilterInitialized and is used to iterate over the raw logs and unpacked data for Initialized events raised by the DcapPortal contract.
type DcapPortalInitializedIterator struct {
	Event *DcapPortalInitialized // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DcapPortalInitializedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DcapPortalInitialized)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DcapPortalInitialized)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DcapPortalInitializedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DcapPortalInitializedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DcapPortalInitialized represents a Initialized event raised by the DcapPortal contract.
type DcapPortalInitialized struct {
	Version uint64
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterInitialized is a free log retrieval operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_DcapPortal *DcapPortalFilterer) FilterInitialized(opts *bind.FilterOpts) (*DcapPortalInitializedIterator, error) {

	logs, sub, err := _DcapPortal.contract.FilterLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return &DcapPortalInitializedIterator{contract: _DcapPortal.contract, event: "Initialized", logs: logs, sub: sub}, nil
}

// WatchInitialized is a free log subscription operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_DcapPortal *DcapPortalFilterer) WatchInitialized(opts *bind.WatchOpts, sink chan<- *DcapPortalInitialized) (event.Subscription, error) {

	logs, sub, err := _DcapPortal.contract.WatchLogs(opts, "Initialized")
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DcapPortalInitialized)
				if err := _DcapPortal.contract.UnpackLog(event, "Initialized", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseInitialized is a log parse operation binding the contract event 0xc7f505b2f371ae2175ee4913f4499e1f2633a7b5936321eed1cdaeb6115181d2.
//
// Solidity: event Initialized(uint64 version)
func (_DcapPortal *DcapPortalFilterer) ParseInitialized(log types.Log) (*DcapPortalInitialized, error) {
	event := new(DcapPortalInitialized)
	if err := _DcapPortal.contract.UnpackLog(event, "Initialized", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DcapPortalOwnershipTransferredIterator is returned from FilterOwnershipTransferred and is used to iterate over the raw logs and unpacked data for OwnershipTransferred events raised by the DcapPortal contract.
type DcapPortalOwnershipTransferredIterator struct {
	Event *DcapPortalOwnershipTransferred // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DcapPortalOwnershipTransferredIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DcapPortalOwnershipTransferred)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DcapPortalOwnershipTransferred)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DcapPortalOwnershipTransferredIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DcapPortalOwnershipTransferredIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DcapPortalOwnershipTransferred represents a OwnershipTransferred event raised by the DcapPortal contract.
type DcapPortalOwnershipTransferred struct {
	PreviousOwner common.Address
	NewOwner      common.Address
	Raw           types.Log // Blockchain specific contextual infos
}

// FilterOwnershipTransferred is a free log retrieval operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DcapPortal *DcapPortalFilterer) FilterOwnershipTransferred(opts *bind.FilterOpts, previousOwner []common.Address, newOwner []common.Address) (*DcapPortalOwnershipTransferredIterator, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _DcapPortal.contract.FilterLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return &DcapPortalOwnershipTransferredIterator{contract: _DcapPortal.contract, event: "OwnershipTransferred", logs: logs, sub: sub}, nil
}

// WatchOwnershipTransferred is a free log subscription operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DcapPortal *DcapPortalFilterer) WatchOwnershipTransferred(opts *bind.WatchOpts, sink chan<- *DcapPortalOwnershipTransferred, previousOwner []common.Address, newOwner []common.Address) (event.Subscription, error) {

	var previousOwnerRule []interface{}
	for _, previousOwnerItem := range previousOwner {
		previousOwnerRule = append(previousOwnerRule, previousOwnerItem)
	}
	var newOwnerRule []interface{}
	for _, newOwnerItem := range newOwner {
		newOwnerRule = append(newOwnerRule, newOwnerItem)
	}

	logs, sub, err := _DcapPortal.contract.WatchLogs(opts, "OwnershipTransferred", previousOwnerRule, newOwnerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DcapPortalOwnershipTransferred)
				if err := _DcapPortal.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseOwnershipTransferred is a log parse operation binding the contract event 0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0.
//
// Solidity: event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)
func (_DcapPortal *DcapPortalFilterer) ParseOwnershipTransferred(log types.Log) (*DcapPortalOwnershipTransferred, error) {
	event := new(DcapPortalOwnershipTransferred)
	if err := _DcapPortal.contract.UnpackLog(event, "OwnershipTransferred", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}

// DcapPortalUpgradedIterator is returned from FilterUpgraded and is used to iterate over the raw logs and unpacked data for Upgraded events raised by the DcapPortal contract.
type DcapPortalUpgradedIterator struct {
	Event *DcapPortalUpgraded // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log        // Log channel receiving the found contract events
	sub  ethereum.Subscription // Subscription for errors, completion and termination
	done bool                  // Whether the subscription completed delivering logs
	fail error                 // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *DcapPortalUpgradedIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(DcapPortalUpgraded)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(DcapPortalUpgraded)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *DcapPortalUpgradedIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *DcapPortalUpgradedIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// DcapPortalUpgraded represents a Upgraded event raised by the DcapPortal contract.
type DcapPortalUpgraded struct {
	Implementation common.Address
	Raw            types.Log // Blockchain specific contextual infos
}

// FilterUpgraded is a free log retrieval operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_DcapPortal *DcapPortalFilterer) FilterUpgraded(opts *bind.FilterOpts, implementation []common.Address) (*DcapPortalUpgradedIterator, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _DcapPortal.contract.FilterLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return &DcapPortalUpgradedIterator{contract: _DcapPortal.contract, event: "Upgraded", logs: logs, sub: sub}, nil
}

// WatchUpgraded is a free log subscription operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_DcapPortal *DcapPortalFilterer) WatchUpgraded(opts *bind.WatchOpts, sink chan<- *DcapPortalUpgraded, implementation []common.Address) (event.Subscription, error) {

	var implementationRule []interface{}
	for _, implementationItem := range implementation {
		implementationRule = append(implementationRule, implementationItem)
	}

	logs, sub, err := _DcapPortal.contract.WatchLogs(opts, "Upgraded", implementationRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(DcapPortalUpgraded)
				if err := _DcapPortal.contract.UnpackLog(event, "Upgraded", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ParseUpgraded is a log parse operation binding the contract event 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b.
//
// Solidity: event Upgraded(address indexed implementation)
func (_DcapPortal *DcapPortalFilterer) ParseUpgraded(log types.Log) (*DcapPortalUpgraded, error) {
	event := new(DcapPortalUpgraded)
	if err := _DcapPortal.contract.UnpackLog(event, "Upgraded", log); err != nil {
		return nil, err
	}
	event.Raw = log
	return event, nil
}
