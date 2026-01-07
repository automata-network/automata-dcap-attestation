// Code generated - DO NOT EDIT.
// This file is a minimal binding for ITcbEvalDao

package AutomataTcbEvalDao

import (
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// TcbId represents the TCB type enum
// 0 = SGX, 1 = TDX
type TcbId = uint8

const (
	TcbIdSGX TcbId = 0
	TcbIdTDX TcbId = 1
)

// AutomataTcbEvalDaoABI is the input ABI used to generate the binding
const AutomataTcbEvalDaoABI = "[{\"inputs\":[{\"internalType\":\"enum TcbId\",\"name\":\"id\",\"type\":\"uint8\"}],\"name\":\"standard\",\"outputs\":[{\"internalType\":\"uint32\",\"name\":\"tcbEvaluationNumber\",\"type\":\"uint32\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]"

// AutomataTcbEvalDao is an auto generated Go binding around an Ethereum contract.
type AutomataTcbEvalDao struct {
	AutomataTcbEvalDaoCaller     // Read-only binding to the contract
	AutomataTcbEvalDaoTransactor // Write-only binding to the contract
	AutomataTcbEvalDaoFilterer   // Log filterer for contract events
}

// AutomataTcbEvalDaoCaller is an auto generated read-only Go binding around an Ethereum contract.
type AutomataTcbEvalDaoCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataTcbEvalDaoTransactor is an auto generated write-only Go binding around an Ethereum contract.
type AutomataTcbEvalDaoTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataTcbEvalDaoFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type AutomataTcbEvalDaoFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// AutomataTcbEvalDaoSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type AutomataTcbEvalDaoSession struct {
	Contract     *AutomataTcbEvalDao // Generic contract binding to set the session for
	CallOpts     bind.CallOpts       // Call options to use throughout this session
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// AutomataTcbEvalDaoCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type AutomataTcbEvalDaoCallerSession struct {
	Contract *AutomataTcbEvalDaoCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts             // Call options to use throughout this session
}

// AutomataTcbEvalDaoTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type AutomataTcbEvalDaoTransactorSession struct {
	Contract     *AutomataTcbEvalDaoTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts             // Transaction auth options to use throughout this session
}

// AutomataTcbEvalDaoRaw is an auto generated low-level Go binding around an Ethereum contract.
type AutomataTcbEvalDaoRaw struct {
	Contract *AutomataTcbEvalDao // Generic contract binding to access the raw methods on
}

// AutomataTcbEvalDaoCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type AutomataTcbEvalDaoCallerRaw struct {
	Contract *AutomataTcbEvalDaoCaller // Generic read-only contract binding to access the raw methods on
}

// AutomataTcbEvalDaoTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type AutomataTcbEvalDaoTransactorRaw struct {
	Contract *AutomataTcbEvalDaoTransactor // Generic write-only contract binding to access the raw methods on
}

// NewAutomataTcbEvalDao creates a new instance of AutomataTcbEvalDao, bound to a specific deployed contract.
func NewAutomataTcbEvalDao(address common.Address, backend bind.ContractBackend) (*AutomataTcbEvalDao, error) {
	contract, err := bindAutomataTcbEvalDao(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &AutomataTcbEvalDao{AutomataTcbEvalDaoCaller: AutomataTcbEvalDaoCaller{contract: contract}, AutomataTcbEvalDaoTransactor: AutomataTcbEvalDaoTransactor{contract: contract}, AutomataTcbEvalDaoFilterer: AutomataTcbEvalDaoFilterer{contract: contract}}, nil
}

// NewAutomataTcbEvalDaoCaller creates a new read-only instance of AutomataTcbEvalDao, bound to a specific deployed contract.
func NewAutomataTcbEvalDaoCaller(address common.Address, caller bind.ContractCaller) (*AutomataTcbEvalDaoCaller, error) {
	contract, err := bindAutomataTcbEvalDao(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataTcbEvalDaoCaller{contract: contract}, nil
}

// NewAutomataTcbEvalDaoTransactor creates a new write-only instance of AutomataTcbEvalDao, bound to a specific deployed contract.
func NewAutomataTcbEvalDaoTransactor(address common.Address, transactor bind.ContractTransactor) (*AutomataTcbEvalDaoTransactor, error) {
	contract, err := bindAutomataTcbEvalDao(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &AutomataTcbEvalDaoTransactor{contract: contract}, nil
}

// NewAutomataTcbEvalDaoFilterer creates a new log filterer instance of AutomataTcbEvalDao, bound to a specific deployed contract.
func NewAutomataTcbEvalDaoFilterer(address common.Address, filterer bind.ContractFilterer) (*AutomataTcbEvalDaoFilterer, error) {
	contract, err := bindAutomataTcbEvalDao(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &AutomataTcbEvalDaoFilterer{contract: contract}, nil
}

// bindAutomataTcbEvalDao binds a generic wrapper to an already deployed contract.
func bindAutomataTcbEvalDao(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(AutomataTcbEvalDaoABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Standard is a free data retrieval call binding the contract method 0x3b2def5c.
//
// Solidity: function standard(uint8 id) view returns(uint32 tcbEvaluationNumber)
func (_AutomataTcbEvalDao *AutomataTcbEvalDaoCaller) Standard(opts *bind.CallOpts, id uint8) (uint32, error) {
	var out []interface{}
	err := _AutomataTcbEvalDao.contract.Call(opts, &out, "standard", id)
	if err != nil {
		return 0, err
	}
	return *abi.ConvertType(out[0], new(uint32)).(*uint32), nil
}

// Compile-time check to ensure unused imports don't cause errors
var (
	_ = big.NewInt
	_ = common.Address{}
	_ = types.BloomLookup
	_ = event.NewSubscription
)
