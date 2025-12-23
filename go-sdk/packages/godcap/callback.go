package godcap

import (
	"math/big"
	"strings"

	gen "github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/DcapPortal"
	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

type Callback struct {
	raw gen.IDcapPortalCallback
	abi abi.ABI
	err error
}

func NewCallback(abi abi.ABI) *Callback {
	cb := &Callback{
		raw: gen.IDcapPortalCallback{},
		abi: abi,
	}

	return cb
}

func NewCallbackFromAbiJSON(json string) *Callback {
	abi, err := abi.JSON(strings.NewReader(json))
	cb := NewCallback(abi)
	if err != nil {
		cb.err = logex.Trace(err)
		return cb
	}
	return cb
}

func (c *Callback) Abi() (gen.IDcapPortalCallback, error) {
	if c == nil {
		return gen.IDcapPortalCallback{
			Value: new(big.Int),
		}, nil
	}
	if c.raw.Value == nil {
		c.raw.Value = new(big.Int)
	}
	return c.raw, c.err
}

func (c *Callback) WithParams(method string, args ...interface{}) *Callback {
	if c.err != nil {
		return c
	}
	params, err := c.abi.Pack(method, args...)
	if err != nil {
		c.err = logex.Trace(err)
		return c
	}
	c.raw.Params = params
	return c
}

func (c *Callback) WithTo(to common.Address) *Callback {
	c.raw.To = to
	return c
}

func (c *Callback) Value() *big.Int {
	if c == nil {
		return new(big.Int)
	}
	return new(big.Int).Set(c.raw.Value)
}

func (c *Callback) WithValue(value *big.Int) *Callback {
	c.raw.Value = value
	return c
}
