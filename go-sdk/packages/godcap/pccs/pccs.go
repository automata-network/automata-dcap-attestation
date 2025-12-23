package pccs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/registry"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/AutomataEnclaveIdentityDao"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/AutomataFmspcTcbDao"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/AutomataPcsDao"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/stubs/AutomataTcbEvalDao"
	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Constants for CA types
const (
	CA_ROOT uint8 = iota
	CA_PROCESSOR
	CA_PLATFORM
	CA_SIGNING
)

// Constants for Enclave ID types
const (
	ENCLAVE_ID_QE uint8 = iota
	ENCLAVE_ID_QVE
	ENCLAVE_ID_TDQE
)

// TcbId constants for TCB type
const (
	TCB_ID_SGX uint8 = 0
	TCB_ID_TDX uint8 = 1
)

// Client holds the Ethereum client and contract instances
type Client struct {
	client     *ethclient.Client
	network    *registry.Network
	pcs        *AutomataPcsDao.AutomataPcsDao
	tcbEvalDao *AutomataTcbEvalDao.AutomataTcbEvalDao

	// Versioned DAO instances - lazily initialized
	fmspcDaos     map[uint32]*AutomataFmspcTcbDao.AutomataFmspcTcbDao
	enclaveIdDaos map[uint32]*AutomataEnclaveIdentityDao.AutomataEnclaveIdentityDao
}

// NewClient initializes a new Client instance from a Network
func NewClient(client *ethclient.Client, network *registry.Network) (*Client, error) {
	// Initialize AutomataPcsDao contract
	pcs, err := AutomataPcsDao.NewAutomataPcsDao(network.Contracts.Pccs.PcsDao, client)
	if err != nil {
		return nil, logex.Trace(err, network.Contracts.Pccs.PcsDao)
	}

	// Initialize TcbEvalDao if available (v1.1 networks)
	var tcbEvalDao *AutomataTcbEvalDao.AutomataTcbEvalDao
	if network.Contracts.Pccs.TcbEvalDao != ([20]byte{}) {
		tcbEvalDao, err = AutomataTcbEvalDao.NewAutomataTcbEvalDao(network.Contracts.Pccs.TcbEvalDao, client)
		if err != nil {
			return nil, logex.Trace(err, network.Contracts.Pccs.TcbEvalDao)
		}
	}

	return &Client{
		client:        client,
		network:       network,
		pcs:           pcs,
		tcbEvalDao:    tcbEvalDao,
		fmspcDaos:     make(map[uint32]*AutomataFmspcTcbDao.AutomataFmspcTcbDao),
		enclaveIdDaos: make(map[uint32]*AutomataEnclaveIdentityDao.AutomataEnclaveIdentityDao),
	}, nil
}

// GetStandardTcbEvalNum queries the TcbEvalDao to get the standard TCB evaluation number
func (p *Client) GetStandardTcbEvalNum(ctx context.Context, tcbId uint8) (uint32, error) {
	if p.tcbEvalDao == nil {
		return 0, logex.NewError("TcbEvalDao not available (v1.0 network)")
	}
	return p.tcbEvalDao.Standard(&bind.CallOpts{Context: ctx}, tcbId)
}

// GetCurrentFmspcTcbDaoAddress returns the FmspcTcbDao address for the current standard TCB eval version
func (p *Client) GetCurrentFmspcTcbDaoAddress(ctx context.Context, tcbId uint8) ([20]byte, error) {
	evalNum, err := p.GetStandardTcbEvalNum(ctx, tcbId)
	if err != nil {
		return [20]byte{}, logex.Trace(err)
	}
	return p.network.GetFmspcTcbDaoAddress(evalNum)
}

// GetCurrentEnclaveIdDaoAddress returns the EnclaveIdDao address for the current standard TCB eval version
func (p *Client) GetCurrentEnclaveIdDaoAddress(ctx context.Context, tcbId uint8) ([20]byte, error) {
	evalNum, err := p.GetStandardTcbEvalNum(ctx, tcbId)
	if err != nil {
		return [20]byte{}, logex.Trace(err)
	}
	return p.network.GetEnclaveIdDaoAddress(evalNum)
}

// GetFmspcTcbDaoForVersion returns the FmspcTcbDao for a specific TCB eval version
func (p *Client) GetFmspcTcbDaoForVersion(tcbEvalNum uint32) (*AutomataFmspcTcbDao.AutomataFmspcTcbDao, error) {
	// Check cache
	if dao, ok := p.fmspcDaos[tcbEvalNum]; ok {
		return dao, nil
	}

	// Get address for this version
	addr, err := p.network.GetFmspcTcbDaoAddress(tcbEvalNum)
	if err != nil {
		return nil, logex.Trace(err)
	}

	// Create new instance
	dao, err := AutomataFmspcTcbDao.NewAutomataFmspcTcbDao(addr, p.client)
	if err != nil {
		return nil, logex.Trace(err)
	}

	// Cache it
	p.fmspcDaos[tcbEvalNum] = dao
	return dao, nil
}

// GetEnclaveIdDaoForVersion returns the EnclaveIdDao for a specific TCB eval version
func (p *Client) GetEnclaveIdDaoForVersion(tcbEvalNum uint32) (*AutomataEnclaveIdentityDao.AutomataEnclaveIdentityDao, error) {
	// Check cache
	if dao, ok := p.enclaveIdDaos[tcbEvalNum]; ok {
		return dao, nil
	}

	// Get address for this version
	addr, err := p.network.GetEnclaveIdDaoAddress(tcbEvalNum)
	if err != nil {
		return nil, logex.Trace(err)
	}

	// Create new instance
	dao, err := AutomataEnclaveIdentityDao.NewAutomataEnclaveIdentityDao(addr, p.client)
	if err != nil {
		return nil, logex.Trace(err)
	}

	// Cache it
	p.enclaveIdDaos[tcbEvalNum] = dao
	return dao, nil
}

// AvailableTcbEvalVersions returns all available TCB evaluation versions
func (p *Client) AvailableTcbEvalVersions() []uint32 {
	return p.network.Contracts.Pccs.EnclaveIdDao.AvailableVersions()
}

// Network returns the network configuration
func (p *Client) Network() *registry.Network {
	return p.network
}

// CertCrl holds certificate and CRL data
type CertCrl struct {
	Cert []byte
	Crl  []byte
}

// GetCertByID retrieves a certificate by its CA ID
func (p *Client) GetCertByID(ctx context.Context, ca uint8) (*CertCrl, error) {
	result, err := p.pcs.GetCertificateById(nil, ca)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return (*CertCrl)(&result), nil
}

// TcbInfo holds TCB information and its signature
type TcbInfo struct {
	TcbInfo   json.RawMessage `json:"tcbInfo"`
	Signature string          `json:"signature"`
}

// Encode serializes TcbInfo to JSON
func (t *TcbInfo) Encode() []byte {
	data, _ := json.Marshal(t)
	return data
}

// GetTcbInfo retrieves TCB information by type, FMSPC, and version (uses default DAO)
func (p *Client) GetTcbInfo(ctx context.Context, tcbType uint8, fmspc string, tcbVersion uint32) (*TcbInfo, error) {
	return p.GetTcbInfoWithEvalNum(ctx, tcbType, fmspc, tcbVersion, nil)
}

// GetTcbInfoWithEvalNum retrieves TCB information with a specific TCB eval number
func (p *Client) GetTcbInfoWithEvalNum(ctx context.Context, tcbType uint8, fmspc string, tcbVersion uint32, tcbEvalNum *uint32) (*TcbInfo, error) {
	var dao *AutomataFmspcTcbDao.AutomataFmspcTcbDao
	var err error
	var evalNum uint32

	if tcbEvalNum != nil {
		evalNum = *tcbEvalNum
	} else {
		// Query TcbEvalDao.standard() to get the current standard evaluation number
		// tcbType maps to tcbId: 0=SGX, 1=TDX
		evalNum, err = p.GetStandardTcbEvalNum(ctx, tcbType)
		if err != nil {
			return nil, logex.Trace(err, "failed to get standard tcb eval num")
		}
	}

	dao, err = p.GetFmspcTcbDaoForVersion(evalNum)
	if err != nil {
		return nil, logex.Trace(err)
	}

	result, err := dao.GetTcbInfo(&bind.CallOpts{Context: ctx}, big.NewInt(int64(tcbType)), fmspc, big.NewInt(int64(tcbVersion)))
	if err != nil {
		return nil, logex.Trace(err)
	}

	var info TcbInfo
	if err := json.Unmarshal([]byte(result.TcbInfoStr), &info.TcbInfo); err != nil {
		return nil, logex.Trace(err)
	}
	info.Signature = hex.EncodeToString(result.Signature)
	return &info, nil
}

// EnclaveIdentityInfo holds enclave identity information and its signature
type EnclaveIdentityInfo struct {
	Identity  json.RawMessage `json:"enclaveIdentity"`
	Signature string          `json:"signature"`
}

// Encode serializes EnclaveIdentityInfo to JSON
func (e *EnclaveIdentityInfo) Encode() []byte {
	data, _ := json.Marshal(e)
	return data
}

// GetEnclaveID retrieves enclave identity information by ID and version (uses default DAO)
func (p *Client) GetEnclaveID(ctx context.Context, enclaveId uint8, version uint32) (*EnclaveIdentityInfo, error) {
	return p.GetEnclaveIDWithEvalNum(ctx, enclaveId, version, nil)
}

// GetEnclaveIDWithEvalNum retrieves enclave identity with a specific TCB eval number
func (p *Client) GetEnclaveIDWithEvalNum(ctx context.Context, enclaveId uint8, version uint32, tcbEvalNum *uint32) (*EnclaveIdentityInfo, error) {
	var dao *AutomataEnclaveIdentityDao.AutomataEnclaveIdentityDao
	var err error
	var evalNum uint32

	if tcbEvalNum != nil {
		evalNum = *tcbEvalNum
	} else {
		// Derive tcbId from enclaveId: QE(0) and QVE(1) are SGX, TDQE(2) is TDX
		tcbId := TCB_ID_SGX
		if enclaveId == ENCLAVE_ID_TDQE {
			tcbId = TCB_ID_TDX
		}
		evalNum, err = p.GetStandardTcbEvalNum(ctx, tcbId)
		if err != nil {
			return nil, logex.Trace(err, "failed to get standard tcb eval num")
		}
	}

	dao, err = p.GetEnclaveIdDaoForVersion(evalNum)
	if err != nil {
		return nil, logex.Trace(err)
	}

	result, err := dao.GetEnclaveIdentity(&bind.CallOpts{Context: ctx}, big.NewInt(int64(enclaveId)), big.NewInt(int64(version)))
	if err != nil {
		return nil, logex.Trace(err)
	}

	var info EnclaveIdentityInfo
	if err := json.Unmarshal([]byte(result.IdentityStr), &info.Identity); err != nil {
		return nil, logex.Trace(err)
	}
	info.Signature = hex.EncodeToString(result.Signature)
	return &info, nil
}

