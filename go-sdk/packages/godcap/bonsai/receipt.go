package bonsai

import (
	"encoding/binary"
	"fmt"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/bincode"

	"github.com/chzyer/logex"
)

type Receipt struct {
	Inner    InnerReceipt
	Journal  Journal
	Metadata ReceiptMetadata
}

func (r *Receipt) FromBin(data []byte) ([]byte, error) {
	data, err := r.Inner.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.Journal.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.Metadata.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

func (r *Receipt) String() string {
	return fmt.Sprintf("Receipt{inner: %v, journal: %v, metadata: %v}", r.Inner.String(), r.Journal.String(), r.Metadata.String())
}

type InnerReceipt struct {
	Type uint32
	// type=0
	// skip

	// type=1 Succinct(SuccinctReceipt<ReceiptClaim>),
	Succinct *SuccinctReceipt[*ReceiptClaim]
	// type=2 Groth16(Groth16Receipt<ReceiptClaim>)
	Groth16 *Groth16Receipt[*ReceiptClaim]
}

func (r *InnerReceipt) String() string {
	switch r.Type {
	case 1:
		return fmt.Sprintf("InnerReceipt::Succinct(%v)", r.Succinct.String())
	case 2:
		return fmt.Sprintf("InnerReceipt::Groth16(%v)", r.Groth16.String())
	default:
		return "unknown"
	}
}

func (r *InnerReceipt) FromBin(data []byte) ([]byte, error) {
	var err error
	r.Type, data = bincode.ReadEnum(data)
	switch r.Type {
	case 1:
		var receipt SuccinctReceipt[*ReceiptClaim]
		data, err = receipt.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		r.Succinct = &receipt
	case 2:
		var groth16 Groth16Receipt[*ReceiptClaim]
		data, err = groth16.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		r.Groth16 = &groth16
	default:
		return nil, bincode.ErrUnexpectEnum.Format(r, r.Type)
	}

	return data, nil
}

type Groth16Receipt[Claim bincode.FromBin] struct {
	Seal               bincode.Bytes
	Claim              MaybePruned[Claim]
	VerifierParameters Digest
}

func (r *Groth16Receipt[Claim]) String() string {
	return fmt.Sprintf("Groth16Receipt{seal: %v, claim: %v, verifier_parameters: %v}", r.Seal.String(), r.Claim.String(), r.VerifierParameters.String())
}

func (r *Groth16Receipt[Claim]) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = r.Seal.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.Claim.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.VerifierParameters.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type SuccinctReceipt[Claim bincode.FromBin] struct {
	/// The cryptographic seal of this receipt. This seal is a STARK proving an execution of the
	/// recursion circuit.
	Seal bincode.Collection[*bincode.U32]

	/// The control ID of this receipt, identifying the recursion program that was run (e.g. lift,
	/// join, or resolve).
	ControlId Digest

	/// Claim containing information about the computation that this receipt proves.
	///
	/// The standard claim type is [ReceiptClaim][crate::ReceiptClaim], which represents a RISC-V
	/// zkVM execution.
	Claim MaybePruned[Claim]

	/// Name of the hash function used to create this receipt.
	Hashfn bincode.String

	/// A digest of the verifier parameters that can be used to verify this receipt.
	///
	/// Acts as a fingerprint to identify differing proof system or circuit versions between a
	/// prover and a verifier. It is not intended to contain the full verifier parameters, which must
	/// be provided by a trusted source (e.g. packaged with the verifier code).
	VerifierParameters Digest

	/// Merkle inclusion proof for control_id against the control root for this receipt.
	ControlInclusionProof MerkleProof
}

func (r *SuccinctReceipt[Claim]) String() string {
	return fmt.Sprintf("SuccinctReceipt{seal: %v, control_id: %v, claim: %v, hashfn: %v, verifier_parameters: %v, control_inclusion_proof: %v}", r.Seal.String(), r.ControlId.String(), r.Claim.String(), r.Hashfn.String(), r.VerifierParameters.String(), r.ControlInclusionProof.String())
}

func (r *SuccinctReceipt[Claim]) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = r.Seal.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.ControlId.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.Claim.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.Hashfn.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.VerifierParameters.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = r.ControlInclusionProof.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type MerkleProof struct {
	/// Index of the leaf for which inclusion is being proven.
	Index bincode.U32
	/// Sibling digests on the path from the root to the leaf.
	/// Does not include the root of the leaf.
	Digests bincode.Collection[*Digest]
}

func (m *MerkleProof) String() string {
	return fmt.Sprintf("MerkleProof{index: %v, digest: %v}", m.Index.String(), m.Digests.String())
}

func (m *MerkleProof) FromBin(data []byte) ([]byte, error) {
	data, err := m.Index.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = m.Digests.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type ReceiptClaim struct {
	/// The [SystemState] just before execution has begun.
	Pre MaybePruned[*SystemState]

	/// The [SystemState] just after execution has completed.
	Post MaybePruned[*SystemState]

	/// The exit code for the execution.
	ExitCode ExitCode

	/// Input to the guest.
	Input MaybePruned[*bincode.Option[*Input]]

	/// [Output] of the guest, including the journal and assumptions set during execution.
	Output MaybePruned[*bincode.Option[*Output]]
}

func (m *ReceiptClaim) New() bincode.FromBin {
	return new(ReceiptClaim)
}

func (m *ReceiptClaim) String() string {
	return fmt.Sprintf("ReceiptClaim{pre: %v, post: %v, exit_code: %v, input: %v, output: %v}", m.Pre.String(), m.Post.String(), m.ExitCode.String(), m.Input.String(), m.Output.String())
}

func (m *ReceiptClaim) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = m.Pre.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = m.Post.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = m.ExitCode.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = m.Input.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = m.Output.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type Input struct{}

func (i *Input) String() string {
	return "Input"
}

func (i *Input) New() bincode.FromBin {
	return new(Input)
}

func (i *Input) FromBin([]byte) ([]byte, error) {
	panic("reachable")
}

type Output struct {
	Journal     MaybePruned[*bincode.Bytes]
	Assumptions MaybePruned[*bincode.Collection[*MaybePruned[*Assumption]]]
}

func (o *Output) New() bincode.FromBin {
	return new(Output)
}

func (o *Output) String() string {
	return fmt.Sprintf("Output{journal: %v, assumptions: %v}", o.Journal.String(), o.Assumptions.String())
}

func (o *Output) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = o.Journal.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = o.Assumptions.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type Assumption struct {
	Claim       Digest
	ControlRoot Digest
}

func (a *Assumption) New() bincode.FromBin {
	return new(Assumption)
}

func (a *Assumption) String() string {
	return fmt.Sprintf("Assumption{claim: %v, ControlRoot: %v}", a.Claim.String(), a.ControlRoot.String())
}

func (a *Assumption) FromBin(data []byte) ([]byte, error) {
	var err error
	data, err = a.Claim.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	data, err = a.ControlRoot.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type SystemState struct {
	/// The program counter.
	Pc uint32

	/// The root hash of a merkle tree which confirms the
	/// integrity of the memory image.
	MerkleRoot Digest
}

func (s *SystemState) New() bincode.FromBin {
	return new(SystemState)
}

func (s *SystemState) String() string {
	return fmt.Sprintf("SystemState{pc: 0x%x, merkle_root: %v}", s.Pc, s.MerkleRoot.String())
}

func (s *SystemState) FromBin(data []byte) ([]byte, error) {
	s.Pc, data = bincode.ReadUint32(data)
	data, err := s.MerkleRoot.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	return data, nil
}

type MaybePruned[Claim bincode.FromBin] struct {
	Type uint32
	// type=0 Value(T)
	Value *Claim
	// type=1 Pruned(Digest)
	Pruned *Digest
}

func (m *MaybePruned[Claim]) New() bincode.FromBin {
	return new(MaybePruned[Claim])
}

func (m *MaybePruned[Claim]) String() string {
	if m == nil {
		return "nil"
	}
	if m.Type == 0 {
		if m.Value == nil {
			return "nil"
		}
		return fmt.Sprintf("MaybePruned::Value(%v)", (*m.Value).String())
	} else {
		return fmt.Sprintf("MaybePruned::Pruned(%v)", m.Pruned.String())
	}
}

func (m *MaybePruned[Claim]) FromBin(data []byte) ([]byte, error) {
	var err error
	m.Type, data = bincode.ReadEnum(data)
	switch m.Type {
	case 0:
		var value Claim
		value = value.New().(Claim)
		data, err = value.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		m.Value = &value
	case 1:
		var dig Digest
		data, err = dig.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		m.Pruned = &dig
	default:
		return nil, bincode.ErrUnexpectEnum.Format(m, m.Type)
	}
	return data, nil
}

type Journal struct {
	Bytes bincode.Bytes
}

func (j *Journal) String() string {
	return fmt.Sprintf("Journal{data: %v}", []byte(j.Bytes))
}

func (j *Journal) FromBin(data []byte) ([]byte, error) {
	return j.Bytes.FromBin(data)
}

type ReceiptMetadata struct {
	VerifierParameters Digest
}

func (m *ReceiptMetadata) String() string {
	return fmt.Sprintf("ReceiptMetadata{verifier_parameters: %v}", m.VerifierParameters.String())
}

func (m *ReceiptMetadata) FromBin(data []byte) ([]byte, error) {
	return m.VerifierParameters.FromBin(data)
}

var led = binary.LittleEndian

type Digest [8]uint32

func (d *Digest) New() bincode.FromBin {
	return new(Digest)
}

func (d *Digest) String() string {
	val := make([]byte, 0, 256)
	for i := 0; i < 8; i++ {
		val = led.AppendUint32(val, (*d)[i])
	}
	return fmt.Sprintf("Digest(%x)", val)
}

func (d *Digest) FromBin(data []byte) ([]byte, error) {
	for i := 0; i < 8; i++ {
		d[i] = led.Uint32(data[4*i : 4*(i+1)])
	}
	return data[4*8:], nil
}

type ExitCode struct {
	Type uint32
	// type=0 Halted(u32),
	Halted *uint32
	// type=1 Paused(u32),
	Paused *uint32
	// type=2 SystemSplit,
	SystemSplit *struct{}
	// type=3 SessionLimit,
	SessionLimit *struct{}
}

func (e *ExitCode) String() string {
	switch e.Type {
	case 0:
		if e.Halted == nil {
			return "nil"
		}
		return fmt.Sprintf("ExitCode::Halted(%v)", *e.Halted)
	case 1:
		if e.Paused == nil {
			return "nil"
		}
		return fmt.Sprintf("ExitCode::Paused(%v)", *e.Paused)
	case 2:
		return "ExitCode::SystemSplit"
	case 3:
		return "ExitCode::SessionLimit"
	default:
		return fmt.Sprintf("unknown")
	}
}

func (e *ExitCode) FromBin(data []byte) ([]byte, error) {
	e.Type, data = bincode.ReadEnum(data)
	switch e.Type {
	case 0:
		var val uint32
		val, data = bincode.ReadUint32(data)
		e.Halted = &val
	case 1:
		var val uint32
		val, data = bincode.ReadUint32(data)
		e.Paused = &val
	case 2:
		e.SystemSplit = &struct{}{}
	case 3:
		e.SessionLimit = &struct{}{}
	default:
		panic("unreachable")
	}
	return data, nil
}

func NewReceiptFromBincode(data []byte) (*Receipt, error) {
	var receipt Receipt
	rest, err := receipt.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	if len(rest) != 0 {
		return nil, logex.NewErrorf("rest: %v", rest)
	}
	return &receipt, nil
}
