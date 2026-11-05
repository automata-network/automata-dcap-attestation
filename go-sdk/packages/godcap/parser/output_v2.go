package parser

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
	"unicode/utf8"
)

const OutputV2HeaderLength = 317

// OutputV2 is wire schema 2.1, not Intel quote version 2.1.
// Journal bytes are identical to the FeeV2 return value; no legacy prefix/trailer is used.
type OutputV2 struct {
	FormatMajorVersion uint16
	FormatMinorVersion uint16
	QuoteVersion       uint16
	QuoteBodyType      uint16
	TCBStatus          uint8
	FMSPC              [6]byte
	PPID               [16]byte
	PIID               [16]byte
	PIIDPresent        bool
	Timestamp          uint64
	CollateralHashes   [6][32]byte
	FullQuoteHash      [32]byte // Keccak-256 of the exact complete input quote.
	QuoteBodyHash      [32]byte // Keccak-256 of the exact report body supplied by the application.
	AdvisoryIDs        []string
}

// ValidateQuoteBody binds a supplied body to an already authenticated output.
// Decoding an untrusted output followed by this check is not verification.
func (o *OutputV2) ValidateQuoteBody(body []byte) error {
	if o == nil {
		return fmt.Errorf("nil OutputV2")
	}
	length, err := v2BodyLength(o.QuoteVersion, o.QuoteBodyType)
	if err != nil {
		return err
	}
	if len(body) != length || !bytes.Equal(crypto.Keccak256(body), o.QuoteBodyHash[:]) {
		return fmt.Errorf("quote body does not match authenticated length/hash")
	}
	return nil
}

func v2BodyLength(version, body uint16) (int, error) {
	if version < 3 || version > 5 || body < 1 || body > 3 || version == 3 && body != 1 || version == 4 && body == 3 {
		return 0, fmt.Errorf("invalid V2 quote/body version %d/%d", version, body)
	}
	return []int{0, 384, 584, 648}[body], nil
}

func advisoryV2ABI() (abi.Arguments, error) {
	t, err := abi.NewType("string[]", "", nil)
	return abi.Arguments{{Type: t}}, err
}

// MarshalBinary returns the one canonical byte representation. Empty advisories have no payload.
func (o *OutputV2) MarshalBinary() ([]byte, error) {
	if o == nil {
		return nil, fmt.Errorf("nil OutputV2")
	}
	_, err := v2BodyLength(o.QuoteVersion, o.QuoteBodyType)
	if err != nil {
		return nil, err
	}
	if o.FormatMajorVersion != 2 || o.FormatMinorVersion != 1 || o.TCBStatus > 9 || !o.PIIDPresent && o.PIID != [16]byte{} {
		return nil, fmt.Errorf("invalid OutputV2 fields")
	}
	var advisory []byte
	if len(o.AdvisoryIDs) > 0 {
		for _, id := range o.AdvisoryIDs {
			if !utf8.ValidString(id) {
				return nil, fmt.Errorf("invalid advisory UTF-8")
			}
		}
		args, err := advisoryV2ABI()
		if err != nil {
			return nil, err
		}
		advisory, err = args.Pack(o.AdvisoryIDs)
		if err != nil {
			return nil, err
		}
	}
	if OutputV2HeaderLength+len(advisory) > 65535 {
		return nil, fmt.Errorf("OutputV2 exceeds uint16 length")
	}
	data := make([]byte, OutputV2HeaderLength+len(advisory))
	binary.BigEndian.PutUint16(data[0:2], 2)
	binary.BigEndian.PutUint16(data[2:4], 1)
	data[4] = 6
	binary.BigEndian.PutUint16(data[5:7], o.QuoteVersion)
	binary.BigEndian.PutUint16(data[7:9], o.QuoteBodyType)
	data[9] = o.TCBStatus
	copy(data[10:16], o.FMSPC[:])
	copy(data[16:32], o.PPID[:])
	copy(data[32:48], o.PIID[:])
	if o.PIIDPresent {
		data[48] = 1
	}
	if len(advisory) > 0 {
		binary.BigEndian.PutUint16(data[49:51], uint16(OutputV2HeaderLength))
		binary.BigEndian.PutUint16(data[51:53], uint16(len(advisory)))
	}
	binary.BigEndian.PutUint64(data[53:61], o.Timestamp)
	for i := range o.CollateralHashes {
		copy(data[61+i*32:93+i*32], o.CollateralHashes[i][:])
	}
	copy(data[253:285], o.FullQuoteHash[:])
	copy(data[285:317], o.QuoteBodyHash[:])
	copy(data[317:], advisory)
	return data, nil
}

// ParseOutputV2 rejects unknown versions, gaps/overlaps, noncanonical ABI, and trailing bytes.
func ParseOutputV2(data []byte) (*OutputV2, error) {
	if len(data) < OutputV2HeaderLength || len(data) > 65535 {
		return nil, fmt.Errorf("invalid OutputV2 length")
	}
	u16 := func(i int) uint16 { return binary.BigEndian.Uint16(data[i : i+2]) }
	if u16(0) != 2 || u16(2) != 1 || data[4] != 6 || data[9] > 9 || data[48] > 1 {
		return nil, fmt.Errorf("invalid OutputV2 header")
	}
	_, err := v2BodyLength(u16(5), u16(7))
	if err != nil {
		return nil, err
	}
	bodyEnd := OutputV2HeaderLength
	o := &OutputV2{FormatMajorVersion: 2, FormatMinorVersion: 1, QuoteVersion: u16(5), QuoteBodyType: u16(7), TCBStatus: data[9], PIIDPresent: data[48] == 1, Timestamp: binary.BigEndian.Uint64(data[53:61])}
	copy(o.FMSPC[:], data[10:16])
	copy(o.PPID[:], data[16:32])
	copy(o.PIID[:], data[32:48])
	copy(o.FullQuoteHash[:], data[253:285])
	copy(o.QuoteBodyHash[:], data[285:317])
	for i := range o.CollateralHashes {
		copy(o.CollateralHashes[i][:], data[61+i*32:93+i*32])
	}
	offset, advisoryLength := int(u16(49)), int(u16(51))
	if advisoryLength == 0 {
		if offset != 0 || len(data) != bodyEnd {
			return nil, fmt.Errorf("noncanonical empty advisory payload")
		}
	} else {
		if offset != bodyEnd || offset+advisoryLength != len(data) {
			return nil, fmt.Errorf("invalid advisory offsets")
		}
		args, err := advisoryV2ABI()
		if err != nil {
			return nil, err
		}
		decoded, err := args.Unpack(data[bodyEnd:])
		if err != nil {
			return nil, err
		}
		ids, ok := decoded[0].([]string)
		if !ok || len(ids) == 0 {
			return nil, fmt.Errorf("noncanonical advisory array")
		}
		o.AdvisoryIDs = ids
	}
	canonical, err := o.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(canonical, data) {
		return nil, fmt.Errorf("noncanonical OutputV2 encoding")
	}
	return o, nil
}
