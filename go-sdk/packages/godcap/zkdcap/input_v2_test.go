package zkdcap

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/parser"
	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/pccs"
	"github.com/ethereum/go-ethereum/common"
)

func TestV2InputMatchesFrozenABI(t *testing.T) {
	for _, name := range []string{"ata-sgx-v3", "ata-tdx-v4", "v5"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../../../evm/forge-test/assets/v2/fixtures", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var f struct {
				Quote, GuestInput, RootCaCrl, PckCrl, TcbSigningCertificate, RootCaCertificate string
				TcbInfoJson, QeIdentityJson                                                    string
				VerificationTimestamp                                                          uint64
			}
			if err = json.Unmarshal(data, &f); err != nil {
				t.Fatal(err)
			}
			c := &Collateral{RootCa: common.FromHex(f.RootCaCertificate), TcbSigningCa: common.FromHex(f.TcbSigningCertificate),
				RootCaCrl: common.FromHex(f.RootCaCrl), PckProcessorCrl: common.FromHex(f.PckCrl), PckPlatformCrl: common.FromHex(f.PckCrl),
				TcbInfo: &pccs.TcbInfo{}, QeIdentity: &pccs.EnclaveIdentityInfo{}}
			if err = json.Unmarshal([]byte(f.TcbInfoJson), c.TcbInfo); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal([]byte(f.QeIdentityJson), c.QeIdentity); err != nil {
				t.Fatal(err)
			}
			quote := common.FromHex(f.Quote)
			input, err := GenerateInputV2(quote, c, f.VerificationTimestamp)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(input, common.FromHex(f.GuestInput)) {
				t.Fatal("Go V2 input differs from frozen Rust ABI input")
			}
			for _, bad := range [][]byte{nil, quote[:8], quote[:len(quote)-1], append(append([]byte(nil), quote...), 0)} {
				if _, err = GenerateInputV2(bad, c, f.VerificationTimestamp); err == nil {
					t.Fatal("malformed/padded quote accepted")
				}
			}
			q, err := parser.NewQuoteParserSafe(quote)
			if err != nil {
				t.Fatal(err)
			}
			certStart, err := q.CertDataOffset()
			if err != nil {
				t.Fatal(err)
			}
			prefix := 576
			if binary.LittleEndian.Uint16(quote[:2]) != parser.V3_QUOTE {
				prefix = 582
			}
			authStart := q.Spec().AuthDataSizeOffset() - prefix
			lengthOffsets := []int{authStart - 4, certStart - 4}
			if prefix == 582 {
				lengthOffsets = append(lengthOffsets, authStart+130)
			}
			for _, offset := range lengthOffsets {
				for _, value := range []uint32{0, ^uint32(0), binary.LittleEndian.Uint32(quote[offset:offset+4]) - 1} {
					bad := append([]byte(nil), quote...)
					binary.LittleEndian.PutUint32(bad[offset:offset+4], value)
					if _, err = GenerateInputV2(bad, c, f.VerificationTimestamp); err == nil {
						t.Fatalf("inconsistent nested length accepted: offset=%d value=%d", offset, value)
					}
				}
			}
			if _, err = GenerateInputV2(quote, nil, f.VerificationTimestamp); err == nil {
				t.Fatal("nil collateral accepted")
			}
			original := c.TcbInfo
			for _, bad := range []*pccs.TcbInfo{nil, {TcbInfo: json.RawMessage(`{"version":2}`)}, {TcbInfo: json.RawMessage(`invalid`)}} {
				c.TcbInfo = bad
				if _, err = GenerateInputV2(quote, c, f.VerificationTimestamp); err == nil {
					t.Fatal("invalid TCB info accepted")
				}
			}
			c.TcbInfo = original
			for _, required := range []*[]byte{&c.RootCa, &c.TcbSigningCa, &c.RootCaCrl, &c.PckPlatformCrl} {
				saved := *required
				*required = nil
				if _, err = GenerateInputV2(quote, c, f.VerificationTimestamp); err == nil {
					t.Fatal("missing required V2 certificate/CRL accepted")
				}
				*required = saved
			}
			c.QeIdentity = nil
			if _, err = GenerateInputV2(quote, c, f.VerificationTimestamp); err == nil {
				t.Fatal("nil QE identity accepted")
			}
		})
	}
}

func FuzzGenerateInputV2NoPanic(f *testing.F) {
	var collateral Collateral
	var timestamp uint64
	for i, name := range []string{"ata-sgx-v3", "ata-tdx-v4", "v5"} {
		data, err := os.ReadFile(filepath.Join("../../../../evm/forge-test/assets/v2/fixtures", name+".json"))
		if err != nil {
			f.Fatal(err)
		}
		var fixture struct {
			Quote, RootCaCrl, PckCrl, TcbSigningCertificate, RootCaCertificate string
			TcbInfoJson, QeIdentityJson                                        string
			VerificationTimestamp                                              uint64
		}
		if err = json.Unmarshal(data, &fixture); err != nil {
			f.Fatal(err)
		}
		f.Add(common.FromHex(fixture.Quote))
		if i == 0 {
			timestamp = fixture.VerificationTimestamp
			collateral = Collateral{RootCa: common.FromHex(fixture.RootCaCertificate), TcbSigningCa: common.FromHex(fixture.TcbSigningCertificate),
				RootCaCrl: common.FromHex(fixture.RootCaCrl), PckPlatformCrl: common.FromHex(fixture.PckCrl), PckProcessorCrl: common.FromHex(fixture.PckCrl),
				TcbInfo: &pccs.TcbInfo{}, QeIdentity: &pccs.EnclaveIdentityInfo{}}
			if err = json.Unmarshal([]byte(fixture.TcbInfoJson), collateral.TcbInfo); err != nil {
				f.Fatal(err)
			}
			if err = json.Unmarshal([]byte(fixture.QeIdentityJson), collateral.QeIdentity); err != nil {
				f.Fatal(err)
			}
		}
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, quote []byte) {
		// Bounded harness input size, not a newly introduced SDK length policy.
		if len(quote) > 128*1024 {
			return
		}
		// Encoding is not attestation verification: errors are expected and a
		// successful encoding does not claim the seed collateral matches a quote.
		_, _ = GenerateInputV2(quote, &collateral, timestamp)
	})
}
