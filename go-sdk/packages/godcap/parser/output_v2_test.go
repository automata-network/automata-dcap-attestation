package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPublicAtaOutputV2Fixtures(t *testing.T) {
	for _, name := range []string{"ata-sgx-v3", "ata-tdx-v4"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile("../../../../evm/forge-test/assets/v2/fixtures/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var fixture struct {
				Quote                 string `json:"quote"`
				QuoteSHA256           string `json:"quoteSha256"`
				QuoteVersion          uint16 `json:"quoteVersion"`
				Timestamp             uint64 `json:"verificationTimestamp"`
				ExpectedJournal       string `json:"expectedJournal"`
				ExpectedJournalSHA256 string `json:"expectedJournalSha256"`
			}
			if err := json.Unmarshal(raw, &fixture); err != nil {
				t.Fatal(err)
			}
			decode := func(s string) []byte {
				t.Helper()
				if !strings.HasPrefix(s, "0x") {
					t.Fatal("missing hex prefix")
				}
				b, err := hex.DecodeString(s[2:])
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			quote, journal := decode(fixture.Quote), decode(fixture.ExpectedJournal)
			quoteHash, journalHash := sha256.Sum256(quote), sha256.Sum256(journal)
			if hex.EncodeToString(quoteHash[:]) != fixture.QuoteSHA256 || hex.EncodeToString(journalHash[:]) != fixture.ExpectedJournalSHA256 {
				t.Fatal("fixture digest mismatch")
			}
			out, err := ParseOutputV2(journal)
			if err != nil {
				t.Fatal(err)
			}
			if out.QuoteVersion != fixture.QuoteVersion || out.Timestamp != fixture.Timestamp || out.FullQuoteHash != quoteHash || !out.PIIDPresent {
				t.Fatal("incorrect journal fields")
			}
			encoded, err := out.MarshalBinary()
			if err != nil || !bytes.Equal(encoded, journal) {
				t.Fatalf("journal roundtrip: %v", err)
			}
			for _, size := range []int{0, 4, 48, 65, 288, len(journal) - 1} {
				if _, err := ParseOutputV2(journal[:size]); err == nil {
					t.Fatalf("accepted truncation %d", size)
				}
			}
			for offset, value := range map[int]byte{4: 0, 48: 2} {
				bad := append([]byte(nil), journal...)
				bad[offset] = value
				if _, err := ParseOutputV2(bad); err == nil {
					t.Fatalf("accepted malformed field %d", offset)
				}
			}
			if _, err := ParseOutputV2(append(append([]byte(nil), journal...), 0)); err == nil {
				t.Fatal("accepted trailing journal byte")
			}
		})
	}
}

func vectorV2(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../../evm/forge-test/assets/v2/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	data, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func TestOutputV2SharedVectors(t *testing.T) {
	for _, name := range []string{"sgx-empty", "tdx10-advisories", "tdx15-relaunch"} {
		data := vectorV2(t, name)
		out, err := ParseOutputV2(data)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := out.MarshalBinary()
		if err != nil || !bytes.Equal(data, encoded) {
			t.Fatalf("roundtrip %s: %v", name, err)
		}
		if out.Timestamp != 0x0102030405060708 || out.PPID != [16]byte{} {
			t.Fatal("incorrect header offsets")
		}
		for size := 0; size < 289+len(out.QuoteBody); size++ {
			if _, err := ParseOutputV2(data[:size]); err == nil {
				t.Fatalf("accepted truncation %d", size)
			}
		}
	}
}
func TestOutputV2RejectsMutations(t *testing.T) {
	data := vectorV2(t, "sgx-empty")
	for offset, value := range map[int]byte{0: 1, 3: 2, 4: 0, 9: 10, 48: 2, 32: 1, 49: 0, 51: 0, 53: 1, 56: 1} {
		bad := append([]byte(nil), data...)
		bad[offset] = value
		if _, err := ParseOutputV2(bad); err == nil {
			t.Fatalf("accepted mutation %d", offset)
		}
	}
	if _, err := ParseOutputV2(append(data, 0)); err == nil {
		t.Fatal("accepted trailing byte")
	}
}
func FuzzOutputV2Parser(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 289))
	f.Fuzz(func(t *testing.T, data []byte) {
		out, err := ParseOutputV2(data)
		if err == nil {
			b, err := out.MarshalBinary()
			if err != nil || !bytes.Equal(data, b) {
				t.Fatal("noncanonical parse")
			}
		}
	})
}
