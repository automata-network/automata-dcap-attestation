package parser

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"

	"github.com/automata-network/automata-dcap-attestation/go-sdk/packages/godcap/mock"
)

func quoteFixtures(t *testing.T) [][]byte {
	t.Helper()
	v5, err := os.ReadFile("../../../../evm/forge-test/assets/quotes/alibaba_quote_5.dat")
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{mock.Quotes[0], mock.Quotes[1], v5}
}

func TestQuoteCertificatesAndTruncatedFraming(t *testing.T) {
	for _, quote := range quoteFixtures(t) {
		q, err := NewQuoteParser(quote)
		if err != nil {
			t.Fatal(err)
		}
		certs, err := q.Certificates()
		if err != nil || len(certs) != 3 {
			t.Fatalf("certificates: %d, %v", len(certs), err)
		}
		start, end, err := q.certDataBounds()
		if err != nil {
			t.Fatal(err)
		}
		if extracted, err := q.CertData(); err != nil || !bytes.Equal(extracted, quote[start:end]) {
			t.Fatal("wrong declared cert range")
		}
		for n := 0; n < end; n++ {
			if _, err := NewQuoteParserSafe(quote[:n]); err == nil {
				t.Fatalf("accepted truncated quote at %d", n)
			}
			// Direct access must also be safe without a successful constructor.
			if _, err := (&QuoteParser{quote: quote[:n]}).Certificates(); err == nil {
				t.Fatal("accepted malformed direct parser")
			}
		}
		withTail, err := NewQuoteParserSafe(append(bytes.Clone(quote), []byte("legacy tail")...))
		if err != nil {
			t.Fatal(err)
		}
		if certs, err := withTail.Certificates(); err != nil || len(certs) != 3 {
			t.Fatalf("tail compatibility: %v", err)
		}
	}
}

func TestQuoteNestedLengthMutationAfterConstruction(t *testing.T) {
	for _, original := range quoteFixtures(t) {
		quote := bytes.Clone(original)
		q, err := NewQuoteParserSafe(quote)
		if err != nil {
			t.Fatal(err)
		}
		start, _, _ := q.certDataBounds()
		binary.LittleEndian.PutUint32(quote[start-4:start], ^uint32(0))
		if _, err := q.Certificates(); err == nil {
			t.Fatal("oversize cert accepted")
		}
		copy(quote, original)
		offset := q.Spec().AuthDataSizeOffset()
		binary.LittleEndian.PutUint16(quote[offset:offset+2], ^uint16(0))
		if _, err := q.Certificates(); err == nil {
			t.Fatal("oversize QE auth accepted")
		}
		copy(quote, original)
		binary.LittleEndian.PutUint32(quote[start-4:start], 0)
		if _, err := q.Certificates(); err == nil {
			t.Fatal("empty certificate payload accepted")
		}
		copy(quote, original)
		quote[start] = '!'
		if _, err := q.Certificates(); err == nil {
			t.Fatal("malformed PEM accepted")
		}
	}
}

func TestV5RejectsBodySizeOverflowAndTypeMismatch(t *testing.T) {
	quote := bytes.Clone(quoteFixtures(t)[2])
	binary.LittleEndian.PutUint32(quote[50:54], ^uint32(0))
	if _, err := DetectQuoteSpecSafe(quote); err == nil {
		t.Fatal("huge body size accepted")
	}
	quote = bytes.Clone(quoteFixtures(t)[2])
	binary.LittleEndian.PutUint32(quote[4:8], SGX_TEE_TYPE)
	if _, err := DetectQuoteSpecSafe(quote); err == nil {
		t.Fatal("TEE/body mismatch accepted")
	}
}

func FuzzQuoteCertificateParser(f *testing.F) {
	f.Add([]byte{})
	for _, quote := range mock.Quotes {
		f.Add(quote)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		q, err := NewQuoteParserSafe(data)
		if err == nil {
			_, _ = q.Certificates()
		}
		_, _ = (&QuoteParser{quote: data}).Certificates()
	})
}
