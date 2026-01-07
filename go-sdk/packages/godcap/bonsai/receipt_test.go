package bonsai

import (
	"encoding/hex"
	"testing"

	_ "embed"

	"github.com/chzyer/logex"
)

//go:embed test_receipt_1.hex
var testReceipt1 string

//go:embed test_receipt_2.hex
var testReceipt2 string

func TestReceipt(t *testing.T) {
	{
		data, err := hex.DecodeString(testReceipt1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewReceiptFromBincode(data); err != nil {
			logex.Error(err)
			t.Fatal(err)
		}
	}
	{
		data, err := hex.DecodeString(testReceipt2)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewReceiptFromBincode(data); err != nil {
			logex.Error(err)
			t.Fatal(err)
		}
	}
}
