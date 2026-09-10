package bincode

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

type decoder interface{ FromBin([]byte) ([]byte, error) }

func TestDecoderRejectsMalformedInputs(t *testing.T) {
	maxLength := binary.LittleEndian.AppendUint64(nil, math.MaxUint64)
	tests := []struct {
		name  string
		value decoder
		data  []byte
	}{
		{"u32-short", new(U32), []byte{1, 2, 3}},
		{"u64-short", new(U64), make([]byte, 7)},
		{"digest-short", new(Bytes32), make([]byte, 31)},
		{"bytes-no-length", new(Bytes), nil},
		{"bytes-huge-length", new(Bytes), maxLength},
		{"collection-huge-count", new(Collection[*U32]), maxLength},
		{"collection-truncated-element", new(Collection[*U32]), append(binary.LittleEndian.AppendUint64(nil, 1), 0)},
		{"option-empty", new(Option[*U32]), nil},
		{"option-unknown", new(Option[*U32]), []byte{2}},
		{"option-truncated-value", new(Option[*U32]), []byte{1}},
		{"varint-empty", new(VarInt), nil},
		{"varint-u16-short", new(VarInt), []byte{251, 0}},
		{"varint-u32-short", new(VarInt), []byte{252, 0, 0, 0}},
		{"varint-u64-short", new(VarInt), []byte{253, 0}},
		{"varint-overflow", new(VarInt), append([]byte{253}, maxLength...)},
		{"varint-unsupported-u128", new(VarInt), []byte{254}},
		{"varint-invalid-tag", new(VarInt), []byte{255}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.value.FromBin(test.data); err == nil {
				t.Fatal("malformed encoding accepted")
			}
		})
	}
}

func TestDecoderPreservesValidValues(t *testing.T) {
	data := binary.LittleEndian.AppendUint64(nil, 2)
	data = append(data, Bytes("one").Bincode()...)
	data = append(data, Bytes("two").Bincode()...)
	values, err := Unmarshal[*Collection[*Bytes]](data)
	if err != nil || len(*values) != 2 || !bytes.Equal([]byte(*(*values)[0]), []byte("one")) {
		t.Fatalf("collection: %v, %v", values, err)
	}
	if _, err := Unmarshal[*Collection[*Bytes]](append(data, 0)); err == nil {
		t.Fatal("trailing bytes accepted")
	}
	var option Option[*U32]
	if _, err := option.FromBin([]byte{1, 7, 0, 0, 0}); err != nil || (*option.Val).Raw() != 7 {
		t.Fatalf("option: %v", err)
	}
	if _, err := option.FromBin([]byte{0}); err != nil || option.Val != nil {
		t.Fatal("None retained a previous Some value")
	}
	for _, encoded := range [][]byte{{7}, {251, 0, 1}, {252, 0, 0, 1, 0}, {253, 0, 0, 1, 0, 0, 0, 0, 0}} {
		var value VarInt
		if rest, err := value.FromBin(encoded); err != nil || len(rest) != 0 {
			t.Fatalf("valid varint: %x, %v", encoded, err)
		}
	}
}

func FuzzBinaryDecoders(f *testing.F) {
	for _, seed := range [][]byte{nil, {0}, {1}, {254}, {255}, bytes.Repeat([]byte{255}, 8), make([]byte, 32)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		values := []decoder{new(U32), new(U64), new(Bytes32), new(Bytes), new(String), new(VarInt),
			new(Option[*Bytes]), new(Collection[*Bytes]), new(Collection[*Collection[*U32]])}
		for _, value := range values {
			_, _ = value.FromBin(data)
		}
	})
}
