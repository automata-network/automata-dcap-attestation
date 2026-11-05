package bincode

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/chzyer/logex"
	"github.com/ethereum/go-ethereum/common"
)

var (
	ErrUnexpectEnum = logex.Define("unexpected enum[%T]: %v")
)

var led = binary.LittleEndian

func Unmarshal[T FromBin](data []byte) (T, error) {
	var item T
	item = item.New().(T)
	data, err := item.FromBin(data)
	if err != nil {
		return item, logex.Trace(err)
	}
	if len(data) > 0 {
		return item, logex.NewErrorf("fromBin not consume all bytes: %v", len(data))
	}
	return item, nil
}

func UnmarshalFields(data []byte, fields []FromBin) ([]byte, error) {
	var err error
	for i, field := range fields {
		data, err = field.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err, fmt.Sprintf("[%T]: %v", field, i))
		}
	}
	return data, nil
}

type FromBin interface {
	New() FromBin
	FromBin([]byte) ([]byte, error)
	String() string
}

type Collection[T FromBin] []T

func (c *Collection[T]) New() FromBin {
	return new(Collection[T])
}

func (c *Collection[T]) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("[")
	for i := 0; i < len(*c); i++ {
		buf.WriteString((*c)[i].String())
		if i != len(*c) {
			buf.WriteString(",")
		}
	}
	buf.WriteString("]")
	return buf.String()
}

func (c *Collection[T]) FromBin(data []byte) ([]byte, error) {
	length, data, err := ReadUint64(data)
	if err != nil {
		return nil, err
	}
	// Supported receipt elements all consume at least one byte. Never allocate
	// an attacker-declared count before checking the available encoded input.
	if length > uint64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	values := make(Collection[T], 0, min(int(length), 1024))
	for i := uint64(0); i < length; i++ {
		var val T
		val = val.New().(T)
		remaining := len(data)
		data, err = val.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		if len(data) >= remaining {
			return nil, logex.NewError("collection element must consume input")
		}
		values = append(values, val)
	}
	*c = values
	return data, nil
}

func ReadUint32(data []byte) (uint32, []byte, error) {
	return ReadEnum(data)
}

func ReadEnum(data []byte) (uint32, []byte, error) {
	if len(data) < 4 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	ty := led.Uint32(data[:4])
	return ty, data[4:], nil
}

func ReadUint64(data []byte) (uint64, []byte, error) {
	if len(data) < 8 {
		return 0, nil, io.ErrUnexpectedEOF
	}
	ty := led.Uint64(data[:8])
	return ty, data[8:], nil
}

type VarInt int

func (i *VarInt) FromBin(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	off := 1
	var value uint64
	switch data[0] {
	case 255:
		return nil, logex.NewError("unexpected 255")
	case 254:
		return nil, logex.NewError("unsupported u128")
	case 253:
		off = 9
	case 252:
		off = 5
	case 251:
		off = 3
	}
	if len(data) < off {
		return nil, io.ErrUnexpectedEOF
	}
	switch off {
	case 9:
		value = led.Uint64(data[1:9])
	case 5:
		value = uint64(led.Uint32(data[1:5]))
	case 3:
		value = uint64(led.Uint16(data[1:3]))
	default:
		value = uint64(data[0])
	}
	if value > uint64(^uint(0)>>1) {
		return nil, logex.NewError("varint overflows int")
	}
	*i = VarInt(value)
	return data[off:], nil
}

type Option[T FromBin] struct {
	Type uint8
	Val  *T
}

func (s *Option[T]) String() string {
	if s.Type == 1 {
		if s.Val == nil {
			return "nil"
		}
		return fmt.Sprintf("Some(%v)", (*s.Val).String())
	} else {
		return "None"
	}
}

func (s *Option[T]) New() FromBin {
	return new(Option[T])
}

func (o *Option[T]) FromBin(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	if data[0] > 1 {
		return nil, ErrUnexpectEnum.Format(o, data[0])
	}
	o.Type = data[0]
	o.Val = nil
	data = data[1:]
	if o.Type == 1 {
		var val T
		val = val.New().(T)
		var err error
		data, err = val.FromBin(data)
		if err != nil {
			return nil, logex.Trace(err)
		}
		o.Val = &val
	}
	return data, nil
}

type Bytes32 [32]byte

func (d *Bytes32) New() FromBin {
	return new(Bytes32)
}

func (d Bytes32) String() string {
	return fmt.Sprintf("Bytes32(%v)", common.Hash(d))
}

func (d *Bytes32) FromBin(data []byte) ([]byte, error) {
	if len(data) < 32 {
		return nil, io.ErrUnexpectedEOF
	}
	copy((*d)[:], data[:32])
	return data[32:], nil
}

type Bytes []byte

func (b *Bytes) New() FromBin {
	return new(Bytes)
}

func (b *Bytes) String() string {
	return fmt.Sprintf("%v", ([]byte)(*b))
}

func (b Bytes) Bincode() []byte {
	buf := make([]byte, 0, 8+len(b))
	buf = led.AppendUint64(buf, uint64(len(b)))
	buf = append(buf, []byte(b)...)
	return buf
}

func (b *Bytes) FromBin(data []byte) ([]byte, error) {
	length, data, err := ReadUint64(data)
	if err != nil {
		return nil, err
	}
	if length > uint64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	*b = make([]byte, int(length))
	copy(*b, data[:len(*b)])
	return data[len(*b):], nil
}

type String string

func (b *String) New() FromBin {
	return new(String)
}

func (b String) Len() int {
	return len(b)
}

func (b String) String() string {
	return fmt.Sprintf("%v", (string)(b))
}

func (b *String) FromBin(data []byte) ([]byte, error) {
	var bytes Bytes
	data, err := bytes.FromBin(data)
	if err != nil {
		return nil, logex.Trace(err)
	}
	*b = String(bytes)
	return data, nil
}

type U32 uint32

func (b *U32) New() FromBin {
	return new(U32)
}

func (b *U32) String() string {
	return fmt.Sprintf("%v", (uint32)(*b))
}

func (b *U32) Raw() uint32 {
	return uint32(*b)
}

func (b *U32) FromBin(data []byte) ([]byte, error) {
	val, data, err := ReadUint32(data)
	if err != nil {
		return nil, err
	}
	*b = U32(val)
	return data, nil
}

type U64 uint64

func (b *U64) New() FromBin {
	return new(U64)
}

func (b *U64) String() string {
	return fmt.Sprintf("%v", (uint64)(*b))
}

func (b *U64) FromBin(data []byte) ([]byte, error) {
	val, data, err := ReadUint64(data)
	if err != nil {
		return nil, err
	}
	*b = U64(val)
	return data, nil
}
