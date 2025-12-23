package zkdcap

import (
	"encoding/binary"
	"time"

	_ "embed"
)

const BONSAI_IMAGE_ID = "d6c3b4b08fa163dd44f89125f97223f6f7163e3f0f62e360d707adab8f6b7799"

//go:embed elf/bonsai_dcap_guest.elf
var BONSAI_DCAP_GUEST_ELF []byte

func BonsaiGenerateInput(quote []byte, collateral *Collateral) []byte {
	currentTime := uint64(time.Now().Unix())

	var currentTimeBytes [8]byte
	binary.LittleEndian.PutUint64(currentTimeBytes[:], currentTime)

	collaterals := collateral.Encode()

	quoteLen := uint32(len(quote))
	collateralsLen := uint32(len(collaterals))

	totalLen := 8 + 4 + 4 + quoteLen + collateralsLen

	data := make([]byte, 0, totalLen)

	data = append(data, currentTimeBytes[:]...)

	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], quoteLen)
	data = append(data, lenBuf[:]...)
	binary.LittleEndian.PutUint32(lenBuf[:], collateralsLen)
	data = append(data, lenBuf[:]...)

	data = append(data, quote...)
	data = append(data, collaterals...)

	return data
}
