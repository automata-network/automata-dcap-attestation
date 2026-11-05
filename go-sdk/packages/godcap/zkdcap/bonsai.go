package zkdcap

import (
	"time"

	_ "embed"
)

const BONSAI_IMAGE_ID = "d6c3b4b08fa163dd44f89125f97223f6f7163e3f0f62e360d707adab8f6b7799"

//go:embed elf/bonsai_dcap_guest.elf
var BONSAI_DCAP_GUEST_ELF []byte

func BonsaiGenerateInput(quote []byte, collateral *Collateral) ([]byte, error) {
	return encodeGuestInput(quote, collateral, uint64(time.Now().Unix()))
}
