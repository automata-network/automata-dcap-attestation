package zkdcap

import (
	_ "embed"
	"encoding/binary"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// How to calculate the vkhash
//
// ```rust
//
//	let private_key = env::var("NETWORK_PRIVATE_KEY").unwrap();
//	let rpc_url = "https://rpc.production.succinct.xyz";
//	let client = NetworkProver::new(&private_key, rpc_url);
//	let hash = client.register_program(&vk, DCAP_ELF).await;
//	println!("{:?}", hash);
//
// ```
var SP1_PROGRAM_VKHASH = common.HexToHash("0x0036efd519bb371b29a40322e40031833716e9441c6907f8aefc5e52ceebc9a6")

func Sp1GenerateInput(quote []byte, collateral *Collateral) []byte {
	collateralBytes := collateral.Encode()
	currentTime := uint64(time.Now().Unix())
	totalLen := 8 + 4 + 4 + len(quote) + len(collateralBytes)
	data := make([]byte, 0, totalLen)

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], currentTime)
	data = append(data, buf[:]...)

	binary.LittleEndian.PutUint32(buf[:4], uint32(len(quote)))
	data = append(data, buf[:4]...)

	binary.LittleEndian.PutUint32(buf[:4], uint32(len(collateralBytes)))
	data = append(data, buf[:4]...)

	data = append(data, quote...)

	data = append(data, collateralBytes...)
	return data
}
