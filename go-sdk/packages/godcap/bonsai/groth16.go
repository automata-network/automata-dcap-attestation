package bonsai

func Groth16Encode(selector [4]byte, data []byte) []byte {
	out := make([]byte, 4+len(data))
	copy(out[:4], selector[:])
	copy(out[4:], data)
	return out
}
