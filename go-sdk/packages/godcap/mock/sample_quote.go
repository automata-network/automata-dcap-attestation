package mock

import (
	"bufio"
	_ "embed"
	"encoding/hex"
	"strings"
)

//go:embed sample_quotes.hex
var sampleQuotes string

var Quotes = func() [][]byte {
	quotes := make([][]byte, 0)
	r := bufio.NewReader(strings.NewReader(sampleQuotes))
	for {
		quoteLine, _ := r.ReadString('\n')
		if len(quoteLine) == 0 {
			break
		}
		quote, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(quoteLine, "0x")))
		if err != nil {
			panic(err)
		}
		if len(quote) == 0 {
			continue
		}
		quotes = append(quotes, quote)
	}
	return quotes
}()
