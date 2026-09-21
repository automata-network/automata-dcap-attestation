package attestationv2

import (
	"github.com/ethereum/go-ethereum/common"
	"testing"
)

type forkNodeInfo struct {
	HardFork         string `json:"hardFork"`
	Network          string `json:"network"`
	CurrentBlockHash string `json:"currentBlockHash"`
	Environment      struct {
		ChainID uint64 `json:"chainId"`
	} `json:"environment"`
	ForkConfig struct {
		Block uint64 `json:"forkBlockNumber"`
	} `json:"forkConfig"`
}

type forkDeployment struct {
	Status    string         `json:"status"`
	RPC       string         `json:"rpc"`
	Owner     common.Address `json:"owner"`
	Origin    forkNodeInfo   `json:"origin"`
	Contracts map[string]struct {
		Address common.Address `json:"address"`
	} `json:"contracts"`
}

func requireReviewedFork(t *testing.T, origin, actual forkNodeInfo) {
	t.Helper()
	if !isReviewedFork(origin, actual) {
		t.Fatal("unreviewed/mismatched local fork origin or execution rules")
	}
}

func isReviewedFork(origin, actual forkNodeInfo) bool {
	valid := false
	switch origin.Environment.ChainID {
	case 11155111:
		valid = origin.ForkConfig.Block == 11689923 && origin.HardFork == "Osaka" && origin.CurrentBlockHash == "0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096" && (origin.Network == "" || origin.Network == "ethereum") && (actual.Network == "" || actual.Network == "ethereum")
	case 560048:
		valid = origin.ForkConfig.Block == 3666000 && origin.HardFork == "Osaka" && origin.CurrentBlockHash == "0x507bec8bb301dc25d57e09fee024cf8a099db7e8ee318c483591fed3b738a57f" && (origin.Network == "" || origin.Network == "ethereum") && (actual.Network == "" || actual.Network == "ethereum")
	case 11155420:
		valid = origin.ForkConfig.Block == 48718178 && origin.HardFork == "Karst" && origin.Network == "optimism" && actual.Network == "optimism" && origin.CurrentBlockHash == "0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c"
	}
	return valid && actual.Environment.ChainID == origin.Environment.ChainID && actual.ForkConfig.Block == origin.ForkConfig.Block && actual.HardFork == origin.HardFork
}

func TestReviewedForkOrigins(t *testing.T) {
	var eth forkNodeInfo
	eth.Environment.ChainID, eth.ForkConfig.Block, eth.HardFork = 11155111, 11689923, "Osaka"
	eth.CurrentBlockHash = "0x4ee0fcdc5b220406b457d0242cc280f0313ff1cc72bd5d9fdf041808881c8096"
	op := eth
	op.Environment.ChainID, op.ForkConfig.Block, op.HardFork, op.Network = 11155420, 48718178, "Karst", "optimism"
	op.CurrentBlockHash = "0x95b1d91f43a9f6209524114ef04d8d49ba47a82743460bce939fa10a97bbac8c"
	hoodi := eth
	hoodi.Environment.ChainID, hoodi.ForkConfig.Block, hoodi.HardFork = 560048, 3666000, "Osaka"
	hoodi.CurrentBlockHash = "0x507bec8bb301dc25d57e09fee024cf8a099db7e8ee318c483591fed3b738a57f"
	if !isReviewedFork(eth, eth) || !isReviewedFork(op, op) || !isReviewedFork(hoodi, hoodi) {
		t.Fatal("valid origin rejected")
	}
	wrongHoodi := hoodi
	wrongHoodi.HardFork = "Prague"
	if isReviewedFork(hoodi, wrongHoodi) {
		t.Fatal("Prague hardfork accepted for the reviewed Hoodi Osaka runtime")
	}
	wrong := op
	wrong.Network = "ethereum"
	if isReviewedFork(op, wrong) {
		t.Fatal("wrong execution engine accepted")
	}
	wrong = op
	wrong.HardFork = "Jovian"
	if isReviewedFork(op, wrong) {
		t.Fatal("old hardfork accepted")
	}
	wrong = eth
	wrong.Network = "optimism"
	if isReviewedFork(eth, wrong) || isReviewedFork(wrong, eth) {
		t.Fatal("Optimism runtime accepted for Ethereum")
	}
	wrong = eth
	wrong.ForkConfig.Block++
	if isReviewedFork(eth, wrong) {
		t.Fatal("wrong pin accepted")
	}
	wrong = eth
	wrong.CurrentBlockHash = "0x00"
	if isReviewedFork(wrong, eth) {
		t.Fatal("wrong origin hash accepted")
	}
	if isReviewedFork(eth, op) || isReviewedFork(forkNodeInfo{}, forkNodeInfo{}) {
		t.Fatal("wrong/empty chain accepted")
	}
}
