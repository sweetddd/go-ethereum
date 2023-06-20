package trace

import (
	"encoding/json"
	"github.com/iswallet/go-ethereum/common"
	"github.com/iswallet/go-ethereum/core/types"
	"github.com/iswallet/go-ethereum/eth/tracers/logger"
)

// BlockTrace contains block execution traces and results required for rollers.
type BlockTrace struct {
	ChainID          uint64                    `json:"chainID"`
	Version          string                    `json:"version"`
	Coinbase         *types.AccountWrapper     `json:"coinbase"`
	Header           *types.Header             `json:"header"`
	Transactions     []*types.TransactionData  `json:"transactions"`
	StorageTrace     *types.StorageTrace       `json:"storageTrace"`
	ExecutionResults []*logger.ExecutionResult `json:"executionResults"`
	MPTWitness       *json.RawMessage          `json:"mptwitness,omitempty"`
	WithdrawTrieRoot common.Hash               `json:"withdraw_trie_root,omitempty"`
}
