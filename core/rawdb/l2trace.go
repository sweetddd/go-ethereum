package rawdb

import (
	"github.com/iswallet/go-ethereum/common"
	"github.com/iswallet/go-ethereum/core/types"
	"github.com/iswallet/go-ethereum/ethdb"
	"github.com/iswallet/go-ethereum/log"
	"github.com/iswallet/go-ethereum/rlp"
)

// ReadBlockResult retrieves all data required by roller.
func ReadBlockResult(db ethdb.Reader, hash common.Hash) *types.BlockResult {
	data, _ := db.Get(blockResultKey(hash))
	if len(data) == 0 {
		return nil
	}
	var blockResult types.BlockResult
	if err := rlp.DecodeBytes(data, &blockResult); err != nil {
		log.Error("Failed to decode BlockResult", "err", err)
		return nil
	}
	return &blockResult
}

// WriteBlockResult stores blockResult into leveldb.
func WriteBlockResult(db ethdb.KeyValueWriter, hash common.Hash, blockResult *types.BlockResult) {
	bytes, err := rlp.EncodeToBytes(blockResult)
	if err != nil {
		log.Crit("Failed to RLP encode BlockResult", "err", err)
	}
	db.Put(blockResultKey(hash), bytes)
}

// DeleteBlockResult removes blockResult with a block hash.
func DeleteBlockResult(db ethdb.KeyValueWriter, hash common.Hash) {
	if err := db.Delete(blockResultKey(hash)); err != nil {
		log.Crit("Failed to delete BlockResult", "err", err)
	}
}
