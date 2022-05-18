// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"runtime"
	"github.com/iswallet/go-ethereum/core/types"
	"math/big"

	"github.com/iswallet/go-ethereum/common"
)

// EVMLogger is used to collect execution traces from an EVM transaction
// execution. CaptureState is called for each step of the VM with the
// current VM state.
// Note that reference types are actual VM data structures; make copies
// if you need to retain them beyond the current call.
type EVMLogger interface {
	// Transaction level
	CaptureTxStart(gasLimit uint64)
	CaptureTxEnd(restGas uint64)
	// Top call frame
	CaptureStart(env *EVM, from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int)
	CaptureEnd(output []byte, gasUsed uint64, err error)
	// Rest of call frames
	CaptureEnter(typ OpCode, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int)
	CaptureExit(output []byte, gasUsed uint64, err error)
	// Opcode level
	CaptureState(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	CaptureStateAfter(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, rData []byte, depth int, err error)
	CaptureFault(pc uint64, op OpCode, gas, cost uint64, scope *ScopeContext, depth int, err error)
}

var (
	formatPool = sync.Pool{
		New: func() interface{} {
			return make([]types.StructLogRes, 0, 128)
		},
	}
)

// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []logger.StructLog) []types.StructLogRes {
	formatted := formatPool.Get().([]types.StructLogRes)
	runtime.SetFinalizer(&formatted, func(format *[]types.StructLogRes) {
		for _, res := range *format {
			res.ExtraData = nil
			res.Storage = nil
			res.Stack = res.Stack[:0]
			res.Memory = res.Memory[:0]
		}
		formatPool.Put(*format)
	})
	for index, trace := range logs {
		formatted = append(formatted, types.StructLogRes{
			Pc:            trace.Pc,
			Op:            trace.Op.String(),
			Gas:           trace.Gas,
			GasCost:       trace.GasCost,
			Depth:         trace.Depth,
			RefundCounter: trace.RefundCounter,
			Error:         trace.ErrorString(),
		})
		if len(trace.Stack) != 0 {
			if formatted[index].Stack == nil {
				formatted[index].Stack = make([]string, 0, len(trace.Stack))
			}
			for _, stackValue := range trace.Stack {
				formatted[index].Stack = append(formatted[index].Stack, stackValue.Hex())
			}
		}
		if trace.Memory.Len() != 0 {
			if formatted[index].Memory == nil {
				formatted[index].Memory = make([]string, 0, (trace.Memory.Len()+31)/32)
			}
			for i := 0; i+32 <= trace.Memory.Len(); i += 32 {
				formatted[index].Memory = append(formatted[index].Memory, common.Bytes2Hex(trace.Memory.Bytes()[i:i+32]))
			}
		}
		if len(trace.Storage) != 0 {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[i.Hex()] = storageValue.Hex()
			}
			formatted[index].Storage = storage
		}
		if trace.ExtraData != nil {
			formatted[index].ExtraData = trace.ExtraData.SealExtraData()
		}
	}
	return formatted
}
