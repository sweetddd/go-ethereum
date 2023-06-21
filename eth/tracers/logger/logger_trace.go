package logger

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
)

type traceFunc func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error

var (
	// OpcodeExecs the map to load opcodes' trace funcs.
	OpcodeExecs = map[vm.OpCode][]traceFunc{
		vm.CALL:         {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
		vm.CALLCODE:     {traceToAddressCode, traceLastNAddressCode(1), traceContractAccount, traceLastNAddressAccount(1)}, // contract account is the caller, stack.nth_last(1) is the callee's address
		vm.DELEGATECALL: {traceToAddressCode, traceLastNAddressCode(1)},
		vm.STATICCALL:   {traceToAddressCode, traceLastNAddressCode(1), traceLastNAddressAccount(1)},
		vm.CREATE:       {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
		vm.CREATE2:      {}, // caller is already recorded in ExtraData.Caller, callee is recorded in CaptureEnter&CaptureExit
		vm.SLOAD:        {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
		vm.SSTORE:       {}, // trace storage in `captureState` instead of here, to handle `l.cfg.DisableStorage` flag
		vm.SELFDESTRUCT: {traceContractAccount, traceLastNAddressAccount(0)},
		vm.SELFBALANCE:  {traceContractAccount},
		vm.BALANCE:      {traceLastNAddressAccount(0)},
		vm.EXTCODEHASH:  {traceLastNAddressAccount(0)},
		vm.CODESIZE:     {traceContractCode},
		vm.CODECOPY:     {traceContractCode},
		vm.EXTCODESIZE:  {traceLastNAddressCode(0)},
		vm.EXTCODECOPY:  {traceLastNAddressCode(0)},
	}
)

// traceToAddressCode gets tx.to address’s code
func traceToAddressCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if l.Env.To == nil {
		return nil
	}
	code := l.Env.StateDB.GetCode(*l.Env.To)
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	return nil
}

// traceLastNAddressCode
func traceLastNAddressCode(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}
		address := common.Address(stack.Datas[stack.Len()-1-n].Bytes20())
		code := l.Env.StateDB.GetCode(address)
		extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
		l.StatesAffected[address] = struct{}{}
		return nil
	}
}

// traceContractCode gets the contract's code
func traceContractCode(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	code := l.Env.StateDB.GetCode(scope.Contract.Address())
	extraData.CodeList = append(extraData.CodeList, hexutil.Encode(code))
	return nil
}

// TraceStorage get contract's storage at storage_address
func TraceStorage(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	if scope.Stack.Len() == 0 {
		return nil
	}
	key := common.Hash(scope.Stack.Peek().Bytes32())
	storage := getWrappedAccountForStorage(l, scope.Contract.Address(), key)
	extraData.StateList = append(extraData.StateList, storage)

	return nil
}

// traceContractAccount gets the contract's account
func traceContractAccount(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
	// Get account state.
	state := getWrappedAccountForAddr(l, scope.Contract.Address())
	extraData.StateList = append(extraData.StateList, state)
	l.StatesAffected[scope.Contract.Address()] = struct{}{}

	return nil
}

// traceLastNAddressAccount returns func about the last N's address account.
func traceLastNAddressAccount(n int) traceFunc {
	return func(l *StructLogger, scope *vm.ScopeContext, extraData *types.ExtraData) error {
		stack := scope.Stack
		if stack.Len() <= n {
			return nil
		}

		address := common.Address(stack.Datas[stack.Len()-1-n].Bytes20())
		state := getWrappedAccountForAddr(l, address)
		extraData.StateList = append(extraData.StateList, state)
		l.StatesAffected[scope.Contract.Address()] = struct{}{}

		return nil
	}
}

// StorageWrapper will be empty
func getWrappedAccountForAddr(l *StructLogger, address common.Address) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:          address,
		Nonce:            l.Env.StateDB.GetNonce(address),
		Balance:          (*hexutil.Big)(l.Env.StateDB.GetBalance(address)),
		KeccakCodeHash:   l.Env.StateDB.GetKeccakCodeHash(address),
		PoseidonCodeHash: l.Env.StateDB.GetPoseidonCodeHash(address),
		CodeSize:         l.Env.StateDB.GetCodeSize(address),
	}
}

func getWrappedAccountForStorage(l *StructLogger, address common.Address, key common.Hash) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:          address,
		Nonce:            l.Env.StateDB.GetNonce(address),
		Balance:          (*hexutil.Big)(l.Env.StateDB.GetBalance(address)),
		KeccakCodeHash:   l.Env.StateDB.GetKeccakCodeHash(address),
		PoseidonCodeHash: l.Env.StateDB.GetPoseidonCodeHash(address),
		CodeSize:         l.Env.StateDB.GetCodeSize(address),
		Storage: &types.StorageWrapper{
			Key:   key.String(),
			Value: l.Env.StateDB.GetState(address, key).String(),
		},
	}
}

func getCodeForAddr(l *StructLogger, address common.Address) []byte {
	return l.Env.StateDB.GetCode(address)
}
