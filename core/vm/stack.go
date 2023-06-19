// Copyright 2014 The go-ethereum Authors
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
	"sync"

	"github.com/holiman/uint256"
)

var stackPool = sync.Pool{
	New: func() interface{} {
		return &Stack{Datas: make([]uint256.Int, 0, 16)}
	},
}

// Stack is an object for basic stack operations. Items popped to the stack are
// expected to be changed and modified. stack does not take care of adding newly
// initialised objects.
type Stack struct {
	Datas []uint256.Int
}

func newstack() *Stack {
	return stackPool.Get().(*Stack)
}

func returnStack(s *Stack) {
	s.Datas = s.Datas[:0]
	stackPool.Put(s)
}

// data returns the underlying uint256.Int array.
func (st *Stack) Data() []uint256.Int {
	return st.Datas
}

func (st *Stack) push(d *uint256.Int) {
	// NOTE push limit (1024) is checked in baseCheck
	st.Datas = append(st.Datas, *d)
}

func (st *Stack) pop() (ret uint256.Int) {
	ret = st.Datas[len(st.Datas)-1]
	st.Datas = st.Datas[:len(st.Datas)-1]
	return
}

func (st *Stack) Len() int {
	return len(st.Datas)
}

func (st *Stack) swap(n int) {
	st.Datas[st.Len()-n], st.Datas[st.Len()-1] = st.Datas[st.Len()-1], st.Datas[st.Len()-n]
}

func (st *Stack) dup(n int) {
	st.push(&st.Datas[st.Len()-n])
}

func (st *Stack) Peek() *uint256.Int {
	return &st.Datas[st.Len()-1]
}

// Back returns the n'th item in stack
func (st *Stack) Back(n int) *uint256.Int {
	return &st.Datas[st.Len()-n-1]
}
