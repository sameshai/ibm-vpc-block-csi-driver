// Code generated by counterfeiter. DO NOT EDIT.
package ibmcsidriverfakes

import (
	"io/fs"
	"sync"
)

type FakeSocketPermission struct {
	ChmodStub        func(string, fs.FileMode) error
	chmodMutex       sync.RWMutex
	chmodArgsForCall []struct {
		arg1 string
		arg2 fs.FileMode
	}
	chmodReturns struct {
		result1 error
	}
	chmodReturnsOnCall map[int]struct {
		result1 error
	}
	ChownStub        func(string, int, int) error
	chownMutex       sync.RWMutex
	chownArgsForCall []struct {
		arg1 string
		arg2 int
		arg3 int
	}
	chownReturns struct {
		result1 error
	}
	chownReturnsOnCall map[int]struct {
		result1 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *FakeSocketPermission) Chmod(arg1 string, arg2 fs.FileMode) error {
	fake.chmodMutex.Lock()
	ret, specificReturn := fake.chmodReturnsOnCall[len(fake.chmodArgsForCall)]
	fake.chmodArgsForCall = append(fake.chmodArgsForCall, struct {
		arg1 string
		arg2 fs.FileMode
	}{arg1, arg2})
	stub := fake.ChmodStub
	fakeReturns := fake.chmodReturns
	fake.recordInvocation("Chmod", []interface{}{arg1, arg2})
	fake.chmodMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeSocketPermission) ChmodCallCount() int {
	fake.chmodMutex.RLock()
	defer fake.chmodMutex.RUnlock()
	return len(fake.chmodArgsForCall)
}

func (fake *FakeSocketPermission) ChmodCalls(stub func(string, fs.FileMode) error) {
	fake.chmodMutex.Lock()
	defer fake.chmodMutex.Unlock()
	fake.ChmodStub = stub
}

func (fake *FakeSocketPermission) ChmodArgsForCall(i int) (string, fs.FileMode) {
	fake.chmodMutex.RLock()
	defer fake.chmodMutex.RUnlock()
	argsForCall := fake.chmodArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *FakeSocketPermission) ChmodReturns(result1 error) {
	fake.chmodMutex.Lock()
	defer fake.chmodMutex.Unlock()
	fake.ChmodStub = nil
	fake.chmodReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeSocketPermission) ChmodReturnsOnCall(i int, result1 error) {
	fake.chmodMutex.Lock()
	defer fake.chmodMutex.Unlock()
	fake.ChmodStub = nil
	if fake.chmodReturnsOnCall == nil {
		fake.chmodReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.chmodReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeSocketPermission) Chown(arg1 string, arg2 int, arg3 int) error {
	fake.chownMutex.Lock()
	ret, specificReturn := fake.chownReturnsOnCall[len(fake.chownArgsForCall)]
	fake.chownArgsForCall = append(fake.chownArgsForCall, struct {
		arg1 string
		arg2 int
		arg3 int
	}{arg1, arg2, arg3})
	stub := fake.ChownStub
	fakeReturns := fake.chownReturns
	fake.recordInvocation("Chown", []interface{}{arg1, arg2, arg3})
	fake.chownMutex.Unlock()
	if stub != nil {
		return stub(arg1, arg2, arg3)
	}
	if specificReturn {
		return ret.result1
	}
	return fakeReturns.result1
}

func (fake *FakeSocketPermission) ChownCallCount() int {
	fake.chownMutex.RLock()
	defer fake.chownMutex.RUnlock()
	return len(fake.chownArgsForCall)
}

func (fake *FakeSocketPermission) ChownCalls(stub func(string, int, int) error) {
	fake.chownMutex.Lock()
	defer fake.chownMutex.Unlock()
	fake.ChownStub = stub
}

func (fake *FakeSocketPermission) ChownArgsForCall(i int) (string, int, int) {
	fake.chownMutex.RLock()
	defer fake.chownMutex.RUnlock()
	argsForCall := fake.chownArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2, argsForCall.arg3
}

func (fake *FakeSocketPermission) ChownReturns(result1 error) {
	fake.chownMutex.Lock()
	defer fake.chownMutex.Unlock()
	fake.ChownStub = nil
	fake.chownReturns = struct {
		result1 error
	}{result1}
}

func (fake *FakeSocketPermission) ChownReturnsOnCall(i int, result1 error) {
	fake.chownMutex.Lock()
	defer fake.chownMutex.Unlock()
	fake.ChownStub = nil
	if fake.chownReturnsOnCall == nil {
		fake.chownReturnsOnCall = make(map[int]struct {
			result1 error
		})
	}
	fake.chownReturnsOnCall[i] = struct {
		result1 error
	}{result1}
}

func (fake *FakeSocketPermission) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.chmodMutex.RLock()
	defer fake.chmodMutex.RUnlock()
	fake.chownMutex.RLock()
	defer fake.chownMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *FakeSocketPermission) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}