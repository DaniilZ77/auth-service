// Code generated by mockery v2.53.3. DO NOT EDIT.

package service

import mock "github.com/stretchr/testify/mock"

// MockTokenHandler is an autogenerated mock type for the TokenHandler type
type MockTokenHandler struct {
	mock.Mock
}

type MockTokenHandler_Expecter struct {
	mock *mock.Mock
}

func (_m *MockTokenHandler) EXPECT() *MockTokenHandler_Expecter {
	return &MockTokenHandler_Expecter{mock: &_m.Mock}
}

// NewToken provides a mock function with given fields: userID, sessionID
func (_m *MockTokenHandler) NewToken(userID string, sessionID string) (string, error) {
	ret := _m.Called(userID, sessionID)

	if len(ret) == 0 {
		panic("no return value specified for NewToken")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string, string) (string, error)); ok {
		return rf(userID, sessionID)
	}
	if rf, ok := ret.Get(0).(func(string, string) string); ok {
		r0 = rf(userID, sessionID)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(userID, sessionID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockTokenHandler_NewToken_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NewToken'
type MockTokenHandler_NewToken_Call struct {
	*mock.Call
}

// NewToken is a helper method to define mock.On call
//   - userID string
//   - sessionID string
func (_e *MockTokenHandler_Expecter) NewToken(userID interface{}, sessionID interface{}) *MockTokenHandler_NewToken_Call {
	return &MockTokenHandler_NewToken_Call{Call: _e.mock.On("NewToken", userID, sessionID)}
}

func (_c *MockTokenHandler_NewToken_Call) Run(run func(userID string, sessionID string)) *MockTokenHandler_NewToken_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockTokenHandler_NewToken_Call) Return(token string, err error) *MockTokenHandler_NewToken_Call {
	_c.Call.Return(token, err)
	return _c
}

func (_c *MockTokenHandler_NewToken_Call) RunAndReturn(run func(string, string) (string, error)) *MockTokenHandler_NewToken_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockTokenHandler creates a new instance of MockTokenHandler. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockTokenHandler(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockTokenHandler {
	mock := &MockTokenHandler{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
