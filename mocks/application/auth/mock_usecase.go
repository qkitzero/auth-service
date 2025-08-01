// Code generated by MockGen. DO NOT EDIT.
// Source: internal/application/auth/usecase.go
//
// Generated by this command:
//
//	mockgen -source=internal/application/auth/usecase.go -destination=mocks/application/auth/mock_usecase.go -package=mocks
//

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	token "github.com/qkitzero/auth-service/internal/domain/token"
	user "github.com/qkitzero/auth-service/internal/domain/user"
	gomock "go.uber.org/mock/gomock"
)

// MockAuthUsecase is a mock of AuthUsecase interface.
type MockAuthUsecase struct {
	ctrl     *gomock.Controller
	recorder *MockAuthUsecaseMockRecorder
	isgomock struct{}
}

// MockAuthUsecaseMockRecorder is the mock recorder for MockAuthUsecase.
type MockAuthUsecaseMockRecorder struct {
	mock *MockAuthUsecase
}

// NewMockAuthUsecase creates a new mock instance.
func NewMockAuthUsecase(ctrl *gomock.Controller) *MockAuthUsecase {
	mock := &MockAuthUsecase{ctrl: ctrl}
	mock.recorder = &MockAuthUsecaseMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAuthUsecase) EXPECT() *MockAuthUsecaseMockRecorder {
	return m.recorder
}

// ExchangeCode mocks base method.
func (m *MockAuthUsecase) ExchangeCode(code, redirectURI string) (token.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExchangeCode", code, redirectURI)
	ret0, _ := ret[0].(token.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ExchangeCode indicates an expected call of ExchangeCode.
func (mr *MockAuthUsecaseMockRecorder) ExchangeCode(code, redirectURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExchangeCode", reflect.TypeOf((*MockAuthUsecase)(nil).ExchangeCode), code, redirectURI)
}

// Login mocks base method.
func (m *MockAuthUsecase) Login(redirectURI string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Login", redirectURI)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Login indicates an expected call of Login.
func (mr *MockAuthUsecaseMockRecorder) Login(redirectURI any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Login", reflect.TypeOf((*MockAuthUsecase)(nil).Login), redirectURI)
}

// Logout mocks base method.
func (m *MockAuthUsecase) Logout(returnTo string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Logout", returnTo)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Logout indicates an expected call of Logout.
func (mr *MockAuthUsecaseMockRecorder) Logout(returnTo any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Logout", reflect.TypeOf((*MockAuthUsecase)(nil).Logout), returnTo)
}

// RefreshToken mocks base method.
func (m *MockAuthUsecase) RefreshToken(refreshToken string) (token.Token, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RefreshToken", refreshToken)
	ret0, _ := ret[0].(token.Token)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RefreshToken indicates an expected call of RefreshToken.
func (mr *MockAuthUsecaseMockRecorder) RefreshToken(refreshToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RefreshToken", reflect.TypeOf((*MockAuthUsecase)(nil).RefreshToken), refreshToken)
}

// RevokeToken mocks base method.
func (m *MockAuthUsecase) RevokeToken(refreshToken string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RevokeToken", refreshToken)
	ret0, _ := ret[0].(error)
	return ret0
}

// RevokeToken indicates an expected call of RevokeToken.
func (mr *MockAuthUsecaseMockRecorder) RevokeToken(refreshToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RevokeToken", reflect.TypeOf((*MockAuthUsecase)(nil).RevokeToken), refreshToken)
}

// VerifyToken mocks base method.
func (m *MockAuthUsecase) VerifyToken(accessToken string) (user.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VerifyToken", accessToken)
	ret0, _ := ret[0].(user.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyToken indicates an expected call of VerifyToken.
func (mr *MockAuthUsecaseMockRecorder) VerifyToken(accessToken any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyToken", reflect.TypeOf((*MockAuthUsecase)(nil).VerifyToken), accessToken)
}
