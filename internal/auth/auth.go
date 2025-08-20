package auth

import (
	"errors"
	"fmt"
	"io"
	"slices"
)

type AuthUser struct {
	username string
	password string
}

type AuthProvider struct {
	users                   []AuthUser
	authentication_type     byte
	authentication_response []byte
}

var (
	SOCKS_NO_AUTH_CODE     byte = 0
	SOCKS_NO_AUTH_RESPONSE      = []byte{
		0x05, 0x00,
	}
	SOCKS_CRED_AUTH_CODE     byte = 1
	SOCKS_CRED_AUTH_RESPONSE      = []byte{
		0x05, 0x02,
	}
	SOCKS_NO_ACCEPTABLE_AUTH_CODE     byte = 2
	SOCKS_NO_ACCEPTABLE_AUTH_RESPONSE      = []byte{
		0x00, 0xFF,
	}

	SOCKS_CRED_AUTH_SUCCESS_RESPONSE = []byte{
		0x05, 0x00,
	}
	SOCKS_CRED_AUTH_FAILURE_RESPONSE = []byte{
		0x05, 0x01,
	}
)

func (a *AuthProvider) ChooseAutenticationMethod(request []byte) (byte, []byte, error) {
	if slices.Contains(request[2:2+request[1]], a.authentication_type) {
		return a.authentication_type, a.authentication_response, nil
	}

	return SOCKS_NO_ACCEPTABLE_AUTH_CODE,
		SOCKS_NO_ACCEPTABLE_AUTH_RESPONSE,
		errors.New("Can't authenticate client: no acceptable method found.")
}

func (a *AuthProvider) UseAuthenticateMethod(w io.Writer, data []byte) error {
	switch a.authentication_type {
	case SOCKS_NO_AUTH_CODE:
		return a.AuthenticateNoAuth(w, data)
	case SOCKS_CRED_AUTH_CODE:
		return a.AuthenticateCredentials(w, data)
	default:
		return fmt.Errorf("Authentication method 0x%X is not supported.", a.authentication_type)
	}
}

func (a *AuthProvider) AuthenticateCredentials(w io.Writer, data []byte) error {
	username := string(data[2 : 2+data[1]])
	password := string(data[4 : 4+data[3]])

	if slices.Contains(a.users, AuthUser{username, password}) {
		w.Write(SOCKS_CRED_AUTH_SUCCESS_RESPONSE)
		return nil
	} else {
		w.Write(SOCKS_CRED_AUTH_FAILURE_RESPONSE)
		return fmt.Errorf("Can't authenticate user %q: credentials not found", username)
	}
}

func (a *AuthProvider) AuthenticateNoAuth(w io.Writer, data []byte) error {
	return nil
}
