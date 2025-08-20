package auth

import (
	"fmt"
	"io"
	"log"
	"slices"
)

type AuthUser struct {
	username string
	password string
}

func NewAuthUser(username string, password string) AuthUser {
	return AuthUser{
		username: username,
		password: password,
	}
}

type AuthProvider struct {
	users                   []AuthUser
	authentication_type     byte
	authentication_response []byte
}

func NewAuthProvider(auth_users []AuthUser, authentication_type byte, authentication_response []byte) AuthProvider {
	users := []AuthUser{}
	for _, u := range auth_users {
		users = append(users, NewAuthUser(u.username, u.password))
	}

	return AuthProvider{
		users:                   users,
		authentication_type:     authentication_type,
		authentication_response: authentication_response,
	}
}

var (
	SOCKS_NO_AUTH_CODE     byte = 0x00
	SOCKS_NO_AUTH_RESPONSE      = []byte{
		0x05, 0x00,
	}
	SOCKS_CRED_AUTH_CODE     byte = 0x02
	SOCKS_CRED_AUTH_RESPONSE      = []byte{
		0x05, 0x02,
	}
	SOCKS_NO_ACCEPTABLE_AUTH_CODE     byte = 0xFF
	SOCKS_NO_ACCEPTABLE_AUTH_RESPONSE      = []byte{
		0x05, 0xFF,
	}

	SOCKS_CRED_AUTH_SUCCESS_RESPONSE = []byte{
		0x05, 0x00,
	}
	SOCKS_CRED_AUTH_FAILURE_RESPONSE = []byte{
		0x05, 0x01,
	}
)

func (a *AuthProvider) ChooseAutenticationMethod(rw io.ReadWriter) error {
	buffer := make([]byte, 1024)
	n, err := rw.Read(buffer)
	if err != nil {
		return fmt.Errorf("Can't authenticate client: %s", err)
	}

	request := buffer[:n]

	if slices.Contains(request[2:2+request[1]], a.authentication_type) {
		log.Printf("Server and client decided to use 0x%X type of authentication.", a.authentication_type)
		_, err = rw.Write(a.authentication_response)
		return err
	}

	rw.Write(SOCKS_NO_ACCEPTABLE_AUTH_RESPONSE)
	return fmt.Errorf("Can't authenticate client: no acceptable method found.")
}

func (a *AuthProvider) UseAuthenticateMethod(rw io.ReadWriter) error {
	buffer := make([]byte, 1024)

	switch a.authentication_type {
	case SOCKS_NO_AUTH_CODE:
		return a.authenticateNoAuth(rw, []byte{})
	case SOCKS_CRED_AUTH_CODE:
		n, err := rw.Read(buffer)
		if err != nil {
			return fmt.Errorf("Can't authenticate client: %s", err)
		}
		return a.authenticateCredentials(rw, buffer[:n])
	default:
		return fmt.Errorf("Authentication method 0x%X is not supported.", a.authentication_type)
	}
}

func (a *AuthProvider) authenticateCredentials(w io.Writer, data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("Can't authenticate user: data %s given", data)
	}

	// wtf
	username := string(data[2 : 2+data[1]])
	password := string(data[2+data[1]+1 : 2+data[1]+1+data[1]])

	if slices.Contains(a.users, AuthUser{username, password}) {
		w.Write(SOCKS_CRED_AUTH_SUCCESS_RESPONSE)
		return nil
	}

	w.Write(SOCKS_CRED_AUTH_FAILURE_RESPONSE)
	return fmt.Errorf("Can't authenticate user %s:%s: credentials not found", username, password)
}

func (a *AuthProvider) authenticateNoAuth(_ io.Writer, _ []byte) error {
	return nil
}
