package main

import (
	"errors"
	"log"
	"net"

	"github.com/ce7er2s/proxy-box/internal/auth"
	"github.com/ce7er2s/proxy-box/internal/dispatcher"
)

func ServeConnection(conn net.Conn, ap auth.AuthProvider) {
	if err := ap.ChooseAutenticationMethod(conn); err != nil {
		log.Printf("Can't authenticate client %s: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	if err := ap.UseAuthenticateMethod(conn); err != nil {
		log.Printf("Can't authenticate client %s: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	if err := dispatcher.Dispatcher(conn); err != nil {
		log.Printf("Client %s dispatch failed: %s", conn.RemoteAddr(), err)
		if errors.Is(err, dispatcher.SOCKS_ATYPE_NOT_SUPPORTED_ERROR) {
			conn.Write(dispatcher.SOCKS_ATYPE_NOT_SUPPORTED_RESPONSE)
		}
		conn.Close()
		return
	}
}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:50057")
	if err != nil {
		log.Fatalf("Can't bind socket: %s", err)
	}
	log.Printf("Open socks proxy (kinda) at %s", listener.Addr())

	ap := auth.NewAuthProvider([]auth.AuthUser{auth.NewAuthUser("user", "pass")}, []byte{auth.SOCKS_NO_AUTH_CODE, auth.SOCKS_CRED_AUTH_CODE})

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Can't accept connection from %s: %s", conn.RemoteAddr(), err)
		}

		go ServeConnection(conn, ap)
	}
}
