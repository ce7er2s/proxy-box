package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	SOCKS_NO_AUTH = []byte{
		0x05, 0x00,
	}
	SOCKS_COMMAND_NOT_SUPPORTED = []byte{
		0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	SOCKS_HOST_UNREACHABLE = []byte{
		0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	SOCKS_CONNECT_REPONSE = []byte{
		0x05, 0x00, 0x00, 0x00,
	}
)

func authSocksConnection(conn net.Conn) {
	authmsg := make([]byte, 257)
	n, err := conn.Read(authmsg)
	if err != nil {
		log.Printf("Can't read from connection %s: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	// Auth message should be at least 3 bytes long and maximum of 257 bytes long
	if n < 3 || n > 257 {
		conn.Close()
		return
	}

	// First byte is always a protocol version which is 5
	if authmsg[:n][0] != 5 {
		conn.Close()
		return
	}

	// Hoping for NMETHODS fields correctness
	if int(authmsg[:n][1])+2 != n {
		conn.Close()
		return
	}

	for _, code := range authmsg[2:n] {
		if code == 0 {
			conn.Write(SOCKS_NO_AUTH)
			go serveSocksClient(conn)
		}
	}
}

func serveSocksClient(conn net.Conn) {
	command := make([]byte, 1024)
	n, err := conn.Read(command)
	log.Printf("Got command from %s: %v", conn.RemoteAddr(), command[:n])
	if err != nil {
		log.Printf("Can't read from connection %s: %s", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	if command[:n][0] != 5 || command[:n][2] != 0 {
		conn.Close()
		return
	}

	switch code := command[:n][1]; code {
	case 1:
		var ip net.IP
		var port int

		switch atype := command[:n][3]; atype {
		case 1:
			ip = net.IPv4(command[:n][3+1], command[:n][3+2], command[:n][3+3], command[:n][3+4])
			port = int(command[:n][3+6]) + int(command[:n][3+5])*256
		case 2:
			hostname := string(command[:n][4 : 4+command[:n][3]])
			ips, err := net.LookupIP(hostname)
			if err != nil {
				log.Printf("NS lookup failed for %s: %s", hostname, err)
				return
			}
			if len(ips) == 0 {
				log.Printf("NS lookup failed for %s: no A records found", hostname)
				return
			}
			ip = ips[0]
			port = int(command[:n][4+command[:n][3]+1]) + int(command[:n][4+command[:n][3]])*256
		case 3:
			ip = net.ParseIP(string(command[4:20]))
			port = int(command[21]) + int(command[20])*256
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			log.Printf("Can't open local socket at %s", listener.Addr())
			conn.Write(SOCKS_HOST_UNREACHABLE)
			return
		}

		log.Printf("Successfully authenticated client from %s", conn.RemoteAddr())
		go serveSocksRemoteConnection(conn, listener, ip, port, code)
	default:
		log.Printf("Proxy does not support command %d", code)
		conn.Write(SOCKS_COMMAND_NOT_SUPPORTED)
	}
}

func serveSocksRemoteConnection(conn net.Conn, listener net.Listener, ip net.IP, port int, atype byte) {
	origin, err := net.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		log.Printf("Can't connect to %s:%d as %s asked: %s", ip, port, conn.RemoteAddr(), err)
		conn.Write(SOCKS_HOST_UNREACHABLE)
		return
	}

	listener_addr := origin.LocalAddr().(*net.TCPAddr)
	listener_ip := listener_addr.IP
	listener_port := make([]byte, 2)
	binary.BigEndian.PutUint16(listener_port, uint16(listener_addr.Port))

	data := append(SOCKS_CONNECT_REPONSE, listener_ip...)
	data = append(data, listener_port...)
	data[3] = atype

	log.Printf("Opened connection to %s:%d at %s", ip, port, listener_addr)
	log.Printf("Data written to %s %v", conn.RemoteAddr(), data)
	log.Printf("Now awaiting connection at %s", listener.Addr())
	conn.Write(data)

	go io.Copy(origin, conn)
	go io.Copy(conn, origin)

}

func main() {
	listener, err := net.Listen("tcp", "127.0.0.1:50057")
	if err != nil {
		log.Fatalf("Can't bind socket: %s", err)
	}
	log.Printf("Open socks proxy (kinda) at %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Can't accept connection from %s: %s", conn.RemoteAddr(), err)
		}

		go authSocksConnection(conn)
	}
}
