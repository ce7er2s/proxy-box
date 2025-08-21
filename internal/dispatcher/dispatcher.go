package dispatcher

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
)

var (
	SOCKS_COMMAND_NOT_SUPPORTED_RESPONSE = []byte{
		0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	SOCKS_CONNECT_REPONSE = []byte{
		0x05, 0x00, 0x00, 0x00,
	}
	SOCKS_HOST_UNREACHABLE_RESPONSE = []byte{
		0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	SOCKS_ATYPE_NOT_SUPPORTED_RESPONSE = []byte{
		0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

const (
	CONNECT_CODE = 1
)

func Dispatcher(rw io.ReadWriter) error {
	buffer := make([]byte, 1024)
	n, err := rw.Read(buffer)
	if err != nil {
		return err
	}

	request := buffer[:n]
	log.Printf("Got command %v", request)
	code := request[1]

	switch code {
	case CONNECT_CODE:
		addrport, err := parseConnect(request)
		if err != nil {
			return fmt.Errorf("Can't process CONNECT request: %s", err)
		}

		serveConnect(rw, addrport)

	default:
		rw.Write(SOCKS_COMMAND_NOT_SUPPORTED_RESPONSE)
		return fmt.Errorf("Command 0x%X is not supported.", code)
	}

	return nil
}

func parseConnect(request []byte) (netip.AddrPort, error) {
	atype := request[3]

	switch atype {
	case 1:
		ip, _ := netip.AddrFromSlice(request[4:8])
		port := int(request[3+6]) + int(request[3+5])*256

		return netip.AddrPortFrom(ip, uint16(port)), nil
	default:
		// добавить статические ошибки в Dispatcher возвращать SOCKS_ATYPE_NOT_SUPPORTED_RESPONSE
		return netip.AddrPort{}, fmt.Errorf("Got atype = %d which is unsupported", atype)
	}
}

func serveConnect(rw io.ReadWriter, addrport netip.AddrPort) error {
	dst, err := net.Dial("tcp", addrport.String())
	laddr := dst.LocalAddr().(*net.TCPAddr)

	log.Printf("Opened connection from %s to %s\n", dst.LocalAddr(), dst.RemoteAddr())

	if err != nil {
		rw.Write(SOCKS_HOST_UNREACHABLE_RESPONSE)
		return fmt.Errorf("Can't dial target %s: %s", addrport, err)
	}

	data := append(SOCKS_CONNECT_REPONSE, laddr.IP...)
	lport := make([]byte, 2)
	binary.BigEndian.PutUint16(lport, uint16(laddr.Port))
	data = append(data, lport...)
	data[3] = 1

	rw.Write(data)

	log.Printf("Responded with %v", data)

	go io.Copy(rw, dst)
	go io.Copy(dst, rw)

	return nil
}
