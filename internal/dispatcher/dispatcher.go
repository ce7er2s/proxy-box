package dispatcher

import (
	"encoding/binary"
	"errors"
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

	SOCKS_ATYPE_NOT_SUPPORTED_ERROR error = errors.New("This atype is not supported.")
)

const (
	CONNECT_CODE = 1
)

func Dispatcher(rw io.ReadWriteCloser) error {
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
			return err
		}

		return serveConnect(rw, addrport)

	default:
		rw.Write(SOCKS_COMMAND_NOT_SUPPORTED_RESPONSE)
		return fmt.Errorf("Command 0x%X is not supported.", code)
	}
}

func parseConnect(request []byte) (netip.AddrPort, error) {
	atype := request[3]

	switch atype {
	case 1:
		ip, _ := netip.AddrFromSlice(request[4:8])
		port := int(request[3+6]) + int(request[3+5])*256

		log.Printf("Resolved atype=1 into %s:%d", ip, port)

		return netip.AddrPortFrom(ip, uint16(port)), nil
	case 3:
		hostname := string(request[4+1 : 4+1+request[4]])
		addrs, _ := net.LookupHost(hostname)
		if len(addrs) == 0 {
			return netip.AddrPort{}, fmt.Errorf("Can't resolve %q", hostname)
		}
		log.Printf("%v", addrs)
		// TODO: iterate over address until IPv4 found and then use it
		ip, err := netip.ParseAddr(addrs[0])
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("Can't parse %q: %s", addrs[0], err)
		}

		if !ip.Is4() {
			return netip.AddrPort{}, SOCKS_ATYPE_NOT_SUPPORTED_ERROR
		}

		// wtf #2
		port := int(request[4+request[4]+2]) + int(request[4+request[4]+1])*256
		log.Printf("Resolved %q into %s:%d", hostname, ip, port)

		return netip.AddrPortFrom(ip, uint16(port)), nil
	/* case 4:
	// wtf #3
	// maybe check ipv6/ipv4 capability at startup and then dynamically enable/disable handlers?
	ip, _ := netip.AddrFromSlice(request[4:20])
	port := int(request[15+6]) + int(request[15+5])*256

	log.Printf("Resolved atype=4 into %s:%d", ip, port)

	return netip.AddrPortFrom(ip, uint16(port)), nil
	*/

	default:
		// добавить статические ошибки в Dispatcher возвращать SOCKS_ATYPE_NOT_SUPPORTED_RESPONSE
		return netip.AddrPort{}, SOCKS_ATYPE_NOT_SUPPORTED_ERROR
	}
}

func serveConnect(src io.ReadWriteCloser, addrport netip.AddrPort) error {
	dst, err := net.Dial("tcp", addrport.String())
	laddr := dst.LocalAddr().(*net.TCPAddr)

	log.Printf("Opened connection from %s to %s\n", dst.LocalAddr(), dst.RemoteAddr())

	if err != nil {
		src.Write(SOCKS_HOST_UNREACHABLE_RESPONSE)
		return fmt.Errorf("Can't dial target %s: %s", addrport, err)
	}

	data := append(SOCKS_CONNECT_REPONSE, laddr.IP...)
	lport := make([]byte, 2)
	binary.BigEndian.PutUint16(lport, uint16(laddr.Port))
	data = append(data, lport...)
	data[3] = 1

	src.Write(data)

	log.Printf("Responded with %v", data)

	go connect(src, dst)
	go connect(dst, src)

	return nil
}

func connect(src io.ReadWriteCloser, dst io.ReadWriteCloser) {
	for {
		buffer := make([]byte, 8192)
		n, err := src.Read(buffer)
		if err != nil {
			src.Close()
			dst.Close()
			return
		}

		_, err = dst.Write(buffer[:n])
		if err != nil {
			src.Close()
			dst.Close()
			return
		}
	}
}
