// Package stunprobe performs a STUN RFC 5389 UDP Binding request.
package stunprobe

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	magicCookie      uint32 = 0x2112A442
	bindingRequest   uint16 = 0x0001
	bindingSuccess   uint16 = 0x0101
	xorMappedAddress uint16 = 0x0020
)

type Result struct {
	Server        string `json:"server"`
	LocalAddress  string `json:"local_address"`
	MappedAddress string `json:"mapped_address"`
	MappedIP      string `json:"mapped_ip"`
	MappedPort    int    `json:"mapped_port"`
}

// Probe binds the requested local UDP port (zero asks the OS for an available
// port), sends a Binding request, and closes the socket before returning.
func Probe(port int, server string) (Result, error) {
	if port < 0 || port > 65535 {
		return Result{}, errors.New("UDP port must be between 0 and 65535")
	}
	if server == "" {
		server = "stun.l.google.com:19302"
	}
	remote, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return Result{}, fmt.Errorf("resolve STUN server: %w", err)
	}
	network := "udp4"
	localIP := net.IPv4zero
	if remote.IP.To4() == nil {
		network, localIP = "udp6", net.IPv6unspecified
	}
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: localIP, Port: port})
	if err != nil {
		return Result{}, fmt.Errorf("bind local UDP port: %w", err)
	}
	defer conn.Close()
	local := conn.LocalAddr().String()
	var tx [12]byte
	if _, err := rand.Read(tx[:]); err != nil {
		return Result{}, errors.New("create STUN transaction")
	}
	request := make([]byte, 20)
	binary.BigEndian.PutUint16(request[0:2], bindingRequest)
	binary.BigEndian.PutUint32(request[4:8], magicCookie)
	copy(request[8:20], tx[:])
	if _, err := conn.WriteToUDP(request, remote); err != nil {
		return Result{}, fmt.Errorf("send STUN request: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1500)
	for {
		n, source, err := conn.ReadFromUDP(buf)
		if err != nil {
			return Result{}, fmt.Errorf("read STUN response: %w", err)
		}
		if !sameUDP(source, remote) || n < 20 {
			continue
		}
		msg := buf[:n]
		if binary.BigEndian.Uint16(msg[:2]) != bindingSuccess || binary.BigEndian.Uint32(msg[4:8]) != magicCookie || string(msg[8:20]) != string(tx[:]) {
			continue
		}
		length := int(binary.BigEndian.Uint16(msg[2:4]))
		if length%4 != 0 || length > n-20 {
			return Result{}, errors.New("malformed STUN response")
		}
		ip, mappedPort, err := decodeXORAddress(msg[20:20+length], tx)
		if err != nil {
			return Result{}, err
		}
		return Result{Server: remote.String(), LocalAddress: local, MappedAddress: net.JoinHostPort(ip.String(), fmt.Sprint(mappedPort)), MappedIP: ip.String(), MappedPort: mappedPort}, nil
	}
}

func sameUDP(a, b *net.UDPAddr) bool { return a.Port == b.Port && a.IP.Equal(b.IP) }
func decodeXORAddress(attrs []byte, tx [12]byte) (net.IP, int, error) {
	for len(attrs) >= 4 {
		typ, size := binary.BigEndian.Uint16(attrs[:2]), int(binary.BigEndian.Uint16(attrs[2:4]))
		if size > len(attrs)-4 {
			break
		}
		padded := (size + 3) &^ 3
		if padded > len(attrs)-4 {
			break
		}
		value := attrs[4 : 4+size]
		if typ == xorMappedAddress {
			if size < 8 {
				return nil, 0, errors.New("malformed STUN XOR-MAPPED-ADDRESS")
			}
			port := int(binary.BigEndian.Uint16(value[2:4]) ^ uint16(magicCookie>>16))
			switch value[1] {
			case 1:
				if size != 8 {
					return nil, 0, errors.New("malformed IPv4 STUN address")
				}
				ip := append(net.IP(nil), value[4:8]...)
				var cookie [4]byte
				binary.BigEndian.PutUint32(cookie[:], magicCookie)
				for i := range ip {
					ip[i] ^= cookie[i]
				}
				return ip, port, nil
			case 2:
				if size != 20 {
					return nil, 0, errors.New("malformed IPv6 STUN address")
				}
				ip := append(net.IP(nil), value[4:20]...)
				mask := make([]byte, 16)
				binary.BigEndian.PutUint32(mask[:4], magicCookie)
				copy(mask[4:], tx[:])
				for i := range ip {
					ip[i] ^= mask[i]
				}
				return ip, port, nil
			default:
				return nil, 0, errors.New("unsupported STUN address family")
			}
		}
		attrs = attrs[4+padded:]
	}
	return nil, 0, errors.New("STUN response has no XOR-MAPPED-ADDRESS")
}
