package stunprobe

import (
	"encoding/binary"
	"errors"
	"net"
	"testing"
)

func TestProbeRejectsInvalidPorts(t *testing.T) {
	for _, port := range []int{-1, 65536} {
		if _, err := Probe(port, "127.0.0.1:3478"); err == nil {
			t.Errorf("Probe(%d) succeeded, want invalid-port error", port)
		}
	}
}

func TestProbeLocalBindingRequest(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddress := server.LocalAddr().String()
	serverResult := make(chan error, 1)
	go func() {
		request := make([]byte, 1500)
		n, peer, err := server.ReadFromUDP(request)
		if err != nil {
			serverResult <- err
			return
		}
		if n != 20 || binary.BigEndian.Uint16(request[:2]) != bindingRequest || binary.BigEndian.Uint32(request[4:8]) != magicCookie {
			serverResult <- errInvalidBindingRequest
			return
		}
		response := ipv4BindingResponse(request[8:20], net.IPv4(203, 0, 113, 7), 45678)
		_, err = server.WriteToUDP(response, peer)
		serverResult <- err
	}()

	result, err := Probe(0, serverAddress)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-serverResult; err != nil {
		t.Fatalf("local STUN server: %v", err)
	}
	if result.Server != serverAddress || result.MappedIP != "203.0.113.7" || result.MappedPort != 45678 || result.MappedAddress != "203.0.113.7:45678" {
		t.Fatalf("unexpected STUN result: %+v", result)
	}
	local, err := net.ResolveUDPAddr("udp", result.LocalAddress)
	if err != nil || local.Port == 0 {
		t.Fatalf("invalid local address %q: %v", result.LocalAddress, err)
	}
	probeSocket, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatalf("Probe left its local UDP socket open: %v", err)
	}
	_ = probeSocket.Close()
}

func TestDecodeXORAddressIPv6(t *testing.T) {
	var tx [12]byte
	for i := range tx {
		tx[i] = byte(i + 1)
	}
	wantIP := net.ParseIP("2001:db8::42").To16()
	attrs := xorMappedAttribute(wantIP, 61234, tx)
	ip, port, err := decodeXORAddress(attrs, tx)
	if err != nil {
		t.Fatal(err)
	}
	if !ip.Equal(wantIP) || port != 61234 {
		t.Fatalf("decoded address = %s:%d, want %s:%d", ip, port, wantIP, 61234)
	}
}

func TestDecodeXORAddressRejectsMalformedAttributes(t *testing.T) {
	var tx [12]byte
	tests := []struct {
		name  string
		attrs []byte
		want  string
	}{
		{name: "missing", want: "STUN response has no XOR-MAPPED-ADDRESS"},
		{name: "truncated length", attrs: []byte{0, 0x20, 0, 8}, want: "STUN response has no XOR-MAPPED-ADDRESS"},
		{name: "short address", attrs: []byte{0, 0x20, 0, 4, 0, 1, 0, 1}, want: "malformed STUN XOR-MAPPED-ADDRESS"},
		{name: "unsupported family", attrs: []byte{0, 0x20, 0, 8, 0, 3, 0, 0, 0, 0, 0, 0}, want: "unsupported STUN address family"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := decodeXORAddress(test.attrs, tx)
			if err == nil || err.Error() != test.want {
				t.Fatalf("decodeXORAddress error = %v, want %q", err, test.want)
			}
		})
	}
}

var errInvalidBindingRequest = errors.New("invalid STUN binding request")

func ipv4BindingResponse(tx []byte, ip net.IP, port int) []byte {
	response := make([]byte, 32)
	binary.BigEndian.PutUint16(response[:2], bindingSuccess)
	binary.BigEndian.PutUint16(response[2:4], 12)
	binary.BigEndian.PutUint32(response[4:8], magicCookie)
	copy(response[8:20], tx)
	binary.BigEndian.PutUint16(response[20:22], xorMappedAddress)
	binary.BigEndian.PutUint16(response[22:24], 8)
	response[25] = 1
	binary.BigEndian.PutUint16(response[26:28], uint16(port)^uint16(magicCookie>>16))
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	for i, value := range ip.To4() {
		response[28+i] = value ^ cookie[i]
	}
	return response
}

func xorMappedAttribute(ip net.IP, port int, tx [12]byte) []byte {
	if ipv4 := ip.To4(); ipv4 != nil {
		attribute := make([]byte, 12)
		binary.BigEndian.PutUint16(attribute[:2], xorMappedAddress)
		binary.BigEndian.PutUint16(attribute[2:4], 8)
		attribute[5] = 1
		binary.BigEndian.PutUint16(attribute[6:8], uint16(port)^uint16(magicCookie>>16))
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for i, value := range ipv4 {
			attribute[8+i] = value ^ cookie[i]
		}
		return attribute
	}
	attribute := make([]byte, 24)
	binary.BigEndian.PutUint16(attribute[:2], xorMappedAddress)
	binary.BigEndian.PutUint16(attribute[2:4], 20)
	attribute[5] = 2
	binary.BigEndian.PutUint16(attribute[6:8], uint16(port)^uint16(magicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[:4], magicCookie)
	copy(mask[4:], tx[:])
	for i, value := range ip.To16() {
		attribute[8+i] = value ^ mask[i]
	}
	return attribute
}
