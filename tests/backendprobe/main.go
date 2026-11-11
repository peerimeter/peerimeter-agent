package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func read(name string) []byte { b, e := os.ReadFile(name); must(e); return b }
func keygen(dir string) {
	must(os.MkdirAll(dir, 0700))
	for _, name := range []string{"native", "reference"} {
		k, e := ecdh.X25519().GenerateKey(rand.Reader)
		must(e)
		must(os.WriteFile(filepath.Join(dir, name+".key"), []byte(base64.StdEncoding.EncodeToString(k.Bytes())+"\n"), 0600))
		must(os.WriteFile(filepath.Join(dir, name+".pub"), []byte(base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())+"\n"), 0600))
	}
	cfg := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.203.0.1/32\nListenPort = 51820\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.203.0.2/32\nEndpoint = 127.0.0.1:51821\n", strings.TrimSpace(string(read(filepath.Join(dir, "native.key")))), strings.TrimSpace(string(read(filepath.Join(dir, "reference.pub")))))
	must(os.WriteFile(filepath.Join(dir, "pmprobe.conf"), []byte(cfg), 0600))
	fmt.Println("Generated ephemeral configs; secret values omitted")
}
func serve(l net.Listener) {
	for {
		c, e := l.Accept()
		if e != nil {
			return
		}
		go func() { defer c.Close(); c.SetDeadline(time.Now().Add(5 * time.Second)); io.Copy(c, c) }()
	}
}
func probe(c net.Conn) error {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	payload := []byte("peerimeter-native-wireguard-probe\n")
	if _, e := c.Write(payload); e != nil {
		return e
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil {
		return e
	}
	if string(got) != string(payload) {
		return fmt.Errorf("payload mismatch")
	}
	return nil
}
func main() {
	if len(os.Args) < 3 {
		panic("usage: pmprobe keygen|reference|host DIR")
	}
	mode, dir := os.Args[1], os.Args[2]
	if mode == "keygen" {
		keygen(dir)
		return
	}
	if mode == "host" {
		l, e := net.Listen("tcp", "10.203.0.1:18081")
		must(e)
		defer l.Close()
		go serve(l)
		c, e := net.DialTimeout("tcp", "10.203.0.2:18080", 10*time.Second)
		must(e)
		must(probe(c))
		fmt.Println("PASS native -> reference checked TCP payload")
		time.Sleep(8 * time.Second)
		return
	}
	if mode != "reference" {
		panic("invalid mode")
	}
	tun, tnet, e := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.203.0.2")}, nil, 1420)
	must(e)
	dev := device.NewDevice(tun, conn.NewStdNetBind(), device.NewLogger(device.LogLevelVerbose, "reference: "))
	defer dev.Close()
	toHex := func(file string) string {
		b, e := base64.StdEncoding.DecodeString(strings.TrimSpace(string(read(filepath.Join(dir, file)))))
		must(e)
		return hex.EncodeToString(b)
	}
	endpoint := os.Getenv("PM_NATIVE_ENDPOINT")
	if endpoint == "" {
		endpoint = "127.0.0.1:51820"
	}
	must(dev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=51821\npublic_key=%s\nallowed_ip=10.203.0.1/32\nendpoint=%s\n", toHex("reference.key"), toHex("native.pub"), endpoint)))
	must(dev.Up())
	l, e := tnet.ListenTCPAddrPort(netip.MustParseAddrPort("10.203.0.2:18080"))
	must(e)
	defer l.Close()
	go serve(l)
	fmt.Println("Reference peer ready")
	for i := 0; i < 1200; i++ {
		time.Sleep(time.Second)
		// A short context prevents a missing host listener from stalling the retry loop.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, e := tnet.DialContext(ctx, "tcp", "10.203.0.1:18081")
		cancel()
		if e == nil && probe(c) == nil {
			fmt.Println("PASS reference -> native checked TCP payload")
			state, e := dev.IpcGet()
			must(e)
			for _, line := range strings.Split(state, "\n") {
				if strings.HasPrefix(line, "last_handshake_time_sec=") || strings.HasPrefix(line, "rx_bytes=") || strings.HasPrefix(line, "tx_bytes=") {
					fmt.Println(line)
				}
			}
		}
	}
}
