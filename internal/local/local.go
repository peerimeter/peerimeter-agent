// Package local provides the protected, machine-local agent control channel.
// It never opens TCP listeners or stores private keys.
package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
)

func DefaultDirectory() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "Peerimeter")
	case "darwin":
		return "/Library/Application Support/Peerimeter"
	default:
		return "/var/lib/peerimeter-agent"
	}
}

// Guard is an OS-held exclusive lock; the lock automatically releases on crash.
type Guard struct {
	f   *os.File
	dir string
}

func Acquire(dir string) (*Guard, error) {
	if err := prepareDirectory(dir); err != nil {
		return nil, err
	}
	f, err := openLock(filepath.Join(dir, "agent.lock"))
	if err != nil {
		return nil, err
	}
	return &Guard{f: f, dir: dir}, nil
}
func (g *Guard) Close() error { return g.f.Close() }

// InterfaceChoice persists the local Linux name independently of display names.
func (g *Guard) InterfaceChoice(id, display, override string) (string, error) {
	path := filepath.Join(g.dir, "network.json")
	var old struct {
		NetworkID     string `json:"network_id"`
		InterfaceName string `json:"interface_name"`
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if json.Unmarshal(data, &old) != nil || old.NetworkID != id || ifname.Validate(old.InterfaceName) != nil {
			return "", errors.New("state directory is associated with another or invalid network")
		}
		if override != "" && override != old.InterfaceName {
			return "", errors.New("persisted interface selection differs from override; explicit safe migration is required")
		}
		return old.InterfaceName, nil
	}
	if !os.IsNotExist(err) {
		return "", errors.New("cannot read persisted local interface selection")
	}
	name, err := ifname.Resolve(id, display, override)
	if err != nil {
		return "", err
	}
	old.NetworkID = id
	old.InterfaceName = name
	data, _ = json.Marshal(old)
	tmp, err := os.OpenFile(path+".new", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot create local interface selection")
	}
	defer os.Remove(path + ".new")
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return "", errors.New("cannot write local interface selection")
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return "", errors.New("cannot sync local interface selection")
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(path+".new", path); err != nil {
		return "", errors.New("cannot persist local interface selection")
	}
	return name, nil
}

// ValidateOperator resolves a control-channel delegate without changing OS state.
func ValidateOperator(operator string) error {
	_, err := resolveOperator(operator)
	return err
}

type Operations struct {
	// Operator delegates local control only; private configuration remains protected.
	Operator string
	Snapshot func(context.Context) (platform.Snapshot, error)
	Reload   func(context.Context) error
	Stop     func()
}

func Serve(ctx context.Context, dir string, ops Operations) (func() error, error) {
	listener, err := listen(dir, ops.Operator)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { s, err := ops.Snapshot(r.Context()); write(w, s, err) })
	mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		s, err := ops.Snapshot(r.Context())
		write(w, s.Peers, err)
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]string{"state": "reconciled"}, ops.Reload(r.Context()))
	})
	mux.HandleFunc("POST /v1/stop", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]string{"state": "stopping"}, nil)
		ops.Stop()
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = server.Serve(listener) }()
	return func() error {
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return server.Shutdown(shutdown)
	}, nil
}
func write(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(value)
}
func Request(ctx context.Context, dir, operation string, out io.Writer) error {
	method := "GET"
	if operation == "stop" || operation == "reload" {
		method = "POST"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, dir) }, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, method, "http://local/v1/"+operation, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("agent is not reachable through its local control channel; check service status and permissions")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return errors.New("cannot read local agent response")
	}
	if resp.StatusCode != http.StatusOK {
		var msg struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &msg) != nil || msg.Error == "" {
			return errors.New("local agent request failed")
		}
		return errors.New(msg.Error)
	}
	_, err = out.Write(data)
	return err
}

// OwnershipToken allows recovery of only a previously owned native interface
// after process death. The process lock must be held before reading this state.
func (g *Guard) OwnershipToken() (string, error) {
	path := filepath.Join(g.dir, "ownership")
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(data))
		decoded, err := hex.DecodeString(token)
		if err != nil || len(decoded) != 32 {
			return "", errors.New("invalid persisted interface ownership")
		}
		return token, nil
	}
	if !os.IsNotExist(err) {
		return "", errors.New("cannot read interface ownership")
	}
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("cannot generate interface ownership")
	}
	token := hex.EncodeToString(value[:])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot create interface ownership")
	}
	_, writeErr := f.WriteString(token + "\n")
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", errors.New("cannot persist interface ownership")
	}
	return token, nil
}
