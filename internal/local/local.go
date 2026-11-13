// Package local provides the protected, machine-local agent control channel.
// It never opens TCP listeners or stores private keys.
package local

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

// ErrBusy distinguishes a live manager from unsafe paths or unsupported locks.
var ErrBusy = errors.New("agent coordination lock is busy")

// Guard is an OS-held exclusive lock; the lock automatically releases on crash.
type Guard struct {
	f      *os.File
	legacy *os.File
	dir    string
}

func Acquire(dir string) (*Guard, error) {
	return acquire(dir, prepareDirectory)
}

// AcquireForService preserves an existing machine-owned Windows directory.
// Service installation validates its ACL before this lease is acquired; the
// foreground path continues to prepare user-owned state directories normally.
func AcquireForService(dir string) (*Guard, error) {
	return acquire(dir, prepareServiceDirectory)
}

func acquire(dir string, prepare func(string) error) (*Guard, error) {
	if err := prepare(dir); err != nil {
		return nil, err
	}
	f, err := openStateLock(dir, false)
	if err != nil {
		return nil, err
	}
	legacy, err := compatibilityLock(dir)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Guard{f: f, legacy: legacy, dir: dir}, nil
}

// TryAcquireExisting never creates/chmods a path. A nil guard means the state
// directory is absent, or Windows has no existing coordination file. A live
// manager holding the current/legacy protocol lock prevents acquisition.
func TryAcquireExisting(dir string) (*Guard, error) {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	f, err := openStateLock(dir, true)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	legacy, err := compatibilityLock(dir)
	if err != nil {
		f.Close()
		return nil, err
	}
	return &Guard{f: f, legacy: legacy, dir: dir}, nil
}
func (g *Guard) Close() error {
	var legacy error
	if g.legacy != nil {
		legacy = g.legacy.Close()
	}
	return errors.Join(g.f.Close(), legacy)
}

// PrepareDirectory validates or creates an owner-controlled agent directory.
func PrepareDirectory(dir string) error { return prepareDirectory(dir) }

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
		return "", fmt.Errorf("cannot read persisted local interface selection %s: %w", path, err)
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
		return "", fmt.Errorf("cannot create local interface selection %s: %w", path, err)
	}
	defer os.Remove(path + ".new")
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("cannot write local interface selection %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return "", errors.New("cannot sync local interface selection")
	}
	if err = tmp.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(path+".new", path); err != nil {
		return "", fmt.Errorf("cannot persist local interface selection %s: %w", path, err)
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
	Operator   string
	InstanceID string
	// BeforeListen claims runtime ownership under its exclusive guard before any
	// existing Unix socket can be removed. Windows calls it after exclusive pipe creation.
	BeforeListen func() error
	// BeforeServe runs only while the listener exclusively owns its runtime.
	BeforeServe func() error
	// OnClose releases only matching owned runtime metadata after the socket
	// closes and before the exclusive runtime guard is released.
	OnClose  func() error
	Snapshot func(context.Context) (platform.Snapshot, error)
	Reload   func(context.Context) error
	Stop     func()
}

func Serve(ctx context.Context, dir string, ops Operations) (func() error, error) {
	listener, err := listenWithHooks(dir, ops.Operator, ops.BeforeListen, ops.OnClose)
	if err != nil {
		return nil, err
	}
	if ops.BeforeServe != nil {
		if err := ops.BeforeServe(); err != nil {
			return nil, errors.Join(err, listener.Close())
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", func(w http.ResponseWriter, r *http.Request) {
		write(w, map[string]string{"instance_id": ops.InstanceID}, nil)
	})
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
		// net/http ignores some listener Close errors. Explicit idempotent Close
		// retrieves the recorded callback/guard error instead of reporting success.
		return errors.Join(server.Shutdown(shutdown), listener.Close())
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
		return "", fmt.Errorf("cannot read interface ownership %s: %w", path, err)
	}
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("cannot generate interface ownership")
	}
	token := hex.EncodeToString(value[:])
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", fmt.Errorf("cannot create interface ownership %s: %w", path, err)
	}
	_, writeErr := f.WriteString(token + "\n")
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return "", fmt.Errorf("cannot persist interface ownership %s: %w", path, err)
	}
	return token, nil
}

func callListenHooks(hooks []func() error) func() error {
	return func() error {
		for _, hook := range hooks {
			if hook != nil {
				if err := hook(); err != nil {
					return err
				}
			}
		}
		return nil
	}
}
