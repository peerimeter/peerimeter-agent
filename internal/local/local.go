// Package local provides the protected, machine-local agent control channel.
// It never opens TCP listeners or stores private keys.
package local

import (
	"bytes"
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
	"sync"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/ifname"
	"github.com/peerimeter/peerimeter-agent/internal/platform"
	"gopkg.in/yaml.v3"
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
	f   *os.File
	dir string
}

func Acquire(dir string) (*Guard, error) {
	return acquire(dir, prepareStateDirectory, true)
}

// AcquireForService preserves an existing machine-owned Windows directory.
// Service installation validates its ACL before this lease is acquired; the
// foreground path continues to prepare user-owned state directories normally.
func AcquireForService(dir string) (*Guard, error) {
	return acquire(dir, prepareServiceDirectory, false)
}

func acquire(dir string, prepare func(string) error, allowSudoOwner bool) (*Guard, error) {
	if err := prepare(dir); err != nil {
		return nil, err
	}
	f, err := openStateLock(dir, false, allowSudoOwner)
	if err != nil {
		return nil, err
	}
	return &Guard{f: f, dir: dir}, nil
}

// TryAcquireExisting never creates/chmods a path. A nil guard means the state
// directory is absent, or Windows has no existing coordination file. A live
// manager holding the current protocol lock prevents acquisition.
func TryAcquireExisting(dir string) (*Guard, error) {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	f, err := openStateLock(dir, true, true)
	if err != nil {
		return nil, err
	}
	if f == nil {
		return nil, nil
	}
	return &Guard{f: f, dir: dir}, nil
}
func (g *Guard) Close() error {
	return g.f.Close()
}

// PrepareDirectory validates or creates an owner-controlled agent directory.
func PrepareDirectory(dir string) error { return prepareDirectory(dir) }

// InterfaceChoice persists the local Linux name independently of display names.
func (g *Guard) InterfaceChoice(id, display, override string) (string, error) {
	path := filepath.Join(g.dir, "network.yaml")
	// TODO(next major): remove the legacy network.json read and conversion.
	legacyPath := filepath.Join(g.dir, "network.json")
	var old struct {
		NetworkID     string `yaml:"network_id"`
		InterfaceName string `yaml:"interface_name"`
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		data, err = os.ReadFile(legacyPath)
		if err == nil {
			path = legacyPath
		}
	}
	if err == nil {
		dec := yaml.NewDecoder(strings.NewReader(string(data)))
		dec.KnownFields(true)
		if dec.Decode(&old) != nil || old.NetworkID != id || ifname.Validate(old.InterfaceName) != nil {
			return "", errors.New("state directory is associated with another or invalid network")
		}
		if override != "" && override != old.InterfaceName {
			return "", errors.New("persisted interface selection differs from override; explicit safe migration is required")
		}
		if path == legacyPath {
			path = filepath.Join(g.dir, "network.yaml")
			if err := persistInterfaceChoice(path, old); err != nil {
				return "", err
			}
			if err := os.Remove(legacyPath); err != nil && !os.IsNotExist(err) {
				return "", fmt.Errorf("cannot remove migrated local interface selection %s: %w", legacyPath, err)
			}
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
	if err := persistInterfaceChoice(path, old); err != nil {
		return "", err
	}
	return name, nil
}

func persistInterfaceChoice(path string, choice any) error {
	data, err := yaml.Marshal(choice)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".new-*")
	if err != nil {
		return fmt.Errorf("cannot create local interface selection %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err = tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("cannot write local interface selection %s: %w", path, err)
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return errors.New("cannot sync local interface selection")
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("cannot persist local interface selection %s: %w", path, err)
	}
	return nil
}

// ValidateOperator resolves a control-channel delegate without changing OS state.
func ValidateOperator(operator string) error {
	_, err := resolveOperator(operator)
	return err
}

type Operations struct {
	// Operator delegates local control only; private configuration remains protected.
	Operator    string
	InstanceID  string
	NetworkID   string
	ConfigPath  string
	PublicKey   string
	Config      func() ([]byte, error)
	ApplyConfig func(context.Context, []byte) error
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
	var runtimeIDBytes [16]byte
	if _, err := rand.Read(runtimeIDBytes[:]); err != nil {
		return nil, errors.Join(errors.New("cannot create local runtime identity"), listener.Close())
	}
	runtimeID := hex.EncodeToString(runtimeIDBytes[:])
	control := &controlServer{runtimeID: runtimeID, ops: ops}
	server := &http.Server{Handler: control.handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { _ = server.Serve(listener) }()
	return func() error {
		control.stopApplying()
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		// net/http ignores some listener Close errors. Explicit idempotent Close
		// retrieves the recorded callback/guard error instead of reporting success.
		return errors.Join(server.Shutdown(shutdown), listener.Close())
	}, nil
}

type controlServer struct {
	runtimeID     string
	ops           Operations
	applyMu       sync.Mutex
	applyStateMu  sync.Mutex
	applyWG       sync.WaitGroup
	applyStopping bool
}

func (server *controlServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/identity", server.identity)
	mux.HandleFunc("GET /v1/config", server.config)
	mux.HandleFunc("POST /v1/config/apply", server.applyConfig)
	mux.HandleFunc("GET /v1/status", server.status)
	mux.HandleFunc("GET /v1/peers", server.peers)
	mux.HandleFunc("POST /v1/reload", server.reload)
	mux.HandleFunc("POST /v1/stop", server.stop)
	return mux
}

func (server *controlServer) identity(w http.ResponseWriter, _ *http.Request) {
	ops := server.ops
	write(w, map[string]string{"instance_id": ops.InstanceID, "runtime_id": server.runtimeID, "network_id": ops.NetworkID, "config_path": ops.ConfigPath, "public_key": ops.PublicKey}, nil)
}

func (server *controlServer) config(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Peerimeter-Runtime-ID") != server.runtimeID || server.ops.Config == nil {
		write(w, nil, errors.New("running agent identity changed or config is unavailable"))
		return
	}
	data, err := server.ops.Config()
	if err != nil {
		write(w, nil, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(append(append([]byte(`{"config":`), data...), '}'))
}

func (server *controlServer) applyConfig(w http.ResponseWriter, r *http.Request) {
	var request struct {
		RuntimeID string `json:"runtime_id"`
		NetworkID string `json:"network_id"`
		Config    []byte `json:"config"`
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, (2<<20)+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || decoder.Decode(new(any)) != io.EOF || request.RuntimeID != server.runtimeID || request.NetworkID != server.ops.NetworkID || server.ops.ApplyConfig == nil {
		write(w, nil, errors.New("running agent identity changed or config update is unavailable"))
		return
	}
	server.applyStateMu.Lock()
	if server.applyStopping {
		server.applyStateMu.Unlock()
		write(w, nil, errors.New("agent is stopping"))
		return
	}
	server.applyWG.Add(1)
	server.applyStateMu.Unlock()
	defer server.applyWG.Done()
	server.applyMu.Lock()
	defer server.applyMu.Unlock()
	applyCtx, cancelApply := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
	defer cancelApply()
	write(w, map[string]string{"state": "reconciled"}, server.ops.ApplyConfig(applyCtx, request.Config))
}

func (server *controlServer) status(w http.ResponseWriter, r *http.Request) {
	snapshot, err := server.ops.Snapshot(r.Context())
	write(w, snapshot, err)
}

func (server *controlServer) peers(w http.ResponseWriter, r *http.Request) {
	snapshot, err := server.ops.Snapshot(r.Context())
	write(w, snapshot.Peers, err)
}

func (server *controlServer) reload(w http.ResponseWriter, r *http.Request) {
	write(w, map[string]string{"state": "reconciled"}, server.ops.Reload(r.Context()))
}

func (server *controlServer) stop(w http.ResponseWriter, _ *http.Request) {
	write(w, map[string]string{"state": "stopping"}, nil)
	server.ops.Stop()
}

func (server *controlServer) stopApplying() {
	server.applyStateMu.Lock()
	server.applyStopping = true
	server.applyStateMu.Unlock()
	server.applyWG.Wait()
}

type Identity struct {
	InstanceID string `json:"instance_id"`
	RuntimeID  string `json:"runtime_id"`
	NetworkID  string `json:"network_id"`
	ConfigPath string `json:"config_path"`
	PublicKey  string `json:"public_key"`
}

func GetIdentity(ctx context.Context, dir string) (Identity, error) {
	var identity Identity
	client, closeClient := newControlClient(dir, 15*time.Second)
	defer closeClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local/v1/identity", nil)
	if err != nil {
		return identity, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return identity, errors.New("agent is not reachable through its local control channel; check service status and permissions")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&identity) != nil {
		return Identity{}, errors.New("cannot read local agent identity")
	}
	return identity, nil
}

func GetConfig(ctx context.Context, dir string, identity Identity) ([]byte, error) {
	client, closeClient := newControlClient(dir, 15*time.Second)
	defer closeClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://local/v1/config", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Peerimeter-Runtime-ID", identity.RuntimeID)
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("agent is not reachable through its local control channel; check service status and permissions")
	}
	defer resp.Body.Close()
	response, err := readControlResponse(resp, "cannot read running agent configuration", 2<<20)
	if err != nil {
		return nil, err
	}
	var result struct {
		Config json.RawMessage `json:"config"`
		Error  string          `json:"error"`
	}
	if err := json.NewDecoder(bytes.NewReader(response)).Decode(&result); err != nil || len(result.Config) == 0 {
		if result.Error != "" {
			return nil, errors.New(result.Error)
		}
		return nil, errors.New("cannot read running agent configuration")
	}
	return result.Config, nil
}

func ApplyConfig(ctx context.Context, dir string, identity Identity, data []byte, out io.Writer) error {
	body, err := json.Marshal(struct {
		RuntimeID string `json:"runtime_id"`
		NetworkID string `json:"network_id"`
		Config    []byte `json:"config"`
	}{identity.RuntimeID, identity.NetworkID, data})
	if err != nil {
		return err
	}
	client, closeClient := newControlClient(dir, 30*time.Second)
	defer closeClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://local/v1/config/apply", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("agent is not reachable through its local control channel; check service status and permissions")
	}
	defer resp.Body.Close()
	response, err := readControlResponse(resp, "local agent request failed", 1<<20)
	if err != nil {
		return err
	}
	_, err = out.Write(response)
	return err
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

func newControlClient(dir string, timeout time.Duration) (*http.Client, func()) {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, dir) }, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: timeout}, transport.CloseIdleConnections
}

func readControlResponse(resp *http.Response, fallback string, maxBytes int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil, errors.New("cannot read local agent response")
	}
	if resp.StatusCode == http.StatusOK {
		return data, nil
	}
	var result struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &result) != nil || result.Error == "" {
		return nil, errors.New(fallback)
	}
	return nil, errors.New(result.Error)
}

func Request(ctx context.Context, dir, operation string, out io.Writer) error {
	method := "GET"
	if operation == "stop" || operation == "reload" {
		method = "POST"
	}
	client, closeClient := newControlClient(dir, 15*time.Second)
	defer closeClient()
	req, err := http.NewRequestWithContext(ctx, method, "http://local/v1/"+operation, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("agent is not reachable through its local control channel; check service status and permissions")
	}
	defer resp.Body.Close()
	data, err := readControlResponse(resp, "local agent request failed", 1<<20)
	if err != nil {
		return err
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
