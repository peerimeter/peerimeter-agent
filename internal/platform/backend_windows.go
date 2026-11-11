package platform

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/driver"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type nativeBackend struct{}

type windowsSession struct {
	mu      sync.Mutex
	adapter *driver.Adapter
	luid    winipcfg.LUID
	name    string
	desired Desired
	routes  map[netip.Prefix]bool
	closed  bool
}

// The DLLs below are from the official WireGuardNT 1.1 archive, whose SHA256 is
// dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace.
// The archive hash is independently pinned in WireGuardWindows v1.1.1/build.bat.
// Runtime loading never downloads anything or searches the working directory.
var wireGuardDLLHashes = map[string]string{
	"amd64": "b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3",
	"arm64": "75bcdc025d6c00e8315af5d62b869d760ca6a253fc82d70f146e789f059a3e0c",
	"386":   "9b292e9e912177df5b99979fb36cc2552ef7428f089f48ef2d524e27d51f7c15",
}

var windowsDriver struct {
	sync.Mutex
	handle windows.Handle
}

func windowsAdapterName(networkID string) string {
	sum := sha256.Sum256([]byte(networkID))
	return "Peerimeter-" + hex.EncodeToString(sum[:8])
}

// loadWindowsDriver verifies and loads only the pinned DLL beside the executable.
// The installer must protect that directory from modification by unprivileged
// users. Keep the verified module loaded for the lifetime of this process; the
// official driver binding also retains its own reference.
func loadWindowsDriver() error {
	windowsDriver.Lock()
	defer windowsDriver.Unlock()
	if windowsDriver.handle != 0 {
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return errors.New("locate WireGuardNT: executable path unavailable")
	}
	path := filepath.Join(filepath.Dir(exe), "wireguard.dll")
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("locate WireGuardNT: invalid installation path")
	}
	h, err := windows.CreateFile(path16, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return errors.New("WireGuardNT 1.1 wireguard.dll is required beside peerimeter-agent; install the complete offline Windows package")
	}
	f := os.NewFile(uintptr(h), "wireguard.dll")
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return errors.New("WireGuardNT DLL must be a regular installed file without links")
	}
	want, ok := wireGuardDLLHashes[runtime.GOARCH]
	if !ok {
		return errors.New("unsupported WireGuardNT architecture")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(f, 32<<20)); err != nil || hex.EncodeToString(hash.Sum(nil)) != want {
		return errors.New("WireGuardNT DLL integrity check failed")
	}
	fi := windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path16, File: h}
	trust := windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi), StateAction: windows.WTD_STATEACTION_VERIFY,
		ProvFlags: windows.WTD_CACHE_ONLY_URL_RETRIEVAL | windows.WTD_REVOCATION_CHECK_NONE,
	}
	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust)
	trust.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &trust)
	if err != nil {
		return errors.New("WireGuardNT DLL signature verification failed using offline Windows trust")
	}
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("load verified WireGuardNT DLL: %w", err)
	}
	// Fail before entering the official binding's lazy Addr(), which panics for
	// missing exports. The pin also prevents an unrelated signed DLL loading.
	for _, name := range []string{"WireGuardCreateAdapter", "WireGuardCloseAdapter", "WireGuardGetAdapterLUID", "WireGuardSetAdapterState", "WireGuardGetAdapterState", "WireGuardSetConfiguration", "WireGuardGetConfiguration", "WireGuardSetLogger"} {
		if _, err := windows.GetProcAddress(handle, name); err != nil {
			windows.FreeLibrary(handle)
			return errors.New("verified WireGuardNT DLL is missing a required API")
		}
	}
	windowsDriver.handle = handle
	return nil
}

func windowsRoutes(d Desired) map[netip.Prefix]bool {
	result := make(map[netip.Prefix]bool)
	for _, peer := range d.Config.Peers {
		for _, raw := range peer.AllowedIPs {
			result[netip.MustParsePrefix(raw)] = true
		}
	}
	return result
}

func windowsCollisionCheck(d Desired, own winipcfg.LUID) error {
	name := windowsAdapterName(d.Config.Network.ID)
	interfaces, err := winipcfg.GetIfTable2Ex(winipcfg.MibIfEntryNormalWithoutStatistics)
	if err != nil {
		return fmt.Errorf("inspect Windows adapter names: %w", err)
	}
	for i := range interfaces {
		if interfaces[i].InterfaceLUID != own && strings.EqualFold(interfaces[i].Alias(), name) {
			return errors.New("Windows adapter name already exists; refusing to take over an existing interface")
		}
	}
	addresses, err := winipcfg.GetUnicastIPAddressTable(windows.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("inspect Windows interface addresses: %w", err)
	}
	for _, raw := range d.Config.Interface.Address {
		address := netip.MustParsePrefix(raw).Addr()
		for i := range addresses {
			if addresses[i].InterfaceLUID != own && addresses[i].Address.Addr() == address {
				return errors.New("static tunnel address is already assigned to another Windows interface")
			}
		}
	}
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("inspect Windows routes: %w", err)
	}
	wanted := windowsRoutes(d)
	for i := range routes {
		if routes[i].InterfaceLUID != own && wanted[routes[i].DestinationPrefix.Prefix()] {
			return errors.New("static tunnel route already exists on another Windows interface")
		}
	}
	return nil
}

func windowsConfiguration(old *Desired, next Desired) (*driver.ConfigBuilder, error) {
	interfaze := driver.Interface{}
	if old == nil || old.PrivateKey != next.PrivateKey {
		interfaze.Flags |= driver.InterfaceHasPrivateKey
		interfaze.PrivateKey = next.PrivateKey
	}
	if old == nil || old.Config.Interface.ListenPort != next.Config.Interface.ListenPort {
		interfaze.Flags |= driver.InterfaceHasListenPort
		interfaze.ListenPort = uint16(next.Config.Interface.ListenPort)
	}
	previous := map[string]config.Peer{}
	if old != nil {
		for _, peer := range old.Config.Peers {
			previous[peer.PublicKey] = peer
		}
	}
	type entry struct {
		peer driver.Peer
		ips  []driver.AllowedIP
	}
	var entries []entry
	for _, peer := range next.Config.Peers {
		before, exists := previous[peer.PublicKey]
		delete(previous, peer.PublicKey)
		if exists && reflect.DeepEqual(before, peer) {
			continue
		}
		var item entry
		item.peer.Flags = driver.PeerHasPublicKey
		key, err := base64.StdEncoding.Strict().DecodeString(peer.PublicKey)
		if err != nil || len(key) != 32 {
			return nil, errors.New("invalid peer public key")
		}
		copy(item.peer.PublicKey[:], key)
		if !exists || before.PersistentKeepaliveSeconds != peer.PersistentKeepaliveSeconds {
			item.peer.Flags |= driver.PeerHasPersistentKeepalive
			item.peer.PersistentKeepalive = uint16(peer.PersistentKeepaliveSeconds)
		}
		if !exists || before.Endpoint != peer.Endpoint {
			item.peer.Flags |= driver.PeerHasEndpoint
			endpoint, err := netip.ParseAddrPort(peer.Endpoint)
			if err != nil || item.peer.Endpoint.SetAddrPort(endpoint) != nil {
				return nil, errors.New("invalid Windows WireGuard endpoint")
			}
		}
		if !exists || !reflect.DeepEqual(before.AllowedIPs, peer.AllowedIPs) {
			item.peer.Flags |= driver.PeerReplaceAllowedIPs
			for _, raw := range peer.AllowedIPs {
				prefix, err := netip.ParsePrefix(raw)
				if err != nil {
					return nil, errors.New("invalid Windows WireGuard allowed IP")
				}
				ip := driver.AllowedIP{Cidr: uint8(prefix.Bits())}
				if prefix.Addr().Is4() {
					ip.AddressFamily = windows.AF_INET
					addr := prefix.Addr().As4()
					copy(ip.Address[:], addr[:])
				} else {
					ip.AddressFamily = windows.AF_INET6
					ip.Address = prefix.Addr().As16()
				}
				item.ips = append(item.ips, ip)
			}
			item.peer.AllowedIPsCount = uint32(len(item.ips))
		}
		entries = append(entries, item)
	}
	// Iterate in old-config order so driver updates and tests are deterministic.
	if old != nil {
		for _, peer := range old.Config.Peers {
			if _, removed := previous[peer.PublicKey]; removed {
				key, _ := base64.StdEncoding.DecodeString(peer.PublicKey)
				item := entry{peer: driver.Peer{Flags: driver.PeerHasPublicKey | driver.PeerRemove}}
				copy(item.peer.PublicKey[:], key)
				entries = append(entries, item)
			}
		}
	}
	interfaze.PeerCount = uint32(len(entries))
	builder := &driver.ConfigBuilder{}
	builder.AppendInterface(&interfaze)
	for _, item := range entries {
		builder.AppendPeer(&item.peer)
		for _, allowedIP := range item.ips {
			builder.AppendAllowedIP(&allowedIP)
		}
	}
	return builder, nil
}

func windowsNextHop(prefix netip.Prefix) netip.Addr {
	if prefix.Addr().Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

func (nativeBackend) Start(ctx context.Context, desired Desired) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := config.Validate(desired.Config, "windows"); err != nil {
		return nil, err
	}
	if desired.PrivateKey == [32]byte{} {
		return nil, errors.New("private key must not be zero")
	}
	name := windowsAdapterName(desired.Config.Network.ID)
	if desired.InterfaceName != "" && desired.InterfaceName != name {
		return nil, errors.New("explicit Linux interface names are unsupported on Windows")
	}
	if err := windowsCollisionCheck(desired, 0); err != nil {
		return nil, err
	}
	builder, err := windowsConfiguration(nil, desired)
	if err != nil {
		return nil, err
	}
	if err := loadWindowsDriver(); err != nil {
		return nil, err
	}
	adapter, err := driver.CreateAdapter(name, "WireGuard", nil)
	if err != nil {
		return nil, fmt.Errorf("create native WireGuardNT adapter (administrator privileges required): %w", err)
	}
	session := &windowsSession{adapter: adapter, luid: adapter.LUID(), name: name, desired: desired, routes: map[netip.Prefix]bool{}}
	complete := false
	defer func() {
		if !complete {
			_ = session.Close(context.Background())
		}
	}()
	interfaze, size := builder.Interface()
	if err := adapter.SetConfiguration(interfaze, size); err != nil {
		return nil, fmt.Errorf("configure WireGuardNT adapter: %w", err)
	}
	if err := adapter.SetAdapterState(driver.AdapterStateUp); err != nil {
		return nil, fmt.Errorf("start WireGuardNT adapter: %w", err)
	}
	families := map[winipcfg.AddressFamily]bool{}
	for _, raw := range desired.Config.Interface.Address {
		prefix := netip.MustParsePrefix(raw)
		family := winipcfg.AddressFamily(windows.AF_INET6)
		if prefix.Addr().Is4() {
			family = windows.AF_INET
		}
		if !families[family] {
			var row *winipcfg.MibIPInterfaceRow
			for attempts := 0; attempts < 100; attempts++ {
				row, err = session.luid.IPInterface(family)
				if err == nil {
					break
				}
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(50 * time.Millisecond):
				}
			}
			if err != nil {
				return nil, fmt.Errorf("wait for Windows IP interface: %w", err)
			}
			row.NLMTU = 1420
			row.DadTransmits = 0
			row.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
			row.UseAutomaticMetric = false
			row.Metric = 0
			if err := row.Set(); err != nil {
				return nil, fmt.Errorf("configure Windows IP interface: %w", err)
			}
			families[family] = true
		}
		if err := session.luid.AddIPAddress(prefix); err != nil {
			return nil, fmt.Errorf("assign Windows tunnel address: %w", err)
		}
	}
	for route := range windowsRoutes(desired) {
		if err := session.luid.AddRoute(route, windowsNextHop(route), 0); err != nil {
			return nil, fmt.Errorf("add Windows tunnel route: %w", err)
		}
		session.routes[route] = true
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	complete = true
	return session, nil
}

func (nativeBackend) Inspect(context.Context) (Snapshot, error) {
	return Snapshot{}, errors.New("query the running Windows agent through local status IPC")
}

func (s *windowsSession) Reconcile(ctx context.Context, desired Desired) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("Windows tunnel session is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := config.Validate(desired.Config, "windows"); err != nil {
		return err
	}
	if desired.Config.Network.ID != s.desired.Config.Network.ID ||
		!reflect.DeepEqual(desired.Config.Interface.Address, s.desired.Config.Interface.Address) ||
		(desired.InterfaceName != "" && desired.InterfaceName != s.name) || desired.PrivateKey == [32]byte{} {
		return errors.New("network identity or local address changes require an explicit Windows tunnel restart")
	}
	if err := windowsCollisionCheck(desired, s.luid); err != nil {
		return err
	}
	builder, err := windowsConfiguration(&s.desired, desired)
	if err != nil {
		return err
	}
	nextRoutes := windowsRoutes(desired)
	var added, removed []netip.Prefix
	rollbackRoutes := func() error {
		var problems []error
		for _, prefix := range removed {
			if err := s.luid.AddRoute(prefix, windowsNextHop(prefix), 0); err != nil {
				problems = append(problems, fmt.Errorf("restore Windows tunnel route: %w", err))
			}
		}
		for _, prefix := range added {
			if err := s.luid.DeleteRoute(prefix, windowsNextHop(prefix)); err != nil {
				problems = append(problems, fmt.Errorf("roll back new Windows route: %w", err))
			}
		}
		return errors.Join(problems...)
	}
	for prefix := range nextRoutes {
		if !s.routes[prefix] {
			if err := s.luid.AddRoute(prefix, windowsNextHop(prefix), 0); err != nil {
				return errors.Join(fmt.Errorf("add Windows tunnel route: %w", err), rollbackRoutes())
			}
			added = append(added, prefix)
		}
	}
	interfaze, size := builder.Interface()
	if interfaze.Flags != 0 || interfaze.PeerCount != 0 {
		if err := s.adapter.SetConfiguration(interfaze, size); err != nil {
			reverse, _ := windowsConfiguration(&desired, s.desired)
			oldInterface, oldSize := reverse.Interface()
			restoreErr := s.adapter.SetConfiguration(oldInterface, oldSize)
			return errors.Join(fmt.Errorf("update WireGuardNT configuration: %w", err), restoreErr, rollbackRoutes())
		}
	}
	for prefix := range s.routes {
		if !nextRoutes[prefix] {
			if err := s.luid.DeleteRoute(prefix, windowsNextHop(prefix)); err != nil {
				reverse, _ := windowsConfiguration(&desired, s.desired)
				oldInterface, oldSize := reverse.Interface()
				restoreErr := s.adapter.SetConfiguration(oldInterface, oldSize)
				return errors.Join(fmt.Errorf("remove Windows tunnel route: %w", err), restoreErr, rollbackRoutes())
			}
			removed = append(removed, prefix)
		}
	}
	s.desired, s.routes = desired, nextRoutes
	return nil
}

func windowsHandshake(raw uint64) time.Time {
	const epoch = uint64(116444736000000000)
	if raw < epoch {
		return time.Time{}
	}
	ticks := raw - epoch
	return time.Unix(int64(ticks/10000000), int64(ticks%10000000)*100).UTC()
}

func (s *windowsSession) Snapshot(ctx context.Context) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if s.closed {
		return Snapshot{}, errors.New("Windows tunnel session is closed")
	}
	configuration, err := s.adapter.Configuration()
	if err != nil {
		return Snapshot{}, fmt.Errorf("read WireGuardNT peer state: %w", err)
	}
	state, err := s.adapter.AdapterState()
	if err != nil {
		return Snapshot{}, fmt.Errorf("read WireGuardNT adapter state: %w", err)
	}
	result := Snapshot{NetworkName: s.desired.Config.Network.Name, PublicKey: base64.StdEncoding.EncodeToString(configuration.PublicKey[:]), ListenPort: int(configuration.ListenPort), NetworkID: s.desired.Config.Network.ID, InterfaceName: s.name, State: "down", Peers: []PeerState{}}
	if state == driver.AdapterStateUp {
		result.State = "running"
	}
	peer := configuration.FirstPeer()
	for i := uint32(0); i < configuration.PeerCount; i++ {

		state := PeerState{PublicKey: base64.StdEncoding.EncodeToString(peer.PublicKey[:]), LastHandshake: windowsHandshake(peer.LastHandshake), ReceivedBytes: peer.RxBytes, SentBytes: peer.TxBytes, PersistentKeepaliveSeconds: int(peer.PersistentKeepalive), AllowedIPs: []string{}}
		if endpoint := peer.Endpoint.AddrPort(); endpoint.IsValid() && endpoint.Port() != 0 {
			state.Endpoint = endpoint.String()
		}
		prefix := peer.FirstAllowedIP()
		for j := uint32(0); j < peer.AllowedIPsCount; j++ {
			var address netip.Addr
			if prefix.AddressFamily == windows.AF_INET {
				var bytes [4]byte
				copy(bytes[:], prefix.Address[:4])
				address = netip.AddrFrom4(bytes)
			} else if prefix.AddressFamily == windows.AF_INET6 {
				address = netip.AddrFrom16(prefix.Address)
			}
			if address.IsValid() {
				p := netip.PrefixFrom(address, int(prefix.Cidr))
				if p.IsValid() {
					state.AllowedIPs = append(state.AllowedIPs, p.String())
				}
			}
			prefix = prefix.NextAllowedIP()
		}
		result.Peers = append(result.Peers, state)
		peer = peer.NextPeer()
	}
	runtime.KeepAlive(configuration)
	return result, nil
}

func (s *windowsSession) Close(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var problems []error
	for prefix := range s.routes {
		if err := s.luid.DeleteRoute(prefix, windowsNextHop(prefix)); err != nil && !errors.Is(err, windows.ERROR_NOT_FOUND) && !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			problems = append(problems, fmt.Errorf("remove owned Windows tunnel route: %w", err))
		}
	}
	if err := s.adapter.SetAdapterState(driver.AdapterStateDown); err != nil {
		problems = append(problems, fmt.Errorf("stop WireGuardNT adapter: %w", err))
	}
	// The native WireGuardCloseAdapter API is VOID. The official Go binding
	// returns an error derived from an unspecified register; ignore it and rely
	// on the API contract: closing our created handle removes our adapter.
	_ = s.adapter.Close()
	s.desired.PrivateKey = [32]byte{}
	return errors.Join(problems...)
}
