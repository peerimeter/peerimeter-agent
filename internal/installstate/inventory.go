// Package installstate stores a protected inventory of one installed agent.
// Operator-supplied source configuration and keys are never inferred as owned.
package installstate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const Filename = ".peerimeter-agent.install.json"
const LockFilename = ".peerimeter-agent.install.lock"
const ReferenceFilename = ".peerimeter-agent.install.ref"
const MarkerFilename = ".peerimeter-agent.profile"
const RuntimeMarkerFilename = ".peerimeter-agent.runtime"
const MaxInventorySize = 1 << 20

type File struct {
	Name   string `json:"name"`
	Dir    string `json:"dir,omitempty"`
	SHA256 string `json:"sha256"`
}
type Profile struct {
	ID                 string `json:"id,omitempty"`
	ConfigDir          string `json:"config_dir,omitempty"`
	LegacyConfigDir    string `json:"legacy_config_dir,omitempty"`
	PendingConfigDir   string `json:"pending_config_dir,omitempty"`
	PendingRuntimeDir  string `json:"pending_runtime_dir,omitempty"`
	PendingConfigOwned bool   `json:"-"`
	StateDir           string `json:"state_dir"`
	RuntimeDir         string `json:"runtime_dir"`
	Service            bool   `json:"service,omitempty"`
	RuntimeOwned       bool   `json:"runtime_owned,omitempty"`
	ConfigOwned        bool   `json:"config_owned,omitempty"`
	LegacyConfigOwned  bool   `json:"-"`
	ClaimConfig        bool   `json:"-"`
	ClaimRuntime       bool   `json:"-"`
}
type Inventory struct {
	Version                 int       `json:"version"`
	Removing                bool      `json:"removing,omitempty"`
	AllowInsecureInstallDir bool      `json:"allow_insecure_install_dir,omitempty"`
	ID                      string    `json:"id"`
	InstallDir              string    `json:"install_dir"`
	DataDir                 string    `json:"data_dir,omitempty"`
	DocDir                  string    `json:"doc_dir,omitempty"`
	LockDir                 string    `json:"lock_dir,omitempty"`
	Files                   []File    `json:"files"`
	Profiles                []Profile `json:"profiles"`
}
type installReference struct {
	DataDir string `json:"data_dir"`
}
type marker struct {
	Version   int    `json:"version"`
	InstallID string `json:"installation_id"`
	ProfileID string `json:"profile_id"`
}

func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func validID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && len(s) == 32
}
func ProgramNames() []string {
	names := []string{"peerimeter-agent", "peerimeter-agent.NOTICES.txt"}
	if runtime.GOOS == "windows" {
		names[0] += ".exe"
		names = append(names, "wireguard.dll")
	}
	return names
}

func ResourcePath(inv Inventory, f File) string {
	dir := f.Dir
	if dir == "" {
		dir = inv.InstallDir
	}
	return filepath.Join(dir, f.Name)
}

// Canonical validates existing components without following untrusted links.
// Only macOS's root-owned operating-system /etc, /var and /tmp aliases are allowed.
func Canonical(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("installation paths must be absolute and contain no control characters")
	}
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if runtime.GOOS == "windows" && strings.HasPrefix(volume, `\\`) {
		return "", errors.New("installation resources require local machine storage")
	}
	current := volume + string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(clean, current), string(os.PathSeparator))
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", errors.New("cannot inspect installation path")
		}
		if info.Mode()&os.ModeSymlink != 0 || isReparse(info) {
			if !trustedSystemAlias(current, info) {
				return "", errors.New("installation path contains an untrusted link or reparse point")
			}
			target, err := filepath.EvalSymlinks(current)
			if err != nil {
				return "", err
			}
			current = target
		}
	}
	current = filepath.Clean(current)
	if runtime.GOOS == "windows" {
		current = strings.ToLower(current)
	}
	return current, nil
}

func CheckDirectory(path string) error {
	return CheckDirectoryWithPolicy(path, false)
}
func CheckDirectoryWithPolicy(path string, _ bool) error {
	canonical, err := Canonical(path)
	if err != nil {
		return err
	}
	for p := canonical; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e == nil {
			if !info.IsDir() {
				return errors.New("installation resource parent is not a directory")
			}
		} else if !os.IsNotExist(e) {
			return errors.New("cannot inspect installation resource parent")
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}
func CheckFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || isReparse(info) {
		return errors.New("owned installation resource must be a regular file without links")
	}
	return checkTrust(path, info, false)
}
func readPrivate(path string) ([]byte, error) {
	for attempt := 0; attempt < 4; attempt++ {
		data, changed, err := readPrivateOnce(path)
		if !changed {
			return data, err
		}
		if attempt < 3 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return nil, errors.New("installation inventory changed during inspection")
}

func readPrivateOnce(path string) ([]byte, bool, error) {
	if err := CheckFile(path); err != nil {
		return nil, false, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	named, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, named) {
		return nil, true, nil
	}
	if err := checkPrivate(path, before); err != nil {
		return nil, false, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxInventorySize+1))
	if err != nil {
		return nil, false, err
	}
	if len(data) > MaxInventorySize {
		return nil, false, errors.New("installation inventory is oversized")
	}
	return data, false, nil
}
func WritePrivate(path string, data []byte) error {
	return WritePrivateWithPolicy(path, data, false)
}
func WritePrivateWithPolicy(path string, data []byte, allowInsecure bool) error {
	if err := CheckDirectoryWithPolicy(filepath.Dir(path), allowInsecure); err != nil {
		return err
	}
	var existing os.FileInfo
	if info, err := os.Lstat(path); err == nil {
		if err := CheckFile(path); err != nil {
			return err
		}
		existing = info
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".peerimeter-inventory-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if err := preserveRunOwner(f, existing); err != nil {
		f.Close()
		return err
	}
	if err := protectCreatedTemp(name); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func Hash(path string) (string, error) {
	if err := CheckFile(path); err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func Load(dir string) (Inventory, error) {
	return load(dir, false)
}
func load(dir string, allowInsecureOverride bool) (Inventory, error) {
	var inv Inventory
	canonical, err := Canonical(dir)
	if err != nil {
		return inv, err
	}
	// The inventory itself is private and trusted. Read it before applying its
	// persisted directory policy so a caller cannot opt out of validation.
	if err := CheckDirectoryWithPolicy(canonical, true); err != nil {
		return inv, err
	}
	dataDir := canonical // legacy installs kept the inventory beside the binary.
	refPath := filepath.Join(canonical, ReferenceFilename)
	if _, statErr := os.Lstat(refPath); statErr == nil {
		refData, readErr := readPrivate(refPath)
		if readErr != nil {
			return inv, readErr
		}
		var ref installReference
		if json.Unmarshal(refData, &ref) != nil {
			return inv, errors.New("installation reference is invalid")
		}
		dataDir, err = Canonical(ref.DataDir)
		if err != nil || dataDir != ref.DataDir {
			return inv, errors.New("installation reference path is invalid")
		}
	} else if !os.IsNotExist(statErr) {
		return inv, statErr
	}
	if err := CheckDirectoryWithPolicy(dataDir, true); err != nil {
		return inv, err
	}
	data, err := readPrivate(filepath.Join(dataDir, Filename))
	if err != nil {
		return inv, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&inv); err != nil {
		return inv, errors.New("installation inventory is invalid")
	}
	if inv.Version != 1 || !validID(inv.ID) || inv.InstallDir != canonical {
		return inv, errors.New("installation inventory identity or directory does not match")
	}
	if inv.DataDir == "" {
		inv.DataDir = canonical
	}
	if inv.DocDir == "" {
		inv.DocDir = canonical
	}
	if inv.LockDir == "" {
		inv.LockDir = canonical
	}
	for _, resourceDir := range []string{inv.DataDir, inv.DocDir, inv.LockDir} {
		resolved, e := Canonical(resourceDir)
		if e != nil || resolved != resourceDir {
			return inv, errors.New("installation resource directory is invalid")
		}
		if err := CheckDirectoryWithPolicy(resourceDir, inv.AllowInsecureInstallDir || allowInsecureOverride); err != nil {
			return inv, err
		}
	}
	if err := CheckDirectoryWithPolicy(canonical, inv.AllowInsecureInstallDir || allowInsecureOverride); err != nil {
		return inv, err
	}
	names := map[string]bool{}
	for _, n := range ProgramNames() {
		names[n] = true
	}
	seen := map[string]bool{}
	for _, f := range inv.Files {
		digest, e := hex.DecodeString(f.SHA256)
		dir := f.Dir
		if dir == "" {
			dir = inv.InstallDir
		}
		resolved, dirErr := Canonical(dir)
		if !names[f.Name] || seen[f.Name] || dirErr != nil || resolved != dir || e != nil || len(digest) != 32 {
			return inv, errors.New("installation inventory contains an invalid program resource")
		}
		seen[f.Name] = true
	}
	if len(inv.Files) != len(names) {
		return inv, errors.New("installation inventory is missing a program resource")
	}
	if len(inv.Profiles) > 256 {
		return inv, errors.New("installation inventory has too many profiles")
	}
	seen = map[string]bool{}
	for _, p := range inv.Profiles {
		if !validID(p.ID) || p.StateDir == "" || p.RuntimeDir == "" || seen[p.StateDir] {
			return inv, errors.New("installation profile identity is invalid")
		}
		seen[p.StateDir] = true
		for _, path := range []string{p.ConfigDir, p.LegacyConfigDir, p.PendingConfigDir, p.PendingRuntimeDir, p.StateDir, p.RuntimeDir} {
			if path == "" {
				continue
			}
			c, e := Canonical(path)
			if e != nil || c != path {
				return inv, errors.New("installation profile path is invalid")
			}
		}
	}
	return inv, nil
}
func save(inv Inventory) error {
	data, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return WritePrivateWithPolicy(filepath.Join(inv.DataDir, Filename), append(data, '\n'), inv.AllowInsecureInstallDir)
}

// Lock serializes inventory mutations. Dry-run must never call this function.
func Lock(dir string) (io.Closer, error) {
	inv, err := Load(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		dir = inv.LockDir
	}
	return LockWithPolicy(dir, err == nil && inv.AllowInsecureInstallDir)
}
func LockWithPolicy(dir string, allowInsecure bool) (io.Closer, error) {
	if err := CheckDirectoryWithPolicy(dir, allowInsecure); err != nil {
		return nil, err
	}
	return lockInventory(filepath.Join(dir, LockFilename))
}

// Register is called by the verified installer after program files are in place.
// Upgrades preserve installation identity and registered profiles.
func Register(dir string) error {
	return RegisterWithPolicy(dir, false)
}
func RegisterWithPolicy(dir string, allowInsecure bool) error {
	return RegisterWithDirectories(dir, dir, dir, dir, allowInsecure)
}

// RegisterWithDirectories keeps program resources, notices, persistent
// inventory and lock files in their selected directories. A small protected
// reference beside the executable lets service startup find the inventory.
func RegisterWithDirectories(dir, docDir, dataDir, lockDir string, allowInsecure bool) error {
	dir, err := Canonical(dir)
	if err != nil {
		return err
	}
	for target, value := range map[string]*string{"documentation": &docDir, "data": &dataDir, "lock": &lockDir} {
		*value, err = Canonical(*value)
		if err != nil {
			return fmt.Errorf("invalid %s directory: %w", target, err)
		}
		if err := CheckDirectoryWithPolicy(*value, allowInsecure); err != nil {
			return fmt.Errorf("unsafe %s directory: %w", target, err)
		}
	}
	existing, loadErr := load(dir, allowInsecure)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return loadErr
	}
	allowInsecure = allowInsecure || loadErr == nil && existing.AllowInsecureInstallDir
	if err := CheckDirectoryWithPolicy(dir, allowInsecure); err != nil {
		return err
	}
	lock, err := LockWithPolicy(lockDir, allowInsecure)
	if err != nil {
		return err
	}
	defer lock.Close()
	inv, err := load(dir, allowInsecure)
	if os.IsNotExist(err) {
		inv = Inventory{Version: 1, InstallDir: dir, DataDir: dataDir, DocDir: docDir, LockDir: lockDir, Profiles: []Profile{}, AllowInsecureInstallDir: allowInsecure}
		inv.ID, err = NewID()
	} else if err != nil {
		return err
	}
	// Once selected, retain the explicit exception on upgrades.
	inv.AllowInsecureInstallDir = inv.AllowInsecureInstallDir || allowInsecure
	if inv.InstallDir != dir {
		return errors.New("installation directory changed; remove the existing installation first")
	}
	// Older installers kept all package metadata beside the executable. Move
	// that inventory to the selected data directory during the first upgrade.
	legacyInventory := inv.DataDir == dir && inv.DocDir == dir && inv.LockDir == dir
	legacyNotice := ""
	if legacyInventory {
		for _, oldFile := range inv.Files {
			if oldFile.Name == "peerimeter-agent.NOTICES.txt" {
				legacyNotice = filepath.Join(dir, oldFile.Name)
				break
			}
		}
	}
	if !legacyInventory && (inv.DataDir != dataDir || inv.DocDir != docDir || inv.LockDir != lockDir) {
		return errors.New("installation resource directories changed; remove the existing installation first")
	}
	if legacyInventory {
		inv.DataDir, inv.DocDir, inv.LockDir = dataDir, docDir, lockDir
	}
	if err != nil {
		return err
	}
	inv.Files = nil
	for _, name := range ProgramNames() {
		resourceDir := dir
		if name == "peerimeter-agent.NOTICES.txt" {
			resourceDir = docDir
		}
		hash, e := Hash(filepath.Join(resourceDir, name))
		if e != nil {
			return fmt.Errorf("inspect installed program resource %s: %w", name, e)
		}
		inv.Files = append(inv.Files, File{Name: name, Dir: resourceDir, SHA256: hash})
	}
	if err := save(inv); err != nil {
		return err
	}
	ref, _ := json.Marshal(installReference{DataDir: dataDir})
	if err := WritePrivateWithPolicy(filepath.Join(dir, ReferenceFilename), append(ref, '\n'), allowInsecure); err != nil {
		return err
	}
	if legacyInventory && dataDir != dir {
		_ = os.Remove(filepath.Join(dir, Filename))
		_ = os.Remove(filepath.Join(dir, LockFilename))
		if legacyNotice != "" && filepath.Join(docDir, "peerimeter-agent.NOTICES.txt") != legacyNotice {
			if oldHash, e := Hash(legacyNotice); e == nil {
				for _, current := range inv.Files {
					if current.Name == "peerimeter-agent.NOTICES.txt" && current.Dir == docDir && oldHash == current.SHA256 {
						_ = os.Remove(legacyNotice)
					}
				}
			}
		}
	}
	return nil
}

// RegisterProfile records only managed snapshots, durable metadata and runtime
// paths. An empty ConfigDir never claims an operator-supplied source config.
// Source builds without an installation inventory intentionally do not register.
func RegisterProfile(dir string, p Profile) error {
	dir, err := Canonical(dir)
	if err != nil {
		return err
	}
	if _, err := Load(dir); os.IsNotExist(err) {
		if p.ClaimRuntime {
			return validateSourceRuntime(p)
		}
		if p.ClaimConfig {
			return ValidateConfigClaim(dir, p.StateDir, p.ConfigDir)
		}
		return nil
	} else if err != nil {
		return err
	}
	lock, err := Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	return registerProfileLocked(dir, p)
}

func registerProfileLocked(dir string, p Profile) error {
	inv, err := Load(dir)
	if err != nil {
		return err
	}
	if inv.Removing {
		return errors.New("installation is being removed; profile startup is disabled")
	}
	p.StateDir, err = Canonical(p.StateDir)
	if err != nil {
		return err
	}
	p.RuntimeDir, err = Canonical(p.RuntimeDir)
	if err != nil {
		return err
	}
	if p.ConfigDir != "" {
		p.ConfigDir, err = Canonical(p.ConfigDir)
		if err != nil {
			return err
		}
	}
	for _, path := range []string{p.ConfigDir, p.LegacyConfigDir, p.PendingConfigDir, p.PendingRuntimeDir, p.StateDir, p.RuntimeDir} {
		if path != "" {
			if err := CheckDirectoryWithPolicy(path, inv.AllowInsecureInstallDir); err != nil {
				return err
			}
		}
	}
	found := -1
	for i, old := range inv.Profiles {
		if old.StateDir == p.StateDir {
			found = i
			p.ID = old.ID
			if p.ConfigDir == "" {
				p.ConfigDir = old.ConfigDir
			}
			p.Service = p.Service || old.Service
			p.RuntimeOwned = old.RuntimeOwned
			p.ConfigOwned = old.ConfigOwned
			p.PendingConfigDir = old.PendingConfigDir
			p.PendingRuntimeDir = old.PendingRuntimeDir
			if p.LegacyConfigDir == "" {
				p.LegacyConfigDir = old.LegacyConfigDir
			}
			if p.RuntimeDir != old.RuntimeDir || old.ConfigDir != "" && p.ConfigDir != old.ConfigDir {
				return errors.New("installation profile paths changed without migration")
			}
			break
		}
	}
	if found < 0 {
		p.ID, err = NewID()
		if err != nil {
			return err
		}
	}
	if (p.ClaimRuntime || p.ClaimConfig) && found < 0 {
		return errors.New("register the planned persistent-state profile before claiming its runtime")
	}
	markerPath := filepath.Join(p.StateDir, MarkerFilename)
	before, err := readPrivate(markerPath)
	expected := marker{Version: 1, InstallID: inv.ID, ProfileID: p.ID}
	if err == nil {
		var got marker
		if json.Unmarshal(before, &got) != nil || got != expected {
			return errors.New("persistent state belongs to another installation profile")
		}
	} else if os.IsNotExist(err) {
		if p.ClaimRuntime {
			return errors.New("planned persistent profile marker is absent; runtime ownership cannot be claimed")
		}
		data, _ := json.Marshal(expected)
		if err := WritePrivateWithPolicy(markerPath, append(data, '\n'), inv.AllowInsecureInstallDir); err != nil {
			return err
		}
	} else {
		return err
	}
	if p.ClaimConfig {
		if err := claimConfig(inv, p); err != nil {
			return err
		}
		p.ConfigOwned = true
	}
	if p.ClaimRuntime {
		if err := claimRuntime(inv, p); err != nil {
			return err
		}
		p.RuntimeOwned = true
	}
	if found >= 0 {
		inv.Profiles[found] = p
	} else {
		inv.Profiles = append(inv.Profiles, p)
	}
	sort.Slice(inv.Profiles, func(i, j int) bool { return inv.Profiles[i].StateDir < inv.Profiles[j].StateDir })
	return save(inv)
}
func VerifyProfile(inv Inventory, p Profile) error {
	if _, err := os.Lstat(p.StateDir); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if err := CheckDirectoryWithPolicy(p.StateDir, inv.AllowInsecureInstallDir); err != nil {
		return err
	}
	data, err := readPrivate(filepath.Join(p.StateDir, MarkerFilename))
	if err != nil {
		return errors.New("installation profile marker is missing or untrusted")
	}
	var got marker
	if json.Unmarshal(data, &got) != nil || got != (marker{1, inv.ID, p.ID}) {
		return errors.New("installation profile marker does not match")
	}
	return nil
}

// MigrateProfile is the deliberate combined-directory -> separated-layout
// transition. It preserves persistent profile/installation identity and refuses
// a different old layout or state directory. Call only after protected snapshots
// and the new service registration are verified by service migration.
func MigrateProfile(dir string, oldProfile, next Profile) error {
	dir, err := Canonical(dir)
	if err != nil {
		return err
	}
	inv, err := Load(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, v := range []*string{&oldProfile.ConfigDir, &oldProfile.StateDir, &oldProfile.RuntimeDir, &next.ConfigDir, &next.StateDir, &next.RuntimeDir} {
		if *v != "" {
			*v, err = Canonical(*v)
			if err != nil {
				return err
			}
		}
	}
	if oldProfile.StateDir != next.StateDir {
		return errors.New("profile migration cannot change persistent identity directory")
	}
	index := -1
	for i, p := range inv.Profiles {
		if p.StateDir == oldProfile.StateDir {
			index = i
			break
		}
	}
	if index < 0 {
		return RegisterProfile(dir, next)
	}
	lock, err := Lock(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	inv, err = Load(dir)
	if err != nil {
		return err
	}
	if inv.Removing {
		return errors.New("installation is being removed; migration is disabled")
	}
	index = -1
	for i, p := range inv.Profiles {
		if p.StateDir == oldProfile.StateDir {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("profile changed during migration")
	}
	existing := inv.Profiles[index]
	if existing.ConfigDir != oldProfile.ConfigDir || existing.RuntimeDir != oldProfile.RuntimeDir {
		return errors.New("inventory does not match the expected legacy profile layout")
	}
	if err := VerifyProfile(inv, existing); err != nil {
		return err
	}
	for _, path := range []string{next.ConfigDir, next.StateDir, next.RuntimeDir} {
		if path != "" {
			if err := CheckDirectoryWithPolicy(path, inv.AllowInsecureInstallDir); err != nil {
				return err
			}
		}
	}
	next.ID = existing.ID
	next.PendingConfigDir = ""
	next.PendingRuntimeDir = ""
	if existing.ConfigDir != next.ConfigDir {
		next.LegacyConfigDir = existing.ConfigDir
	} else if next.LegacyConfigDir == "" {
		next.LegacyConfigDir = existing.LegacyConfigDir
	}
	next.Service = next.Service || existing.Service
	if next.ClaimConfig {
		if err := claimConfig(inv, next); err != nil {
			return err
		}
		next.ConfigOwned = true
	} else {
		next.ConfigOwned = next.ConfigDir == existing.ConfigDir && existing.ConfigOwned
	}
	next.RuntimeOwned = next.RuntimeDir == existing.RuntimeDir && existing.RuntimeOwned
	inv.Profiles[index] = next
	return save(inv)
}
