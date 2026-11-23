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

	"gopkg.in/yaml.v3"
)

const Filename = ".install.yaml"

// TODO(next major): remove the previous dotfile names after migration support expires.
const LegacyYAMLFilename = ".peerimeter-agent.install.yaml"
const LegacyJSONFilename = ".peerimeter-agent.install.json"
const LockFilename = ".install.lock"
const LegacyLockFilename = ".peerimeter-agent.install.lock"
const ReferenceFilename = ".install.ref"
const LegacyReferenceFilename = ".peerimeter-agent.install.ref"
const MarkerFilename = ".profile"
const LegacyMarkerFilename = ".peerimeter-agent.profile"
const RuntimeMarkerFilename = ".runtime"
const LegacyRuntimeMarkerFilename = ".peerimeter-agent.runtime"
const MaxInventorySize = 1 << 20

type File struct {
	Name   string `json:"name" yaml:"name"`
	Dir    string `json:"dir,omitempty" yaml:"dir,omitempty"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}
type Profile struct {
	ID                 string `json:"id,omitempty" yaml:"id,omitempty"`
	ConfigDir          string `json:"config_dir,omitempty" yaml:"config_dir,omitempty"`
	LegacyConfigDir    string `json:"legacy_config_dir,omitempty" yaml:"legacy_config_dir,omitempty"`
	PendingConfigDir   string `json:"pending_config_dir,omitempty" yaml:"pending_config_dir,omitempty"`
	PendingRuntimeDir  string `json:"pending_runtime_dir,omitempty" yaml:"pending_runtime_dir,omitempty"`
	PendingConfigOwned bool   `json:"-" yaml:"-"`
	StateDir           string `json:"state_dir" yaml:"state_dir"`
	RuntimeDir         string `json:"runtime_dir" yaml:"runtime_dir"`
	Service            bool   `json:"service,omitempty" yaml:"service,omitempty"`
	RuntimeOwned       bool   `json:"runtime_owned,omitempty" yaml:"runtime_owned,omitempty"`
	ConfigOwned        bool   `json:"config_owned,omitempty" yaml:"config_owned,omitempty"`
	LegacyConfigOwned  bool   `json:"-" yaml:"-"`
	ClaimConfig        bool   `json:"-" yaml:"-"`
	ClaimRuntime       bool   `json:"-" yaml:"-"`
}
type Inventory struct {
	Version                 int       `json:"version" yaml:"version"`
	Removing                bool      `json:"removing,omitempty" yaml:"removing,omitempty"`
	AllowInsecureInstallDir bool      `json:"allow_insecure_install_dir,omitempty" yaml:"allow_insecure_install_dir,omitempty"`
	ID                      string    `json:"id" yaml:"id"`
	InstallDir              string    `json:"install_dir" yaml:"install_dir"`
	DataDir                 string    `json:"data_dir,omitempty" yaml:"data_dir,omitempty"`
	DocDir                  string    `json:"doc_dir,omitempty" yaml:"doc_dir,omitempty"`
	LockDir                 string    `json:"lock_dir,omitempty" yaml:"lock_dir,omitempty"`
	Files                   []File    `json:"files" yaml:"files"`
	Profiles                []Profile `json:"profiles" yaml:"profiles"`
}

// HasFile reports whether the inventory owns a file with the given name.
func (inv Inventory) HasFile(name string) bool {
	for _, file := range inv.Files {
		if file.Name == name {
			return true
		}
	}
	return false
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

func readInventory(dataDir string) ([]byte, string, error) {
	for _, name := range []string{Filename, LegacyYAMLFilename, LegacyJSONFilename} {
		data, err := readPrivate(filepath.Join(dataDir, name))
		if err == nil {
			return data, name, nil
		}
		if !os.IsNotExist(err) {
			return nil, "", err
		}
	}
	return nil, "", os.ErrNotExist
}

// ExistingInventoryFilename returns the currently persisted inventory name.
func ExistingInventoryFilename(dataDir string) (string, error) {
	_, name, err := readInventory(dataDir)
	return name, err
}

func readCompatPrivate(dir, currentName, legacyName string) ([]byte, bool, error) {
	data, err := readPrivate(filepath.Join(dir, currentName))
	if err == nil || !os.IsNotExist(err) {
		return data, false, err
	}
	data, err = readPrivate(filepath.Join(dir, legacyName))
	return data, err == nil, err
}
func ProgramNames() []string {
	names := []string{"peerimeter-agent", "pma", "peerimeter-agent.NOTICES.txt"}
	if runtime.GOOS == "windows" {
		names[0] += ".exe"
		names[1] += ".cmd"
		names = append(names, "wireguard.dll")
	}
	return names
}

func commandAliasName() string {
	if runtime.GOOS == "windows" {
		return "pma.cmd"
	}
	return "pma"
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
func CheckDirectoryWithPolicy(path string, allowInsecure bool) error {
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
			// A trusted leaf can still be renamed by an attacker who controls an
			// ancestor. Validate every existing directory component, while keeping
			// the explicit insecure-directory exception scoped to the leaf itself.
			var trustErr error
			if p == canonical {
				trustErr = checkTrustWithPolicy(p, info, true, allowInsecure)
			} else {
				trustErr = checkAncestorDirectoryTrust(p, info)
			}
			if trustErr != nil {
				return trustErr
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
	if info.Mode()&os.ModeSymlink != 0 && runtime.GOOS != "windows" && filepath.Base(path) == "pma" {
		target, err := os.Readlink(path)
		if err == nil && target == "peerimeter-agent" {
			return CheckFile(filepath.Join(filepath.Dir(path), target))
		}
	}
	if !info.Mode().IsRegular() || isReparse(info) {
		return errors.New("owned installation resource must be a regular file without links")
	}
	return checkTrust(path, info, false)
}

// CheckPrivateFile verifies that a managed credential or configuration file
// is a regular installation-owned file with private permissions.
func CheckPrivateFile(path string) error {
	if err := CheckFile(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return checkPrivate(path, info)
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
		if privateFileDisappeared(path, err) {
			return nil, true, nil
		}
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
		if privateFileDisappeared(path, err) {
			return nil, true, nil
		}
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

// Darwin's ACL check opens a file after its metadata has already been
// inspected. A concurrent owner can remove a private marker between those
// operations. Retry only when a wrapped ENOENT came from that second open and
// the path is still absent; an initial Lstat miss remains an ordinary
// not-exist result for callers that distinguish missing markers.
func privateFileDisappeared(path string, err error) bool {
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return false
	}
	_, statErr := os.Lstat(path)
	return errors.Is(statErr, os.ErrNotExist)
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
	return renamePrivateFile(name, path)
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
	return loadAtDataDir(dir, "", allowInsecureOverride)
}
func loadAtDataDir(dir, requestedDataDir string, allowInsecureOverride bool) (Inventory, error) {
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
	dataDir, err := resolveInventoryDataDir(canonical, requestedDataDir)
	if err != nil {
		return inv, err
	}
	data, _, err := readInventory(dataDir)
	if err != nil {
		return inv, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
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
	if err := validateInventoryPrograms(inv); err != nil {
		return inv, err
	}
	if err := validateInventoryProfiles(inv.Profiles); err != nil {
		return inv, err
	}
	return inv, nil
}

func resolveInventoryDataDir(canonical, requestedDataDir string) (string, error) {
	dataDir := ""
	hasReference := false
	refData, _, refErr := readCompatPrivate(canonical, ReferenceFilename, LegacyReferenceFilename)
	if refErr == nil {
		hasReference = true
		var ref installReference
		if json.Unmarshal(refData, &ref) != nil {
			return "", errors.New("installation reference is invalid")
		}
		var err error
		dataDir, err = Canonical(ref.DataDir)
		if err != nil || dataDir != ref.DataDir {
			return "", errors.New("installation reference path is invalid")
		}
	} else if !os.IsNotExist(refErr) {
		return "", refErr
	}
	if !hasReference {
		var err error
		if requestedDataDir != "" {
			dataDir, err = Canonical(requestedDataDir)
		} else {
			dataDir, err = defaultInstallDataDir(canonical)
		}
		if err != nil {
			return "", err
		}
	}
	// Older installations kept their inventory beside the executable. Ignore a
	// different installation's default inventory and preserve this legacy lookup.
	if !hasReference && requestedDataDir == "" {
		if defaultData, _, readErr := readInventory(dataDir); readErr == nil {
			var owner struct {
				InstallDir string `yaml:"install_dir"`
			}
			if yaml.Unmarshal(defaultData, &owner) != nil || owner.InstallDir == "" {
				return "", errors.New("installation inventory is invalid")
			}
			if owner.InstallDir != canonical {
				dataDir = canonical
			}
		} else if os.IsNotExist(readErr) {
			if _, _, legacyErr := readInventory(canonical); legacyErr == nil {
				dataDir = canonical
			} else if legacyErr != nil && !os.IsNotExist(legacyErr) {
				return "", legacyErr
			}
		} else {
			return "", readErr
		}
	}
	if err := CheckDirectoryWithPolicy(dataDir, true); err != nil {
		return "", err
	}
	return dataDir, nil
}

func validateInventoryPrograms(inv Inventory) error {
	names := map[string]bool{}
	for _, name := range ProgramNames() {
		names[name] = true
	}
	seen := map[string]bool{}
	for _, file := range inv.Files {
		digest, err := hex.DecodeString(file.SHA256)
		dir := file.Dir
		if dir == "" {
			dir = inv.InstallDir
		}
		resolved, dirErr := Canonical(dir)
		if !names[file.Name] || seen[file.Name] || dirErr != nil || resolved != dir || err != nil || len(digest) != 32 {
			return errors.New("installation inventory contains an invalid program resource")
		}
		seen[file.Name] = true
	}
	programs := ProgramNames()
	requiredPresent := true
	for _, name := range programs {
		if !seen[name] {
			requiredPresent = false
		}
	}
	if !requiredPresent || len(seen) != len(programs) {
		return errors.New("installation inventory is missing a program resource")
	}
	return nil
}

func validateInventoryProfiles(profiles []Profile) error {
	if len(profiles) > 256 {
		return errors.New("installation inventory has too many profiles")
	}
	seen := map[string]bool{}
	for _, profile := range profiles {
		if !validID(profile.ID) || profile.StateDir == "" || profile.RuntimeDir == "" || seen[profile.StateDir] {
			return errors.New("installation profile identity is invalid")
		}
		seen[profile.StateDir] = true
		for _, path := range []string{profile.ConfigDir, profile.LegacyConfigDir, profile.PendingConfigDir, profile.PendingRuntimeDir, profile.StateDir, profile.RuntimeDir} {
			if path == "" {
				continue
			}
			canonical, err := Canonical(path)
			if err != nil || canonical != path {
				return errors.New("installation profile path is invalid")
			}
		}
	}
	return nil
}

func loadForRegistration(dir, dataDir string, allowInsecureOverride bool) (Inventory, error) {
	if _, err := os.Lstat(filepath.Join(dir, ReferenceFilename)); err == nil {
		return load(dir, allowInsecureOverride)
	} else if !os.IsNotExist(err) {
		return Inventory{}, err
	} else if _, err := os.Lstat(filepath.Join(dir, LegacyReferenceFilename)); err == nil {
		// TODO(next major): remove discovery of the previous install reference filename.
		return load(dir, allowInsecureOverride)
	} else if !os.IsNotExist(err) {
		return Inventory{}, err
	}
	defaultDataDir, err := defaultInstallDataDir(dir)
	if err == nil {
		data, _, readErr := readInventory(defaultDataDir)
		if readErr == nil {
			var owner Inventory
			if yaml.Unmarshal(data, &owner) != nil || owner.InstallDir == "" {
				return Inventory{}, errors.New("installation inventory is invalid")
			}
			if owner.InstallDir == dir {
				return load(dir, allowInsecureOverride)
			}
		} else if !os.IsNotExist(readErr) {
			return Inventory{}, readErr
		}
	}
	if _, _, err := readInventory(dir); err == nil {
		return loadAtDataDir(dir, dir, allowInsecureOverride)
	} else if !os.IsNotExist(err) {
		return Inventory{}, err
	}
	return loadAtDataDir(dir, dataDir, allowInsecureOverride)
}
func save(inv Inventory) error {
	data, err := yaml.Marshal(inv)
	if err != nil {
		return err
	}
	if err := WritePrivateWithPolicy(filepath.Join(inv.DataDir, Filename), append(data, '\n'), inv.AllowInsecureInstallDir); err != nil {
		return err
	}
	// TODO(next major): remove compatibility writes for the previous inventory names.
	for _, name := range []string{LegacyYAMLFilename, LegacyJSONFilename} {
		legacyPath := filepath.Join(inv.DataDir, name)
		legacyData, err := readPrivate(legacyPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var legacy Inventory
		if yaml.Unmarshal(legacyData, &legacy) != nil || legacy.ID != inv.ID || legacy.InstallDir != inv.InstallDir {
			return errors.New("legacy installation inventory identity does not match")
		}
		compatData := data
		if name == LegacyJSONFilename {
			compatData, err = json.Marshal(inv)
			if err != nil {
				return err
			}
			compatData = append(compatData, '\n')
		}
		if err := WritePrivateWithPolicy(legacyPath, compatData, inv.AllowInsecureInstallDir); err != nil {
			return err
		}
	}
	return syncInventoryDirectory(inv.DataDir)
}

// UpdateProgramHashesLocked records hashes for existing inventoried files.
// The caller must hold Lock(inv.InstallDir), and should call this only after
// replacing those files. No profile paths or ownership fields are changed.
func UpdateProgramHashesLocked(inv Inventory, hashes map[string]string) error {
	if len(hashes) != len(inv.Files) {
		return errors.New("updated program hashes do not match the installation inventory")
	}
	for i := range inv.Files {
		digest, ok := hashes[inv.Files[i].Name]
		decoded, err := hex.DecodeString(digest)
		if !ok || err != nil || len(decoded) != sha256.Size {
			return errors.New("updated program hash is invalid")
		}
		inv.Files[i].SHA256 = strings.ToLower(digest)
	}
	if err := save(inv); err != nil {
		return err
	}
	return syncInventoryDirectory(inv.DataDir)
}

// Lock serializes inventory mutations. Dry-run must never call this function.
func Lock(dir string) (io.Closer, error) {
	inv, err := Load(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err != nil {
		return LockWithPolicy(dir, false)
	}
	locks, err := acquireDirectoryLocks([]string{inv.LockDir, inv.DataDir}, inv.AllowInsecureInstallDir)
	if err != nil {
		return nil, err
	}
	return locks, nil
}

type lockGroup []io.Closer

func (locks lockGroup) Close() error {
	var errs []error
	for i := len(locks) - 1; i >= 0; i-- {
		errs = append(errs, locks[i].Close())
	}
	return errors.Join(errs...)
}

func acquireDirectoryLocks(dirs []string, allowInsecure bool) (lockGroup, error) {
	lockDirs := uniqueSortedPaths(dirs)
	locks := make(lockGroup, 0, len(lockDirs))
	for _, dir := range lockDirs {
		lock, err := LockWithPolicy(dir, allowInsecure)
		if err != nil {
			for i := len(locks) - 1; i >= 0; i-- {
				_ = locks[i].Close()
			}
			return nil, err
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

func LockWithPolicy(dir string, allowInsecure bool) (io.Closer, error) {
	if err := CheckDirectoryWithPolicy(dir, allowInsecure); err != nil {
		return nil, err
	}
	lock, err := lockInventory(filepath.Join(dir, LockFilename))
	if err != nil {
		return nil, err
	}
	locks := lockGroup{lock}
	// TODO(next major): remove locking compatibility for the previous filename.
	legacyPath := filepath.Join(dir, LegacyLockFilename)
	if _, err := os.Lstat(legacyPath); err == nil {
		legacyLock, lockErr := lockInventory(legacyPath)
		if lockErr != nil {
			_ = locks.Close()
			return nil, lockErr
		}
		locks = append(locks, legacyLock)
	} else if !os.IsNotExist(err) {
		_ = locks.Close()
		return nil, err
	}
	return locks, nil
}

// LockNamed serializes an operation with its own lock file in a trusted
// directory, without blocking service startup on the inventory lock.
func LockNamed(dir, name string, allowInsecure bool) (io.Closer, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "\\/\x00\r\n") {
		return nil, errors.New("invalid installation lock name")
	}
	if err := CheckDirectoryWithPolicy(dir, allowInsecure); err != nil {
		return nil, err
	}
	return lockInventory(filepath.Join(dir, name))
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
// inventory and lock files in their selected directories. Non-default data
// directories are recorded in a protected reference beside the executable.
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
	}
	existing, loadErr := loadForRegistration(dir, dataDir, allowInsecure)
	if loadErr != nil && !os.IsNotExist(loadErr) {
		return loadErr
	}
	allowInsecure = allowInsecure || loadErr == nil && existing.AllowInsecureInstallDir
	for target, value := range map[string]string{"documentation": docDir, "data": dataDir, "lock": lockDir} {
		if err := CheckDirectoryWithPolicy(value, allowInsecure); err != nil {
			return fmt.Errorf("unsafe %s directory: %w", target, err)
		}
	}
	if err := CheckDirectoryWithPolicy(dir, allowInsecure); err != nil {
		return err
	}
	lockDirs := []string{lockDir, dataDir}
	if loadErr == nil {
		lockDirs = append(lockDirs, existing.LockDir)
	}
	locks, err := acquireDirectoryLocks(lockDirs, allowInsecure)
	if err != nil {
		return err
	}
	defer locks.Close()
	// Re-read after acquiring the shared data-directory lock. Two distinct
	// executable directories must never overwrite one another's inventory.
	if current, _, readErr := readInventory(dataDir); readErr == nil {
		var owner Inventory
		if err := yaml.Unmarshal(current, &owner); err != nil || owner.InstallDir != dir {
			return errors.New("installation data directory is already owned by another installation")
		}
	} else if !os.IsNotExist(readErr) {
		return fmt.Errorf("inspect installation data directory inventory: %w", readErr)
	}
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
	legacyNoticeDigest := ""
	if legacyInventory {
		for _, oldFile := range inv.Files {
			if oldFile.Name == "peerimeter-agent.NOTICES.txt" {
				legacyNotice = filepath.Join(dir, oldFile.Name)
				legacyNoticeDigest = oldFile.SHA256
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
	previousInventory, previousInventoryName, previousInventoryErr := readInventory(dataDir)
	if previousInventoryErr != nil && !os.IsNotExist(previousInventoryErr) {
		return fmt.Errorf("read previous installation inventory: %w", previousInventoryErr)
	}
	previousReference, previousReferenceErr := readPrivate(filepath.Join(dir, ReferenceFilename))
	if previousReferenceErr != nil && !os.IsNotExist(previousReferenceErr) {
		return fmt.Errorf("read previous installation reference: %w", previousReferenceErr)
	}
	if err := save(inv); err != nil {
		return err
	}
	if err := updateInstallReference(dir, dataDir, allowInsecure); err != nil {
		rollbackErr := rollbackInventoryFile(dataDir, previousInventoryName, previousInventory, previousInventoryErr, allowInsecure)
		referenceErr := restoreInstallReference(dir, previousReference, previousReferenceErr, allowInsecure)
		return errors.Join(fmt.Errorf("update installation reference: %w", err), rollbackErr, referenceErr)
	}
	if legacyInventory && dataDir != dir {
		cleanupLegacyInstallMetadata(dir, docDir, legacyNotice, legacyNoticeDigest)
	}
	return nil
}

func restoreInstallReference(dir string, previous []byte, previousErr error, allowInsecure bool) error {
	path := filepath.Join(dir, ReferenceFilename)
	if previousErr == nil {
		return WritePrivateWithPolicy(path, previous, allowInsecure)
	}
	if !os.IsNotExist(previousErr) {
		return previousErr
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func updateInstallReference(dir, dataDir string, allowInsecure bool) error {
	refPath := filepath.Join(dir, ReferenceFilename)
	defaultDataDir, defaultErr := defaultInstallDataDir(dir)
	if defaultErr == nil && dataDir == defaultDataDir {
		if err := os.Remove(refPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		ref, _ := json.Marshal(installReference{DataDir: dataDir})
		if err := WritePrivateWithPolicy(refPath, append(ref, '\n'), allowInsecure); err != nil {
			return err
		}
	}
	// TODO(next major): remove cleanup of the previous reference filename.
	legacyRef := filepath.Join(dir, LegacyReferenceFilename)
	if _, err := readPrivate(legacyRef); err == nil {
		if err := os.Remove(legacyRef); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func rollbackInventoryFile(dataDir, previousName string, previousData []byte, previousErr error, allowInsecure bool) error {
	inventoryPath := filepath.Join(dataDir, Filename)
	if previousErr == nil {
		if previousName != Filename {
			if err := os.Remove(inventoryPath); err != nil && !os.IsNotExist(err) {
				return err
			}
			return WritePrivateWithPolicy(filepath.Join(dataDir, previousName), previousData, allowInsecure)
		}
		return WritePrivateWithPolicy(inventoryPath, previousData, allowInsecure)
	}
	if err := os.Remove(inventoryPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func cleanupLegacyInstallMetadata(dir, docDir, legacyNotice, legacyNoticeDigest string) {
	_ = os.Remove(filepath.Join(dir, Filename))
	// TODO(next major): remove cleanup of old inventory and lock filenames.
	_ = os.Remove(filepath.Join(dir, LegacyYAMLFilename))
	_ = os.Remove(filepath.Join(dir, LegacyJSONFilename))
	_ = os.Remove(filepath.Join(dir, LockFilename))
	_ = os.Remove(filepath.Join(dir, LegacyLockFilename))
	if legacyNotice != "" && filepath.Join(docDir, "peerimeter-agent.NOTICES.txt") != legacyNotice {
		if oldHash, err := Hash(legacyNotice); err == nil && oldHash == legacyNoticeDigest {
			_ = os.Remove(legacyNotice)
		}
	}
}

func uniqueSortedPaths(paths []string) []string {
	sort.Strings(paths)
	unique := paths[:0]
	for _, path := range paths {
		if len(unique) == 0 || unique[len(unique)-1] != path {
			unique = append(unique, path)
		}
	}
	return unique
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
	found := findProfileByStateDir(inv.Profiles, p.StateDir)
	if found >= 0 {
		p, err = mergeExistingProfile(inv.Profiles[found], p)
		if err != nil {
			return err
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
	if err := ensureProfileMarker(inv, p); err != nil {
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

func mergeExistingProfile(existing, next Profile) (Profile, error) {
	next.ID = existing.ID
	if next.ConfigDir == "" {
		next.ConfigDir = existing.ConfigDir
	}
	next.Service = next.Service || existing.Service
	next.RuntimeOwned = existing.RuntimeOwned
	next.ConfigOwned = existing.ConfigOwned
	next.PendingConfigDir = existing.PendingConfigDir
	next.PendingRuntimeDir = existing.PendingRuntimeDir
	if next.LegacyConfigDir == "" {
		next.LegacyConfigDir = existing.LegacyConfigDir
	}
	if next.RuntimeDir != existing.RuntimeDir || existing.ConfigDir != "" && next.ConfigDir != existing.ConfigDir {
		return Profile{}, errors.New("installation profile paths changed without migration")
	}
	return next, nil
}

func ensureProfileMarker(inv Inventory, profile Profile) error {
	markerPath := filepath.Join(profile.StateDir, MarkerFilename)
	before, err := readPrivate(markerPath)
	legacyMarkerPath := filepath.Join(profile.StateDir, LegacyMarkerFilename)
	legacyMarker := false
	if os.IsNotExist(err) {
		// TODO(next major): remove migration of the previous profile marker filename.
		before, err = readPrivate(legacyMarkerPath)
		legacyMarker = err == nil
	}
	expected := marker{Version: 1, InstallID: inv.ID, ProfileID: profile.ID}
	if err == nil {
		var got marker
		if json.Unmarshal(before, &got) != nil || got != expected {
			return errors.New("persistent state belongs to another installation profile")
		}
		if legacyMarker {
			if err := WritePrivateWithPolicy(markerPath, before, inv.AllowInsecureInstallDir); err != nil {
				return err
			}
			if err := os.Remove(legacyMarkerPath); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	if profile.ClaimRuntime {
		return errors.New("planned persistent profile marker is absent; runtime ownership cannot be claimed")
	}
	data, _ := json.Marshal(expected)
	return WritePrivateWithPolicy(markerPath, append(data, '\n'), inv.AllowInsecureInstallDir)
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
	if os.IsNotExist(err) {
		// TODO(next major): remove reads of the previous profile marker filename.
		data, err = readPrivate(filepath.Join(p.StateDir, LegacyMarkerFilename))
	}
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
	oldProfile, next, err = canonicalizeMigrationPaths(oldProfile, next)
	if err != nil {
		return err
	}
	if oldProfile.StateDir != next.StateDir {
		return errors.New("profile migration cannot change persistent identity directory")
	}
	index := findProfileByStateDir(inv.Profiles, oldProfile.StateDir)
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
	index = findProfileByStateDir(inv.Profiles, oldProfile.StateDir)
	if index < 0 {
		return errors.New("profile changed during migration")
	}
	next, err = prepareMigratedProfile(inv, oldProfile, next, inv.Profiles[index])
	if err != nil {
		return err
	}
	inv.Profiles[index] = next
	return save(inv)
}

func canonicalizeMigrationPaths(oldProfile, next Profile) (Profile, Profile, error) {
	for _, path := range []*string{&oldProfile.ConfigDir, &oldProfile.StateDir, &oldProfile.RuntimeDir, &next.ConfigDir, &next.StateDir, &next.RuntimeDir} {
		if *path == "" {
			continue
		}
		canonical, err := Canonical(*path)
		if err != nil {
			return Profile{}, Profile{}, err
		}
		*path = canonical
	}
	return oldProfile, next, nil
}

func prepareMigratedProfile(inv Inventory, oldProfile, next, existing Profile) (Profile, error) {
	if existing.ConfigDir != oldProfile.ConfigDir || existing.RuntimeDir != oldProfile.RuntimeDir {
		return Profile{}, errors.New("inventory does not match the expected legacy profile layout")
	}
	if err := VerifyProfile(inv, existing); err != nil {
		return Profile{}, err
	}
	for _, path := range []string{next.ConfigDir, next.StateDir, next.RuntimeDir} {
		if path != "" {
			if err := CheckDirectoryWithPolicy(path, inv.AllowInsecureInstallDir); err != nil {
				return Profile{}, err
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
			return Profile{}, err
		}
		next.ConfigOwned = true
	} else {
		next.ConfigOwned = next.ConfigDir == existing.ConfigDir && existing.ConfigOwned
	}
	next.RuntimeOwned = next.RuntimeDir == existing.RuntimeDir && existing.RuntimeOwned
	return next, nil
}

func findProfileByStateDir(profiles []Profile, stateDir string) int {
	for index, profile := range profiles {
		if profile.StateDir == stateDir {
			return index
		}
	}
	return -1
}
