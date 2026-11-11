// Package ifname resolves device-local Linux interface names without OS changes.
package ifname

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// DefaultPrefix is the single build-time default for generated Linux names.
// Existing persisted names and explicit --interface selections take precedence.
const DefaultPrefix = "pm-"
const MaxNameBytes = 15
const hashLength = 6

// Resolve applies initial-setup precedence. Persisted selections must be supplied
// as override by the state store on later starts (Phase 1).
func Resolve(networkID, displayName, override string) (string, error) {
	if networkID == "" {
		return "", errors.New("interface name requires an immutable network ID")
	}
	if override != "" {
		if err := Validate(override); err != nil {
			return "", err
		}
		return override, nil
	}
	if len(DefaultPrefix)+hashLength > MaxNameBytes {
		return "", errors.New("configured Linux interface prefix leaves no room for the stable suffix")
	}
	if DefaultPrefix != "" {
		if err := Validate(DefaultPrefix + "a"); err != nil {
			return "", errors.New("configured Linux interface prefix contains unsafe characters")
		}
	}
	var b strings.Builder
	separator := false
	for _, c := range strings.ToLower(displayName) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			b.WriteRune(c)
			separator = false
		} else {
			separator = true
		}
	}
	slug := b.String()
	sum := sha256.Sum256([]byte(networkID))
	suffix := hex.EncodeToString(sum[:])[:hashLength]
	if slug == "" {
		return DefaultPrefix + suffix, nil
	}
	if len(slug) <= MaxNameBytes-len(DefaultPrefix) {
		return DefaultPrefix + slug, nil
	}
	humanBytes := MaxNameBytes - len(DefaultPrefix) - 1 - hashLength
	if humanBytes <= 0 {
		return DefaultPrefix + suffix, nil
	}
	return DefaultPrefix + strings.TrimRight(slug[:humanBytes], "-") + "-" + suffix, nil
}
func Validate(name string) error {
	if name == "" || name == "." || name == ".." || len(name) > MaxNameBytes {
		return errors.New("Linux interface name must contain 1–15 safe ASCII bytes")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return errors.New("Linux interface name allows only ASCII letters, digits, dot, hyphen and underscore")
		}
	}
	return nil
}

// CheckOwnership refuses takeover. Empty owner denotes an unmanaged OS device.
// The caller must query OS devices as well as its protected local state store.
func CheckOwnership(name, networkID string, owners map[string]string) error {
	if err := Validate(name); err != nil {
		return err
	}
	if owner, exists := owners[name]; exists && (owner == "" || owner != networkID) {
		return errors.New("interface name is already in use; choose another local name")
	}
	return nil
}
