//go:build windows

package installstate

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func defaultInstallDataDir(installDir string) (string, error) {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	sum := sha256.Sum256([]byte(strings.ToLower(installDir)))
	key := fmt.Sprintf("%x", sum[:])
	return Canonical(filepath.Join(base, "Peerimeter", "Installations", key, "State"))
}
