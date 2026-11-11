package secret

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func setTestDACL(t *testing.T, path, descriptor string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsDACL(t *testing.T) {
	for _, trustee := range []string{"WD", "BU", "AU"} {
		t.Run(trustee, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "private.key")
			if err := WriteNew(path, mustGenerate(t)); err != nil {
				t.Fatal(err)
			}
			allowed, err := trustedSIDs()
			if err != nil {
				t.Fatal(err)
			}
			// Everyone, Users or Authenticated Users receiving read access
			// must be rejected, even when the current user also has full access.
			setTestDACL(t, path, "D:P(A;;FA;;;"+allowed[0].String()+")(A;;GR;;;"+trustee+")")
			if _, err := Load(path); err == nil {
				t.Fatal("broadly readable Windows private key accepted")
			}
		})
	}
}

func TestWindowsNullDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private.key")
	if err := WriteNew(path, mustGenerate(t)); err != nil {
		t.Fatal(err)
	}
	// A NULL DACL gives unrestricted access and must fail closed.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("NULL DACL accepted")
	}
}
