package secret

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadProtectedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "join-token.txt")
	f, err := CreateProtectedFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("protected-token\n")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	got, err := ReadProtectedText(path, 64)
	if err != nil || got != "protected-token\n" {
		t.Fatalf("ReadProtectedText = %q, %v", got, err)
	}
	if _, err := ReadProtectedText(path, 4); err == nil {
		t.Fatal("accepted an oversized secret file")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadProtectedText(path, 64); err == nil {
			t.Fatal("accepted a broadly readable secret file")
		}
	}
}
