package secret

import (
	"errors"
	"io"
	"os"
)

// CreateProtectedFile exclusively creates an empty file with restrictive
// owner and ACL checks completed before the caller can write data.
func CreateProtectedFile(path string) (*os.File, error) {
	f, err := createProtected(path)
	if err != nil {
		return nil, errors.New("could not create protected file")
	}
	if err := VerifyProtectedFile(f); err != nil {
		f.Close()
		_ = os.Remove(path)
		return nil, errors.New("new file did not pass protected-file checks")
	}
	return f, nil
}

// VerifyProtectedFile checks the open file descriptor for a private regular
// file without links. It can be called before writing sensitive contents.
func VerifyProtectedFile(f *os.File) error {
	if f == nil {
		return errors.New("protected file handle is unavailable")
	}
	return verifyProtectedFile(f)
}

// ReadProtectedText reads a small credential file after applying the same
// owner, permission, link and ACL checks used for private-key files.
func ReadProtectedText(path string, maxBytes int64) (string, error) {
	if maxBytes < 1 {
		return "", errors.New("protected secret: invalid size limit")
	}
	f, err := openProtected(path)
	if err != nil {
		return "", errors.New("protected secret file is unavailable or has unsafe permissions")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil || int64(len(data)) > maxBytes {
		return "", errors.New("protected secret file is unreadable or too large")
	}
	return string(data), nil
}
