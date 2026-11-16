package secret

import (
	"errors"
	"io"
)

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
