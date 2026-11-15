//go:build windows

package selfupdate

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
	"path/filepath"
)

func setFileOwner(_ *os.File, _ os.FileInfo) error { return nil }

func replaceFile(stage, path, backup string) error {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := os.OpenFile(backup, os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(destination, source); err != nil {
		destination.Close()
		return err
	}
	if err := destination.Sync(); err != nil {
		destination.Close()
		return err
	}
	if err := destination.Close(); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(stage)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func restoreFile(backup, path string) error {
	from, err := windows.UTF16PtrFromString(backup)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(_ string) error { return nil }
