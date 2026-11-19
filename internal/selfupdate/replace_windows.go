//go:build windows

package selfupdate

import (
	"os"

	"golang.org/x/sys/windows"
	"path/filepath"
)

func setFileOwner(_ *os.File, _ os.FileInfo) error { return nil }

func isManagedAliasSymlink(string) bool { return false }

func replaceFile(stage, path string) error {
	if err := syncDirectory(filepath.Dir(path)); err != nil {
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
