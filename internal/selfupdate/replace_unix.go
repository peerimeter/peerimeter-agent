//go:build !windows

package selfupdate

import (
	"os"
	"path/filepath"
	"syscall"
)

func setFileOwner(file *os.File, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	current, err := file.Stat()
	if err != nil {
		return err
	}
	currentOwner, currentOK := current.Sys().(*syscall.Stat_t)
	if currentOK && currentOwner.Uid == stat.Uid && currentOwner.Gid == stat.Gid {
		return nil
	}
	return file.Chown(int(stat.Uid), int(stat.Gid))
}

func replaceFile(stage, path string) error {
	if isManagedAliasSymlink(path) {
		return nil
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Rename(stage, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func isManagedAliasSymlink(path string) bool {
	if filepath.Base(path) != "pma" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	target, err := os.Readlink(path)
	return err == nil && target == "peerimeter-agent"
}

func restoreFile(backup, path string) error {
	if err := os.Rename(backup, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
