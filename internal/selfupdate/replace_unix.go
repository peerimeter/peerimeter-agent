//go:build !windows

package selfupdate

import (
	"io"
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

func replaceFile(stage, path, backup string) error {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	info, err := source.Stat()
	if err != nil {
		return err
	}
	destination, err := os.OpenFile(backup, os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if err := setFileOwner(destination, info); err != nil {
		destination.Close()
		return err
	}
	if err := destination.Chmod(info.Mode().Perm()); err != nil {
		destination.Close()
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
	// Persist the backup directory entry before replacing the only installed copy.
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Rename(stage, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
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
