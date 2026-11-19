package uninstall

import (
	"errors"
	"os"
	"path/filepath"
)

func removeDirectoryContents(path string, markers map[string]bool, approvedContents ...[]string) ([]string, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("purge target changed type or became a symbolic link")
	}

	// OpenRoot pins the directory so later operations do not re-resolve its
	// path. Compare identities to reject a symlink or replacement between
	// Lstat and OpenRoot.
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	openedInfo, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.New("purge target changed while opening")
	}

	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(approvedContents) > 0 {
		current := make([]string, 0, len(entries))
		for _, entry := range entries {
			relative, err := listRootTree(root, entry.Name())
			if err != nil {
				return nil, err
			}
			current = append(current, filepath.Join(path, entry.Name()))
			for _, child := range relative {
				current = append(current, filepath.Join(path, child))
			}
		}
		if !isPathSubset(current, approvedContents[0]) {
			return nil, errors.New("purge contents changed after confirmation")
		}
	}

	var removed []string
	for _, entry := range entries {
		// Keep only markers scheduled for the normal marker-removal phase.
		name := entry.Name()
		fullPath := filepath.Join(path, name)
		if markers[fullPath] {
			continue
		}
		relativePaths, err := listRootTree(root, name)
		if err != nil {
			return removed, err
		}
		removed = append(removed, fullPath)
		for _, relative := range relativePaths {
			removed = append(removed, filepath.Join(path, relative))
		}
		if err := root.RemoveAll(name); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func isPathSubset(paths, approved []string) bool {
	approvedSet := make(map[string]bool, len(approved))
	for _, path := range approved {
		approvedSet[path] = true
	}
	for _, path := range paths {
		if !approvedSet[path] {
			return false
		}
	}
	return true
}

// listRootTree walks only directories opened beneath root. Root prevents a
// concurrent symlink replacement from redirecting traversal outside it.
func listRootTree(root *os.Root, name string) ([]string, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	openedInfo, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		_ = file.Close()
		return nil, errors.New("purge entry changed while opening")
	}
	entries, readErr := file.ReadDir(-1)
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	var paths []string
	for _, entry := range entries {
		relative := filepath.Join(name, entry.Name())
		paths = append(paths, relative)
		nested, err := listRootTree(root, relative)
		if err != nil {
			return paths, err
		}
		paths = append(paths, nested...)
	}
	return paths, nil
}
