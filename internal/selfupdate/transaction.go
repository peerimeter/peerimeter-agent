package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

const JournalFilename = ".peerimeter-agent.update-journal.json"

type journal struct {
	Version   int           `json:"version"`
	InstallID string        `json:"installation_id"`
	State     string        `json:"state"`
	Files     []journalFile `json:"files"`
}
type journalFile struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Stage   string `json:"stage"`
	Backup  string `json:"backup"`
	OldHash string `json:"old_hash"`
	NewHash string `json:"new_hash"`
}

// Apply stages every owned program file beside its destination, writes a
// private recovery journal, then replaces files. The caller must hold the
// installstate lock until it records the returned hashes.
func Apply(inv installstate.Inventory, packageFiles map[string][]byte) (map[string]string, func() error, func() error, error) {
	if len(packageFiles) != len(inv.Files) {
		return nil, nil, nil, errors.New("release package does not match the installed program file inventory")
	}
	for name := range packageFiles {
		if !knownInventoryFile(inv, name) {
			return nil, nil, nil, fmt.Errorf("release package contains unowned file %q", name)
		}
	}
	journalPath := filepath.Join(inv.LockDir, JournalFilename)
	if _, err := os.Lstat(journalPath); err == nil {
		return nil, nil, nil, errors.New("an interrupted update must be recovered before starting another update")
	} else if !os.IsNotExist(err) {
		return nil, nil, nil, err
	}
	j := journal{Version: 1, InstallID: inv.ID, State: "applying"}
	hashes := make(map[string]string, len(inv.Files))
	cleanupStages := func() {
		for _, f := range j.Files {
			_ = os.Remove(f.Stage)
			_ = os.Remove(f.Backup)
		}
	}
	for _, owned := range inv.Files {
		path := installstate.ResourcePath(inv, owned)
		if err := installstate.CheckFile(path); err != nil {
			cleanupStages()
			return nil, nil, nil, fmt.Errorf("inspect installed %s: %w", owned.Name, err)
		}
		oldHash, err := installstate.Hash(path)
		if err != nil {
			cleanupStages()
			return nil, nil, nil, err
		}
		if oldHash != owned.SHA256 {
			cleanupStages()
			return nil, nil, nil, fmt.Errorf("installed %s was modified; refusing to overwrite it", owned.Name)
		}
		info, err := os.Stat(path)
		if err != nil {
			cleanupStages()
			return nil, nil, nil, err
		}
		stage, err := os.CreateTemp(filepath.Dir(path), ".peerimeter-update-stage-*")
		if err != nil {
			cleanupStages()
			return nil, nil, nil, err
		}
		stagePath := stage.Name()
		if err := stage.Chmod(info.Mode().Perm()); err != nil {
			stage.Close()
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		if err := setFileOwner(stage, info); err != nil {
			stage.Close()
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		if _, err := stage.Write(packageFiles[owned.Name]); err != nil {
			stage.Close()
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		if err := stage.Sync(); err != nil {
			stage.Close()
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		if err := stage.Close(); err != nil {
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		if err := installstate.CheckFile(stagePath); err != nil {
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		backup, err := os.CreateTemp(filepath.Dir(path), ".peerimeter-update-backup-*")
		if err != nil {
			os.Remove(stagePath)
			cleanupStages()
			return nil, nil, nil, err
		}
		backupPath := backup.Name()
		if err := backup.Close(); err != nil {
			os.Remove(stagePath)
			os.Remove(backupPath)
			cleanupStages()
			return nil, nil, nil, err
		}
		sum := sha256.Sum256(packageFiles[owned.Name])
		hashes[owned.Name] = hex.EncodeToString(sum[:])
		j.Files = append(j.Files, journalFile{Name: owned.Name, Path: path, Stage: stagePath, Backup: backupPath, OldHash: oldHash, NewHash: hashes[owned.Name]})
	}
	if err := writeJournal(journalPath, j); err != nil {
		cleanupStages()
		return nil, nil, nil, err
	}
	rollback := func() error { return recoverJournal(inv, &j, false) }
	for _, f := range j.Files {
		if err := replaceFile(f.Stage, f.Path, f.Backup); err != nil {
			return nil, nil, nil, errors.Join(fmt.Errorf("replace installed %s: %w", f.Name, err), rollback())
		}
	}
	for _, f := range j.Files {
		if err := installstate.CheckFile(f.Path); err != nil {
			return nil, nil, nil, errors.Join(err, rollback())
		}
	}
	commit := func() error {
		j.State = "committed"
		if err := writeJournal(journalPath, j); err != nil {
			return err
		}
		if err := syncDirectory(inv.LockDir); err != nil {
			return err
		}
		if err := cleanupJournalFiles(j); err != nil {
			return err
		}
		for _, f := range j.Files {
			if err := syncDirectory(filepath.Dir(f.Path)); err != nil {
				return err
			}
		}
		if err := os.Remove(journalPath); err != nil {
			return err
		}
		return syncDirectory(inv.LockDir)
	}
	return hashes, rollback, commit, nil
}

// RecoverLocked completes cleanup after a committed update or restores the
// previous files after an interrupted transaction. The caller holds the
// installstate lock; profile metadata and paths are never rewritten.
func RecoverLocked(inv installstate.Inventory) error {
	path := filepath.Join(inv.LockDir, JournalFilename)
	if err := installstate.CheckPrivateFile(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var j journal
	if err := json.Unmarshal(data, &j); err != nil || j.Version != 1 || j.InstallID != inv.ID || (j.State != "applying" && j.State != "committed") {
		return errors.New("update recovery journal is invalid")
	}
	if err := validateJournal(inv, j); err != nil {
		return err
	}
	if j.State == "committed" {
		if err := cleanupJournalFiles(j); err != nil {
			return err
		}
		for _, f := range j.Files {
			if err := syncDirectory(filepath.Dir(f.Path)); err != nil {
				return err
			}
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		return syncDirectory(inv.LockDir)
	}
	if err := recoverJournal(inv, &j, true); err != nil {
		return err
	}
	return nil
}

func recoverJournal(inv installstate.Inventory, j *journal, saveOldHashes bool) error {
	if err := validateJournal(inv, *j); err != nil {
		return err
	}
	var failures []error
	oldHashes := make(map[string]string, len(j.Files))
	for i := len(j.Files) - 1; i >= 0; i-- {
		f := j.Files[i]
		oldHashes[f.Name] = f.OldHash
		hash, hashErr := installstate.Hash(f.Path)
		if hashErr == nil && hash == f.OldHash {
			_ = os.Remove(f.Backup)
			_ = os.Remove(f.Stage)
			continue
		}
		backupHash, backupErr := installstate.Hash(f.Backup)
		if backupErr != nil || backupHash != f.OldHash {
			failures = append(failures, fmt.Errorf("cannot safely restore previous %s", f.Name))
			continue
		}
		if err := restoreFile(f.Backup, f.Path); err != nil {
			failures = append(failures, fmt.Errorf("restore %s: %w", f.Name, err))
			continue
		}
		_ = os.Remove(f.Stage)
	}
	if err := errors.Join(failures...); err != nil {
		return err
	}
	if saveOldHashes {
		if len(oldHashes) != len(inv.Files) {
			return errors.New("update recovery journal is incomplete")
		}
		if err := installstate.UpdateProgramHashesLocked(inv, oldHashes); err != nil {
			return err
		}
	}
	if err := cleanupJournalFiles(*j); err != nil {
		return err
	}
	for _, f := range j.Files {
		if err := syncDirectory(filepath.Dir(f.Path)); err != nil {
			return err
		}
	}
	path := filepath.Join(inv.LockDir, JournalFilename)
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(inv.LockDir)
}

func validateJournal(inv installstate.Inventory, j journal) error {
	if j.InstallID != inv.ID || len(j.Files) != len(inv.Files) {
		return errors.New("update recovery journal does not match the installation")
	}
	known := make(map[string]installstate.File, len(inv.Files))
	for _, owned := range inv.Files {
		known[owned.Name] = owned
	}
	seen := make(map[string]bool, len(j.Files))
	for _, f := range j.Files {
		owned, ok := known[f.Name]
		if !ok || seen[f.Name] || installstate.ResourcePath(inv, owned) != f.Path {
			return errors.New("update recovery journal contains an unknown program path")
		}
		seen[f.Name] = true
		if filepath.Dir(f.Path) != filepath.Dir(f.Stage) || filepath.Dir(f.Path) != filepath.Dir(f.Backup) || !hasPrefix(filepath.Base(f.Stage), ".peerimeter-update-stage-") || !hasPrefix(filepath.Base(f.Backup), ".peerimeter-update-backup-") {
			return errors.New("update recovery journal contains unsafe temporary paths")
		}
		if !validDigest(f.OldHash) || !validDigest(f.NewHash) {
			return errors.New("update recovery journal contains invalid hashes")
		}
	}
	return nil
}

func writeJournal(path string, j journal) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if err := installstate.WritePrivate(path, append(data, '\n')); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}
func cleanupJournalFiles(j journal) error {
	var errs []error
	for _, f := range j.Files {
		for _, p := range []string{f.Stage, f.Backup} {
			if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}
func hasPrefix(s, prefix string) bool { return len(s) >= len(prefix) && s[:len(prefix)] == prefix }

func knownInventoryFile(inv installstate.Inventory, name string) bool {
	for _, file := range inv.Files {
		if file.Name == name {
			return true
		}
	}
	return false
}
