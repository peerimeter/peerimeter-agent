package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
)

const JournalFilename = ".update-journal.json"

// TODO(next major): remove recovery and locking support for the former filenames.
const LegacyJournalFilename = ".peerimeter-agent.update-journal.json"
const UpdateLockFilename = ".update.lock"
const LegacyUpdateLockFilename = ".peerimeter-agent.update.lock"

// LockUpdate owns an update transaction across inventory-lock release windows
// such as service restart and readiness verification.
func LockUpdate(inv installstate.Inventory) (io.Closer, error) {
	lock, err := installstate.LockNamed(inv.LockDir, UpdateLockFilename, inv.AllowInsecureInstallDir)
	if err != nil {
		return nil, err
	}
	locks := lockGroup{lock}
	// TODO(next major): remove locking compatibility for the previous filename.
	legacyPath := filepath.Join(inv.LockDir, LegacyUpdateLockFilename)
	if _, err := os.Lstat(legacyPath); err == nil {
		legacyLock, lockErr := installstate.LockNamed(inv.LockDir, LegacyUpdateLockFilename, inv.AllowInsecureInstallDir)
		if lockErr != nil {
			_ = locks.Close()
			return nil, lockErr
		}
		locks = append(locks, legacyLock)
	} else if !os.IsNotExist(err) {
		_ = locks.Close()
		return nil, err
	}
	return locks, nil
}

func FindJournal(inv installstate.Inventory) (string, bool, error) {
	for _, name := range []string{JournalFilename, LegacyJournalFilename} {
		path := filepath.Join(inv.LockDir, name)
		if _, err := os.Lstat(path); err == nil {
			return path, true, nil
		} else if !os.IsNotExist(err) {
			return "", false, err
		}
	}
	return filepath.Join(inv.LockDir, JournalFilename), false, nil
}

type lockGroup []io.Closer

func (g lockGroup) Close() error {
	var result error
	for i := len(g) - 1; i >= 0; i-- {
		if err := g[i].Close(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

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
// private recovery journal, then replaces files. The caller must hold both
// the update ownership lock and installstate lock through hash recording.
func Apply(inv installstate.Inventory, packageFiles map[string][]byte) (map[string]string, func() error, func() error, error) {
	if len(packageFiles) != len(inv.Files) {
		return nil, nil, nil, errors.New("release package does not match the installed program file inventory")
	}
	for name := range packageFiles {
		if !inv.HasFile(name) {
			return nil, nil, nil, fmt.Errorf("release package contains unowned file %q", name)
		}
	}
	journalPath := filepath.Join(inv.LockDir, JournalFilename)
	for _, name := range []string{JournalFilename, LegacyJournalFilename} {
		if _, err := os.Lstat(filepath.Join(inv.LockDir, name)); err == nil {
			return nil, nil, nil, errors.New("an interrupted update must be recovered before starting another update")
		} else if !os.IsNotExist(err) {
			return nil, nil, nil, err
		}
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
		file, err := stageAndBackupProgramFile(inv, owned, packageFiles[owned.Name])
		if err != nil {
			cleanupStages()
			return nil, nil, nil, err
		}
		sum := sha256.Sum256(packageFiles[owned.Name])
		hashes[owned.Name] = hex.EncodeToString(sum[:])
		file.NewHash = hashes[owned.Name]
		j.Files = append(j.Files, file)
	}
	if err := writeJournal(journalPath, j); err != nil {
		cleanupStages()
		return nil, nil, nil, err
	}
	rollback := func() error {
		current, err := installstate.Load(inv.InstallDir)
		if err != nil {
			return err
		}
		return recoverJournal(current, journalPath, &j)
	}
	for _, f := range j.Files {
		if err := replaceFile(f.Stage, f.Path); err != nil {
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
		return finalizeCommittedJournal(inv, journalPath, j)
	}
	return hashes, rollback, commit, nil
}

func stageAndBackupProgramFile(inv installstate.Inventory, owned installstate.File, data []byte) (journalFile, error) {
	path := installstate.ResourcePath(inv, owned)
	if err := installstate.CheckDirectory(filepath.Dir(path)); err != nil {
		return journalFile{}, fmt.Errorf("inspect installed %s directory: %w", owned.Name, err)
	}
	if err := installstate.CheckFile(path); err != nil {
		return journalFile{}, fmt.Errorf("inspect installed %s: %w", owned.Name, err)
	}
	oldHash, err := installstate.Hash(path)
	if err != nil {
		return journalFile{}, err
	}
	if oldHash != owned.SHA256 {
		return journalFile{}, fmt.Errorf("installed %s was modified; refusing to overwrite it", owned.Name)
	}
	info, err := os.Stat(path)
	if err != nil {
		return journalFile{}, err
	}
	stagePath, err := stageUpdateFile(path, info, data)
	if err != nil {
		return journalFile{}, err
	}
	backupPath, err := createBackup(path, info, oldHash)
	if err != nil {
		_ = os.Remove(stagePath)
		return journalFile{}, err
	}
	return journalFile{Name: owned.Name, Path: path, Stage: stagePath, Backup: backupPath, OldHash: oldHash}, nil
}

func finalizeCommittedJournal(inv installstate.Inventory, journalPath string, j journal) error {
	if err := cleanupJournalFiles(j); err != nil {
		return err
	}
	for _, file := range j.Files {
		if err := syncDirectory(filepath.Dir(file.Path)); err != nil {
			return err
		}
	}
	if err := os.Remove(journalPath); err != nil {
		return err
	}
	return syncDirectory(inv.LockDir)
}

func stageUpdateFile(targetPath string, info os.FileInfo, data []byte) (string, error) {
	return writeTempSiblingFile(targetPath, ".peerimeter-update-stage-*", info, func(writer io.Writer) error {
		_, err := writer.Write(data)
		return err
	})
}

func createBackup(path string, info os.FileInfo, expectedHash string) (string, error) {
	backupPath, err := writeTempSiblingFile(path, ".peerimeter-update-backup-*", info, func(writer io.Writer) error {
		source, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(writer, source)
		return errors.Join(copyErr, source.Close())
	})
	if err != nil {
		return "", err
	}
	digest, err := installstate.Hash(backupPath)
	if err != nil || digest != expectedHash {
		_ = os.Remove(backupPath)
		if err != nil {
			return "", err
		}
		return "", errors.New("installed program changed while preparing its update backup")
	}
	return backupPath, nil
}

func writeTempSiblingFile(targetPath, prefix string, info os.FileInfo, writeFn func(io.Writer) error) (string, error) {
	file, err := os.CreateTemp(filepath.Dir(targetPath), prefix)
	if err != nil {
		return "", err
	}
	tempPath := file.Name()
	cleanup := func(cause error) (string, error) {
		_ = file.Close()
		_ = os.Remove(tempPath)
		return "", cause
	}
	if err := file.Chmod(info.Mode().Perm()); err != nil {
		return cleanup(err)
	}
	if err := setFileOwner(file, info); err != nil {
		return cleanup(err)
	}
	if err := writeFn(file); err != nil {
		return cleanup(err)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	if err := installstate.CheckFile(tempPath); err != nil {
		_ = os.Remove(tempPath)
		return "", err
	}
	return tempPath, nil
}

// RecoverLocked completes cleanup after a committed update or restores the
// previous files after an interrupted transaction. The caller holds both the
// update ownership lock and installstate lock; profile paths are preserved.
func RecoverLocked(inv installstate.Inventory) error {
	path := filepath.Join(inv.LockDir, JournalFilename)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		// TODO(next major): remove recovery of the previous update journal filename.
		path = filepath.Join(inv.LockDir, LegacyJournalFilename)
	}
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
		return finalizeCommittedJournal(inv, path, j)
	}
	if err := recoverJournal(inv, path, &j); err != nil {
		return err
	}
	return nil
}

func recoverJournal(inv installstate.Inventory, path string, j *journal) error {
	if err := validateJournal(inv, *j); err != nil {
		return err
	}
	var failures []error
	oldHashes := make(map[string]string, len(j.Files))
	for i := len(j.Files) - 1; i >= 0; i-- {
		f := j.Files[i]
		oldHashes[f.Name] = f.OldHash
		if isManagedAliasSymlink(f.Path) {
			_ = os.Remove(f.Backup)
			_ = os.Remove(f.Stage)
			continue
		}
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
	if len(oldHashes) != len(inv.Files) {
		return errors.New("update recovery journal is incomplete")
	}
	for _, f := range j.Files {
		if err := syncDirectory(filepath.Dir(f.Path)); err != nil {
			return err
		}
	}
	if err := installstate.UpdateProgramHashesLocked(inv, oldHashes); err != nil {
		return err
	}
	if err := cleanupJournalFiles(*j); err != nil {
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
		if err := installstate.CheckDirectory(filepath.Dir(f.Path)); err != nil {
			return fmt.Errorf("unsafe update recovery directory: %w", err)
		}
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
