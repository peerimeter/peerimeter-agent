package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"github.com/peerimeter/peerimeter-agent/internal/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const windowsServiceName = "PeerimeterAgent"

// serviceSecureObject requires machine-owned resources before registering a
// LocalSystem service. Installing a service over a user-writable config, key or
// executable directory would elevate that user's later modifications.
func serviceSecureObject(path string, directory, private bool) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errors.New("Windows service resource path is invalid")
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	h, err := windows.CreateFile(path16, windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return errors.New("Windows service resource cannot be inspected; provision protected machine-owned config, key and installation directories first")
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		return errors.New("Windows service resources must not be symbolic links or reparse points")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("Windows service resource security descriptor is unavailable")
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	// Windows protects Program Files and some volume roots with TrustedInstaller.
	installer, _ := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	trusted := func(sid *windows.SID) bool {
		return sid != nil && sid.IsValid() && (sid.Equals(system) || sid.Equals(admins) || sid.Equals(installer))
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return errors.New("Windows service resource owner must be SYSTEM or Administrators")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("Windows service resource requires a restrictive DACL")
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return errors.New("Windows service resource ACL cannot be inspected")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("Windows service resource has an unsupported ACL entry")
		}
		if trusted((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			continue
		}
		mask := uint32(ace.Mask)
		const readOnly = windows.GENERIC_READ | windows.GENERIC_EXECUTE | windows.READ_CONTROL | windows.SYNCHRONIZE |
			windows.FILE_READ_DATA | windows.FILE_READ_ATTRIBUTES | windows.FILE_READ_EA | windows.FILE_EXECUTE
		allowedMask := uint32(readOnly)
		// Windows volume roots and ProgramData normally allow unprivileged
		// identities to create new children, while ownership/DELETE_CHILD and
		// existing protected child ACLs prevent replacement of installed paths.
		clean := filepath.Clean(path)
		if directory && !private && (filepath.Dir(clean) == clean || strings.EqualFold(clean, filepath.Clean(os.Getenv("ProgramData")))) {
			allowedMask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
		}
		if mask != 0 && (private || mask&^allowedMask != 0) {
			return errors.New("Windows service resources must not grant write access outside SYSTEM/Administrators; private key and state must grant no other access")
		}
	}
	return nil
}

func serviceArguments(cfg Config) []string {
	args := []string{"run", "--config", cfg.ConfigPath, "--state-dir", cfg.StateDirectory, "--runtime-dir", serviceRuntime(cfg), "--config-dir", snapshotDirectory(cfg)}
	if cfg.Operator != "" {
		args = append(args, "--operator", cfg.Operator)
	}
	return args
}

func waitWindowsService(s *mgr.Service, wanted svc.State) error {
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		status, err := s.Query()
		if err != nil {
			return err
		}
		if status.State == wanted {
			return nil
		}
		if wanted == svc.Running && status.State == svc.Stopped {
			return fmt.Errorf("Windows service exited before running (exit code %d)", status.Win32ExitCode)
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("Windows service did not reach the requested state within 45 seconds")
}

func stopWindowsService(s *mgr.Service) error {
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
			return err
		}
	}
	return waitWindowsService(s, svc.Stopped)
}

func nativeManage(action string, cfg Config) error {
	manager, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Windows Service Control Manager (administrator privileges required): %w", err)
	}
	defer manager.Disconnect()
	if action == "install" {
		exe, err := os.Executable()
		if err != nil {
			return errors.New("cannot locate Windows agent executable")
		}
		for _, path := range []string{exe, cfg.ConfigPath, cfg.StateDirectory} {
			if err := serviceSecureAncestors(path); err != nil {
				return err
			}
		}
		static, err := config.Load(cfg.ConfigPath)
		if err != nil {
			return err
		}
		for _, object := range []struct {
			path      string
			directory bool
			private   bool
		}{
			{filepath.Dir(exe), true, false}, {exe, false, false},
			{filepath.Dir(cfg.ConfigPath), true, false}, {cfg.ConfigPath, false, false},
			{filepath.Dir(static.Interface.PrivateKeyFile), true, true}, {static.Interface.PrivateKeyFile, false, true},
			{cfg.StateDirectory, true, true},
		} {
			if err := serviceSecureObject(object.path, object.directory, object.private); err != nil {
				return err
			}
		}
		s, err := manager.CreateService(windowsServiceName, exe, mgr.Config{
			DisplayName: "Peerimeter Agent", Description: "Offline static WireGuard mesh agent",
			StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
			ServiceStartName: "LocalSystem", Dependencies: []string{"Tcpip"},
		}, serviceArguments(cfg)...)
		if err != nil {
			return fmt.Errorf("install Windows agent service: %w", err)
		}
		defer s.Close()
		if err := s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 5 * time.Second}, {Type: mgr.ServiceRestart, Delay: 15 * time.Second}, {Type: mgr.ServiceRestart, Delay: 30 * time.Second}}, 24*60*60); err != nil {
			_ = s.Delete()
			return fmt.Errorf("configure Windows service restart policy: %w", err)
		}
		if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
			_ = s.Delete()
			return fmt.Errorf("configure Windows service failure policy: %w", err)
		}
		return nil
	}
	s, err := manager.OpenService(windowsServiceName)
	if err != nil {
		return fmt.Errorf("open Windows agent service: %w", err)
	}
	defer s.Close()
	switch action {
	case "start":
		if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return fmt.Errorf("start Windows agent service: %w", err)
		}
		return waitWindowsService(s, svc.Running)
	case "stop":
		return stopWindowsService(s)
	case "uninstall":
		if err := stopWindowsService(s); err != nil {
			return err
		}
		// Service deletion deliberately preserves static config and private keys.
		return s.Delete()
	default:
		return errors.New("unsupported Windows service action")
	}
}

type windowsHandler struct {
	ctx context.Context
	run func(context.Context) error
}

func (h windowsHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(h.ctx)
	defer cancel()
	statuses <- svc.Status{State: svc.StartPending, WaitHint: 15000}
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- current
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var stopping <-chan time.Time
	parentDone := h.ctx.Done()
	for {
		select {
		case err := <-done:
			if err != nil {
				slog.Error("Windows service agent stopped", "error", err)
				return true, 1
			}
			return false, 0
		case request, ok := <-requests:
			if !ok {
				cancel()
				requests = nil
				continue
			}
			switch request.Cmd {
			case svc.Interrogate:
				statuses <- current
			case svc.Stop, svc.Shutdown:
				if stopping == nil {
					cancel()
					current = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 20000}
					statuses <- current
					stopping = time.After(40 * time.Second)
				}
			}
		case <-parentDone:
			parentDone = nil
			cancel()
			if stopping == nil {
				current = svc.Status{State: svc.StopPending, CheckPoint: 1, WaitHint: 20000}
				statuses <- current
				stopping = time.After(40 * time.Second)
			}
		case <-ticker.C:
			if current.State == svc.StopPending {
				current.CheckPoint++
				statuses <- current
			}
		case <-stopping:
			slog.Error("Windows service cleanup exceeded 40 seconds")
			return true, 2
		}
	}
}

// Dispatch joins SCM only for an actual service process. Ordinary foreground
// commands continue through the CLI. Stop/Shutdown cancels the same runtime
// context and waits for tunnel teardown before reporting service completion.
func Dispatch(ctx context.Context, run func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, err
	}
	return true, svc.Run(windowsServiceName, windowsHandler{ctx: ctx, run: run})
}

// nativeSecureFiles provisions installer-owned copies, never the operator's
// originals. Callers include the state directory itself to prevent replacement
// of protected children through a user-writable parent.
func nativeSecureFiles(paths ...string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return errors.New("resolve Windows Administrators identity")
	}
	for _, path := range paths {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return errors.New("invalid protected Windows service path")
		}
		h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return fmt.Errorf("secure Windows service resources (administrator privileges required): %w", err)
		}
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 && info.NumberOfLinks != 1 {
			windows.CloseHandle(h)
			return errors.New("refuse links in protected Windows service resources")
		}
		aceFlags := ""
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
			aceFlags = "OICI"
		}
		sd, err := windows.SecurityDescriptorFromString("D:P(A;" + aceFlags + ";FA;;;SY)(A;" + aceFlags + ";FA;;;BA)")
		if err != nil {
			windows.CloseHandle(h)
			return errors.New("construct protected Windows service ACL")
		}
		dacl, _, err := sd.DACL()
		if err == nil {
			err = windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, admins, nil, dacl, nil)
		}
		windows.CloseHandle(h)
		if err != nil {
			return fmt.Errorf("set machine-owned Windows service ACL (administrator privileges required): %w", err)
		}
	}
	return nil
}

func nativeRequireAdmin() error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return errors.New("cannot inspect Windows administrator identity")
	}
	member, err := windows.Token(0).IsMember(admins)
	if err != nil || !member || !windows.GetCurrentProcessToken().IsElevated() {
		return errors.New("Windows service installation requires an elevated administrator terminal")
	}
	return nil
}

// serviceSecureAncestors rejects junctions and user-controlled directories in
// the persistent SCM executable/config/state paths, not only final components.
func serviceSecureAncestors(path string) error {
	if strings.HasPrefix(filepath.VolumeName(path), `\\`) {
		return errors.New("Windows service resources require local machine storage")
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if _, err := os.Lstat(parent); err == nil {
			if err := serviceSecureObject(parent, true, false); err != nil {
				return errors.Join(errors.New("Windows service ancestor directory is not trusted"), err)
			}
		} else if !os.IsNotExist(err) {
			return errors.New("cannot inspect Windows service ancestor directory")
		}
		if next := filepath.Dir(parent); next == parent {
			return nil
		}
	}
}

func nativeValidateStatePath(path string) error {
	if !filepath.IsAbs(path) || strings.HasPrefix(filepath.VolumeName(path), `\\`) {
		return errors.New("Windows service state requires an absolute local machine path")
	}
	if _, err := os.Lstat(path); err == nil {
		if err := serviceSecureObject(path, true, false); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return errors.New("cannot inspect Windows service state directory")
	}
	return serviceSecureAncestors(path)
}

func validateLegacySnapshot(path string) error { return serviceSecureObject(path, false, true) }
func RemoveOwned(ctx context.Context, expectedExe string, cfg Config) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	registered, err := manager.OpenService(windowsServiceName)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer registered.Close()
	settings, err := registered.Config()
	if err != nil {
		return err
	}
	arguments, err := windows.DecomposeCommandLine(settings.BinaryPathName)
	if err != nil {
		return err
	}
	if err := verifyServiceArguments(arguments, expectedExe, cfg); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := stopWindowsService(registered); err != nil {
		return err
	}
	return registered.Delete()
}

func HasOwnedRegistration(ctx context.Context, expectedExe string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, err
	}
	defer windows.CloseServiceHandle(manager)
	name, err := windows.UTF16PtrFromString(windowsServiceName)
	if err != nil {
		return false, err
	}
	handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	registered := &mgr.Service{Name: windowsServiceName, Handle: handle}
	defer registered.Close()
	settings, err := registered.Config()
	if err != nil {
		return false, err
	}
	return windowsRegistrationUsesExecutable(settings.BinaryPathName, expectedExe)
}
func windowsRegistrationUsesExecutable(command, expectedExe string) (bool, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return false, errors.New("Windows service executable registration is empty")
	}
	if !strings.HasPrefix(command, `"`) {
		fields := strings.Fields(command)
		if len(fields) == 0 || !strings.HasSuffix(strings.ToLower(fields[0]), ".exe") {
			return false, errors.New("ambiguous unquoted Windows service executable; program files were preserved")
		}
	}
	if strings.HasPrefix(command, `"`) {
		end := strings.Index(command[1:], `"`)
		if end < 0 {
			return false, errors.New("unterminated Windows service executable registration")
		}
		end++
		if end+1 < len(command) && command[end+1] != ' ' && command[end+1] != '\t' {
			return false, errors.New("ambiguous Windows service executable quoting")
		}
	}
	arguments, err := windows.DecomposeCommandLine(command)
	if err != nil || len(arguments) == 0 || !filepath.IsAbs(arguments[0]) {
		return false, errors.New("cannot inspect exact Windows service executable registration")
	}
	return equalServicePath(arguments[0], expectedExe), nil
}
