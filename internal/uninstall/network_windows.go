package uninstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/peerimeter/peerimeter-agent/internal/installstate"
	"golang.org/x/sys/windows"
)

// WireGuardNT adapters created by this process are handle-scoped; stopping the
// service and obtaining its persistent lock establishes that tunnel cleanup has
// completed. Never remove another program's adapter by a cosmetic name, and do
// not call WireGuardDeleteDriver: the installed system driver can be shared.
func cleanupOwnedNetwork(ctx context.Context, _ installstate.Profile) error { return ctx.Err() }

func protectHelperDirectory(path string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, acl, nil)
}
func scheduleRemoval(plan removalPlan) (string, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return "", errors.New("full Windows uninstall requires an elevated administrator terminal")
	}
	// Keep deferred code and diagnostics beneath the already-validated
	// installation parent, outside the tree being removed. A private child ACL
	// alone cannot protect a helper beneath a hostile TEMP ancestor.
	helperParent := filepath.Dir(plan.InstallDir)
	if err := installstate.CheckDirectory(helperParent); err != nil {
		return "", err
	}
	work, err := os.MkdirTemp(helperParent, ".peerimeter-uninstall-")
	if err != nil {
		return "", err
	}
	success := false
	defer func() {
		if !success {
			_ = os.RemoveAll(work)
		}
	}()
	if err := protectHelperDirectory(work); err != nil {
		return "", err
	}
	plan.ResultFile = work + ".result.json"
	pending, _ := json.Marshal(report{State: "pending", Message: "Waiting for the initiating agent process to exit."})
	if err := installstate.WritePrivate(plan.ResultFile, append(pending, '\n')); err != nil {
		return "", err
	}
	planPath := filepath.Join(work, "plan.json")
	scriptPath := filepath.Join(work, "remove.ps1")
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(planPath, data, 0600); err != nil {
		return "", err
	}
	if err := os.WriteFile(scriptPath, []byte(windowsRemovalScript), 0600); err != nil {
		return "", err
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	cmd := exec.Command(filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-Plan", planPath, "-Receipt", plan.ResultFile)
	cmd.SysProcAttr = helperProcessAttributes()
	logPath := work + ".helper.log"
	if err := installstate.WritePrivate(logPath, nil); err != nil {
		return "", err
	}
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return "", err
	}
	defer logFile.Close()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		return "", err
	}
	// Confirm PowerShell parsed/initialized while the parent still owns all
	// removal guards. The helper cannot delete installation data before parent
	// exit, so terminating an uninitialized child leaves managed data untouched.
	ready := false
	// Starting Windows PowerShell can take longer on cold or busy Windows hosts.
	// The helper cannot remove managed files until the parent exits.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var response struct {
			State string `json:"state"`
			Ready bool   `json:"helper_ready"`
		}
		raw, readErr := os.ReadFile(plan.ResultFile)
		if readErr == nil && json.Unmarshal(raw, &response) == nil {
			if response.Ready {
				ready = true
				break
			}
			if response.State == "failed" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		remaining := []string{}
		for _, f := range plan.Files {
			if _, e := os.Lstat(f.Path); e == nil {
				remaining = append(remaining, f.Path)
			}
		}
		for _, path := range []string{plan.Inventory, plan.Lock, plan.DataLock} {
			if path == "" {
				continue
			}
			if _, e := os.Lstat(path); e == nil {
				remaining = append(remaining, path)
			}
		}
		failed, _ := json.Marshal(report{State: "failed", Remaining: remaining, Message: "Removal helper could not initialize; managed files were preserved. Inspect the sibling .helper.log for the cause."})
		_ = installstate.WritePrivate(plan.ResultFile, append(failed, '\n'))
		return "", fmt.Errorf("Windows removal helper could not initialize; installation remains incomplete; inspect %s and %s", plan.ResultFile, logPath)
	}
	// No inherited output pipes tie the helper to the invoking shell.
	_ = cmd.Process.Release()
	success = true
	return plan.ResultFile, nil
}

const windowsRemovalScript = `param([Parameter(Mandatory=$true)][string]$Plan,[Parameter(Mandatory=$true)][string]$Receipt)
$ErrorActionPreference = 'Stop'
trap {
    try { [IO.File]::WriteAllText($Receipt,(@{state='failed';remaining=@($Plan);message=$_.Exception.Message} | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false)) } catch {}
    exit 1
}
$p = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$work = Split-Path -Parent $Plan
$handles = [Collections.Generic.List[IO.FileStream]]::new()
$removed = [Collections.Generic.List[string]]::new()
$state = 'failed'; $message = ''; $remaining = @()
$watch = [Diagnostics.Stopwatch]::StartNew()
function Exists([string]$Path) { return [IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path) }
function No-Reparse([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'An owned resource became a reparse point' }
}
function Remove-Leaf([string]$Path) {
    while (Exists $Path) {
        No-Reparse $Path
        if (Test-Path -LiteralPath $Path -PathType Container) { throw 'An owned file became a directory' }
        try { Remove-Item -LiteralPath $Path -Force; $removed.Add($Path); return } catch {
            if ($watch.Elapsed.TotalSeconds -ge 45) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}
function File-SHA256([string]$Path) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
    finally { $stream.Dispose(); $algorithm.Dispose() }
}
function Lock-Existing([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return }
    No-Reparse $Path
    $f = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try { $f.Lock(0,1) } catch { $f.Dispose(); throw 'A manager or installer is still using the recorded resources' }
    $handles.Add($f)
}
try {
    [IO.File]::WriteAllText($Receipt,(@{state='pending';helper_ready=$true;remaining=@()} | ConvertTo-Json),[Text.UTF8Encoding]::new($false))
    $parent = Get-Process -Id $p.parent_pid -ErrorAction SilentlyContinue
    if ($parent -and -not $parent.WaitForExit(30000)) { throw 'Initiating agent did not exit within 30 seconds; files preserved' }
    Lock-Existing $p.lock
    if ($p.data_lock) { Lock-Existing $p.data_lock }
    foreach ($profile in $p.profiles) {
        if (Test-Path -LiteralPath $profile.state_dir) {
            No-Reparse $profile.state_dir
            $markerPath = Join-Path $profile.state_dir '.peerimeter-agent.profile'
            if (Test-Path -LiteralPath $markerPath) {
                No-Reparse $markerPath
                $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json
                if ($marker.installation_id -ne $p.installation_id -or $marker.profile_id -ne $profile.id) { throw 'Profile ownership changed before deferred removal' }
            }
            Lock-Existing (Join-Path $profile.state_dir 'agent.lock')
        }
    }
    # Recheck all immutable program hashes before deleting any installation data.
    foreach ($f in $p.files) {
        if (Exists $f.path) {
            No-Reparse $f.path
            if ($f.sha256 -and (File-SHA256 $f.path) -ne $f.sha256) { throw 'Inventoried program changed before deferred removal' }
        }
    }
    foreach ($f in $p.files) {
        if ($f.marker -or [IO.Path]::GetFileName($f.path) -eq 'agent.lock') { continue }
        Remove-Leaf $f.path
    }
    # Delete the coordination names while their exclusive ranges remain held.
    # FILE_SHARE_DELETE makes deletion pending, so new openers cannot replace a
    # live manager's lock between guard release and unlink.
    foreach ($f in $p.files) { if ([IO.Path]::GetFileName($f.path) -eq 'agent.lock') { Remove-Leaf $f.path } }
    foreach ($f in $p.files) { if ($f.marker) { Remove-Leaf $f.path } }
    Remove-Leaf $p.lock
    if ($p.data_lock) { Remove-Leaf $p.data_lock }
    Remove-Leaf $p.inventory
    foreach ($h in $handles) { $h.Dispose() }; $handles.Clear()
    foreach ($dir in $p.directories) {
        if (Test-Path -LiteralPath $dir) {
            No-Reparse $dir
            if (@(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) { Remove-Item -LiteralPath $dir -Force }
        }
    }
    $state = 'removed'
} catch { $message = $_.Exception.Message }
finally {
    foreach ($h in $handles) { $h.Dispose() }
    foreach ($f in $p.files) { if (Exists $f.path) { $remaining += $f.path } }
    foreach ($f in @($p.inventory,$p.lock,$p.data_lock)) { if ($f -and (Exists $f)) { $remaining += $f } }
    try { Remove-Item -LiteralPath $Plan -Force; Remove-Item -LiteralPath $PSCommandPath -Force; Remove-Item -LiteralPath $work -Force } catch {
        $state = 'failed'; $remaining += $work; $message += ' Temporary helper cleanup was incomplete.'
    }
    if ($remaining.Count -ne 0) { $state = 'failed' }
    $removed.Sort()
    $result = @{state=$state;paths=@($removed.ToArray());remaining=@($remaining);message=$message} | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($p.result_file,$result,[Text.UTF8Encoding]::new($false))
}
`
