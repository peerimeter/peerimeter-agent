package uninstall

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"

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
	work, err := os.MkdirTemp("", "peerimeter-uninstall-")
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
	cmd := exec.Command(filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-Plan", planPath)
	cmd.SysProcAttr = helperProcessAttributes()
	if err := cmd.Start(); err != nil {
		return "", err
	}
	// No inherited pipe handles tie the helper to CLI output. The helper has a
	// bounded deadline and communicates only through its private receipt file.
	_ = cmd.Process.Release()
	success = true
	return plan.ResultFile, nil
}

const windowsRemovalScript = `param([Parameter(Mandatory=$true)][string]$Plan)
$ErrorActionPreference = 'Stop'
$p = Get-Content -LiteralPath $Plan -Raw | ConvertFrom-Json
$work = Split-Path -Parent $Plan
$handles = [Collections.Generic.List[IO.FileStream]]::new()
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
        try { Remove-Item -LiteralPath $Path -Force; return } catch {
            if ($watch.Elapsed.TotalSeconds -ge 45) { throw }
            Start-Sleep -Milliseconds 200
        }
    }
}
function Lock-Existing([string]$Path) {
    if (-not [IO.File]::Exists($Path)) { return }
    No-Reparse $Path
    $f = [IO.FileStream]::new($Path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    try { $f.Lock(0,1) } catch { $f.Dispose(); throw 'A manager or installer is still using the recorded resources' }
    $handles.Add($f)
}
try {
    $parent = Get-Process -Id $p.parent_pid -ErrorAction SilentlyContinue
    if ($parent -and -not $parent.WaitForExit(30000)) { throw 'Initiating agent did not exit within 30 seconds; files preserved' }
    Lock-Existing $p.lock
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
            if ($f.sha256 -and (Get-FileHash -LiteralPath $f.path -Algorithm SHA256).Hash -ne $f.sha256) { throw 'Inventoried program changed before deferred removal' }
        }
    }
    foreach ($f in $p.files) {
        if ($f.marker -or [IO.Path]::GetFileName($f.path) -eq 'agent.lock') { continue }
        Remove-Leaf $f.path
    }
    foreach ($h in $handles) { $h.Dispose() }; $handles.Clear()
    foreach ($f in $p.files) { if ([IO.Path]::GetFileName($f.path) -eq 'agent.lock') { Remove-Leaf $f.path } }
    foreach ($f in $p.files) { if ($f.marker) { Remove-Leaf $f.path } }
    Remove-Leaf $p.lock
    Remove-Leaf $p.inventory
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
    foreach ($f in @($p.inventory,$p.lock)) { if (Exists $f) { $remaining += $f } }
    try { Remove-Item -LiteralPath $Plan -Force; Remove-Item -LiteralPath $PSCommandPath -Force; Remove-Item -LiteralPath $work -Force } catch {
        $state = 'failed'; $remaining += $work; $message += ' Temporary helper cleanup was incomplete.'
    }
    if ($remaining.Count -ne 0) { $state = 'failed' }
    $result = @{state=$state;remaining=@($remaining);message=$message} | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($p.result_file,$result,[Text.UTF8Encoding]::new($false))
}
`
