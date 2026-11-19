param(
    [string]$Version = 'latest',
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Peerimeter'),
    [string]$DocDir,
    [string]$DataDir,
    [string]$LockDir,
    [string]$Archive,
    [string]$SHA256
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Write-InstallerProgress([string]$Message) {
    Write-Host "Peerimeter installer: $Message"
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run the Windows installer from an elevated administrator terminal' }
if ($InstallDir -notmatch '^[A-Za-z]:[\\/]') { throw 'InstallDir must be an absolute local drive path' }
if ($InstallDir.Contains(';')) { throw 'InstallDir must not contain a semicolon' }
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$aliasPath = Join-Path $InstallDir 'pma.cmd'
$legacyAliasPath = Join-Path $InstallDir 'pma.exe'
$agentPath = Join-Path $InstallDir 'peerimeter-agent.exe'
$expectedAlias = "@echo off`r`nsetlocal DisableDelayedExpansion`r`n`"%~dp0peerimeter-agent.exe`" %*`r`nexit /b %ERRORLEVEL%`r`n"
if (Test-Path -LiteralPath $aliasPath) {
    $aliasItem = Get-Item -LiteralPath $aliasPath -Force
    if ($aliasItem.PSIsContainer -or ($aliasItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-Path -LiteralPath $agentPath -PathType Leaf) -or [IO.File]::ReadAllText($aliasPath) -ne $expectedAlias) {
        throw 'pma.cmd destination already exists and is not a managed Peerimeter alias'
    }
}
if (Test-Path -LiteralPath $legacyAliasPath) {
    $legacyAliasItem = Get-Item -LiteralPath $legacyAliasPath -Force
    if ($legacyAliasItem.PSIsContainer -or ($legacyAliasItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or -not (Test-Path -LiteralPath $agentPath -PathType Leaf)) {
        throw 'pma.exe destination already exists and is not a managed legacy Peerimeter alias'
    }
    if ((Get-FileHash -LiteralPath $legacyAliasPath -Algorithm SHA256).Hash -ne (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash) {
        throw 'pma.exe destination already exists and does not match the installed agent'
    }
}
if ([string]::IsNullOrWhiteSpace($DocDir) -or [string]::IsNullOrWhiteSpace($DataDir) -or [string]::IsNullOrWhiteSpace($LockDir)) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $installKey = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($InstallDir.ToLowerInvariant()))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
    $resourceRoot = Join-Path $env:ProgramData (Join-Path 'Peerimeter\Installations' $installKey)
    if ([string]::IsNullOrWhiteSpace($DocDir)) { $DocDir = Join-Path $resourceRoot 'Documentation' }
    if ([string]::IsNullOrWhiteSpace($DataDir)) { $DataDir = Join-Path $resourceRoot 'State' }
    if ([string]::IsNullOrWhiteSpace($LockDir)) { $LockDir = Join-Path $resourceRoot 'Locks' }
}
$DocDir = [IO.Path]::GetFullPath($DocDir)
$DataDir = [IO.Path]::GetFullPath($DataDir)
$LockDir = [IO.Path]::GetFullPath($LockDir)
# RuntimeInformation.OSArchitecture can be null in Windows PowerShell 5.1 on
# older Windows 10/.NET Framework installations. Prefer the OS architecture
# environment variable, which also handles a 32-bit PowerShell on 64-bit OS.
$nativeArch = $env:PROCESSOR_ARCHITEW6432
if ([string]::IsNullOrWhiteSpace($nativeArch)) { $nativeArch = $env:PROCESSOR_ARCHITECTURE }
$arch = switch ($nativeArch.ToUpperInvariant()) { 'AMD64' { 'amd64' } 'X64' { 'amd64' } 'ARM64' { 'arm64' } default { throw 'Unsupported architecture' } }
Write-InstallerProgress "Preparing windows/$arch installation in $InstallDir."

function Set-InstallerACL([string]$Path,[bool]$Private=$false) {
    $isDirectory = Test-Path -LiteralPath $Path -PathType Container
    if ($isDirectory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]::None
    }
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-32-544','S-1-5-18')) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    if (-not $Private) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-InstallerAncestors([string]$Path) {
    $parent = [IO.Directory]::GetParent($Path)
    while ($null -ne $parent) {
        if ($parent.Exists) {
            $item = Get-Item -LiteralPath $parent.FullName -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation ancestor must not be a reparse point' }
        }
        $parent = $parent.Parent
    }
}
function Add-MachinePath([string]$Directory) {
    $mutex = [Threading.Mutex]::new($false,'Global\PeerimeterAgentMachinePath')
    $acquired = $false
    try {
        try { $acquired = $mutex.WaitOne(30000) } catch [Threading.AbandonedMutexException] { $acquired = $true }
        if (-not $acquired) { throw 'Timed out waiting to update the machine PATH' }
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Session Manager\Environment',$true)
        if (-not $key) { throw 'Could not open the machine environment registry key' }
        $changed = $false
        try {
            $old = [string]$key.GetValue('Path','',[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $parts = @($old -split ';')
            if (-not @($parts | Where-Object { [string]::Equals($_.TrimEnd('\'),$Directory.TrimEnd('\'),[StringComparison]::OrdinalIgnoreCase) }).Count) {
                $next = if ([string]::IsNullOrEmpty($old)) { $Directory } else { $old + ';' + $Directory }
                $key.SetValue('Path',$next,$key.GetValueKind('Path'))
                $changed = $true
            }
        } finally { $key.Dispose() }
        if ($changed) {
            if (-not ('PeerimeterEnvironmentNotifier' -as [type])) {
                Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class PeerimeterEnvironmentNotifier { [DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam, uint flags, uint timeout, out IntPtr result); }'
            }
            $result = [IntPtr]::Zero
            [PeerimeterEnvironmentNotifier]::SendMessageTimeout([IntPtr]0xffff,0x001A,[IntPtr]::Zero,'Environment',0x0002,5000,[ref]$result) | Out-Null
        }
    } finally { if ($acquired) { $mutex.ReleaseMutex() }; $mutex.Dispose() }
}
foreach ($path in @($InstallDir,$DocDir,$DataDir,$LockDir)) {
    if ($path -notmatch '^[A-Za-z]:[\\/]') { throw 'All resource directories must be absolute local drive paths' }
    Assert-InstallerAncestors $path
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('peerimeter-install-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
Set-InstallerACL $work $true
try {
    if ($resourceRoot) {
        # Resource folders live below a shared ProgramData tree. Protect the
        # common installation root before creating per-installation children,
        # so a less-privileged user cannot replace their parent directories.
        $installationsRoot = Join-Path $env:ProgramData 'Peerimeter\Installations'
        New-Item -ItemType Directory -Path $installationsRoot -Force | Out-Null
        Set-InstallerACL $installationsRoot $true
        New-Item -ItemType Directory -Path $resourceRoot -Force | Out-Null
        Set-InstallerACL $resourceRoot $true
    }
    if (-not $Archive) {
        Write-InstallerProgress 'Resolving release version and downloading package files.'
        $repo = 'https://api.github.com/repos/peerimeter/peerimeter-agent'
        if ($Version -eq 'latest') { $Version = (Invoke-RestMethod "$repo/releases/latest").tag_name }
        if (-not $Version.StartsWith('v')) { $Version = 'v' + $Version }
        if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$') { throw 'Invalid release version' }
        $assetArch = switch ($arch) { 'amd64' { 'x86_64' } 'arm64' { 'aarch64' } }
        $asset = "peerimeter-agent-windows-$assetArch.zip"
        $base = "https://github.com/peerimeter/peerimeter-agent/releases/download/$Version"
        $Archive = Join-Path $work 'package.zip'
        Invoke-WebRequest "$base/$asset" -OutFile $Archive -UseBasicParsing
        # GitHub serves SHA256SUMS as application/octet-stream. PowerShell 5.1
        # can expose that response as bytes rather than text in .Content.
        $checksumFile = Join-Path $work 'SHA256SUMS'
        Invoke-WebRequest "$base/SHA256SUMS" -OutFile $checksumFile -UseBasicParsing
        $matchingLines = @(Get-Content -LiteralPath $checksumFile -Encoding ASCII | Where-Object { $_.Trim() -match ('^[a-fA-F0-9]{64}\s+' + [regex]::Escape($asset) + '$') })
        if ($matchingLines.Count -ne 1) { throw 'Missing or ambiguous release checksum' }
        $SHA256 = ($matchingLines[0].Trim() -split '\s+')[0]
    }
    Write-InstallerProgress 'Verifying package checksum and contents.'
    if ($SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash -ne $SHA256) { throw 'Package integrity check failed; local archives require -SHA256' }
    $unpacked = Join-Path $work 'unpacked'
    New-Item -ItemType Directory -Path $unpacked | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $wanted = @('peerimeter-agent.exe','wireguard.dll','peerimeter-agent.NOTICES.txt')
        if ($zip.Entries.Count -ne $wanted.Count) { throw 'Unexpected package members' }
        foreach ($entry in $zip.Entries) {
            if ($entry.FullName -notin $wanted -or $entry.Length -gt 128MB) { throw 'Unexpected or oversized package member' }
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Join-Path $unpacked $entry.FullName),$false)
        }
    } finally { $zip.Dispose() }
    [IO.File]::WriteAllText((Join-Path $unpacked 'pma.cmd'),$expectedAlias,[Text.Encoding]::ASCII)
    $dll = Join-Path $unpacked 'wireguard.dll'
    $dllHash = switch ($arch) { 'amd64' { 'B1B85E072C45D81358BE29D94C599DC76652F912BE8C0F0A41E2D5D89A6461D3' } 'arm64' { '75BCDC025D6C00E8315AF5D62B869D760CA6A253FC82D70F146E789F059A3E0C' } }
    if ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash -ne $dllHash -or (Get-AuthenticodeSignature -LiteralPath $dll).Status -ne 'Valid') { throw 'Bundled WireGuardNT integrity/signature verification failed' }
    Write-InstallerProgress 'Preparing protected installation directories.'
    foreach ($directory in @($InstallDir,$DocDir,$DataDir,$LockDir)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        if ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Resource directory must not be a reparse point' }
    }
    # Construct a fresh DACL: icacls /grant:r alone would retain unrelated
    # explicit access entries from an existing directory.
    Set-InstallerACL $InstallDir
    Set-InstallerACL $DocDir
    Set-InstallerACL $DataDir $true
    Set-InstallerACL $LockDir $true
    $packageFiles = @(@{Name='peerimeter-agent.exe';Dir=$InstallDir;Source='peerimeter-agent.exe'},@{Name='pma.cmd';Dir=$InstallDir;Source='pma.cmd'},@{Name='wireguard.dll';Dir=$InstallDir;Source='wireguard.dll'},@{Name='peerimeter-agent.NOTICES.txt';Dir=$DocDir;Source='peerimeter-agent.NOTICES.txt'})
    $moved = @(); $installed = @(); $staged = @()
    try {
        # Stage and protect the complete package before replacing any old file.
        Write-InstallerProgress "Installing package files to $InstallDir."
        foreach ($member in $packageFiles) {
            $next = (Join-Path $member.Dir $member.Name) + '.new-' + [guid]::NewGuid()
            $staged += $next
            Copy-Item -LiteralPath (Join-Path $unpacked $member.Source) -Destination $next
            Set-InstallerACL $next
        }
        if (Test-Path -LiteralPath $legacyAliasPath) {
            $backup = $legacyAliasPath + '.old-' + [guid]::NewGuid()
            Move-Item -LiteralPath $legacyAliasPath -Destination $backup
            $moved += ,@($backup,$legacyAliasPath)
        }
        for ($i=0; $i -lt $packageFiles.Count; $i++) {
            $dest = Join-Path $packageFiles[$i].Dir $packageFiles[$i].Name
            if (Test-Path -LiteralPath $dest) {
                if ((Get-Item -LiteralPath $dest -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installed package member must not be a reparse point' }
                $backup = $dest + '.old-' + [guid]::NewGuid()
                Move-Item -LiteralPath $dest -Destination $backup
                $moved += ,@($backup,$dest)
            }
            Move-Item -LiteralPath $staged[$i] -Destination $dest
            $installed += $dest
        }
        $versionOutput = & (Join-Path $InstallDir 'peerimeter-agent.exe') version --json
        if ($LASTEXITCODE -ne 0) { throw 'Could not determine installed agent version' }
        $installedVersion = ($versionOutput | ConvertFrom-Json).version
        if ([string]::IsNullOrWhiteSpace($installedVersion)) { throw 'Could not determine installed agent version' }
        Write-InstallerProgress 'Registering protected installation inventory.'
        $registerArgs = @('register-installation','--install-dir',$InstallDir,'--doc-dir',$DocDir,'--data-dir',$DataDir,'--lock-dir',$LockDir)
        & (Join-Path $InstallDir 'peerimeter-agent.exe') @registerArgs | Out-Null
        $inventoryPaths = @((Join-Path $DataDir '.install.yaml'),(Join-Path $DataDir '.peerimeter-agent.install.yaml'),(Join-Path $DataDir '.peerimeter-agent.install.json'))
        $inventoryFound = $false
        foreach ($inventoryPath in $inventoryPaths) {
            if (Test-Path -LiteralPath $inventoryPath) {
                $inventoryItem = Get-Item -LiteralPath $inventoryPath -Force
                if ($inventoryItem.PSIsContainer -or ($inventoryItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Installation inventory registration failed' }
                $inventoryFound = $true
            }
        }
        if ($LASTEXITCODE -ne 0 -or -not $inventoryFound) { throw 'Installation inventory registration failed' }
        foreach ($referencePath in @((Join-Path $InstallDir '.install.ref'),(Join-Path $InstallDir '.peerimeter-agent.install.ref'))) {
            if ((Test-Path -LiteralPath $referencePath) -and ((Get-Item -LiteralPath $referencePath -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Installation reference is invalid' }
        }
    } catch {
        $failure = $_
        $rollbackErrors = @()
        foreach ($path in $installed) {
            try { Remove-Item -LiteralPath $path -Force } catch { $rollbackErrors += $_ }
        }
        for ($i=$moved.Count-1; $i -ge 0; $i--) {
            try { Move-Item -LiteralPath $moved[$i][0] -Destination $moved[$i][1] } catch { $rollbackErrors += $_ }
        }
        if ($rollbackErrors.Count) { throw "Installation failed and rollback was incomplete; preserve .old files for recovery: $failure" }
        throw $failure
    } finally {
        foreach ($path in $staged) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } }
    }
    foreach ($pair in $moved) { Remove-Item -LiteralPath $pair[0] -Force }
    Add-MachinePath $InstallDir
    Write-Output 'Installation directories:'
    Write-Output "  Install: $InstallDir"
    Write-Output "  Documentation: $DocDir"
    Write-Output "  State: $DataDir"
    Write-Output "  Locks: $LockDir"
    Write-Output "Installed Peerimeter Agent $installedVersion to $InstallDir (windows/$arch). Config and services are managed separately."
} finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
