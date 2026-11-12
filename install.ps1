param(
    [string]$Version = 'latest',
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'Peerimeter'),
    [string]$Archive,
    [string]$SHA256,
    [switch]$AllowInsecureInstallDir
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run the Windows installer from an elevated administrator terminal' }
if ($InstallDir -notmatch '^[A-Za-z]:[\\/]') { throw 'InstallDir must be an absolute local drive path' }
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$arch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
$arch = switch ($arch) { 'x64' { 'amd64' } 'arm64' { 'arm64' } default { throw 'Unsupported architecture' } }

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
Assert-InstallerAncestors $InstallDir
$work = Join-Path ([IO.Path]::GetTempPath()) ('peerimeter-install-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
Set-InstallerACL $work $true
try {
    if (-not $Archive) {
        $repo = 'https://api.github.com/repos/peerimeter/peerimeter-agent'
        if ($Version -eq 'latest') { $Version = (Invoke-RestMethod "$repo/releases/latest").tag_name }
        if (-not $Version.StartsWith('v')) { $Version = 'v' + $Version }
        if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$') { throw 'Invalid release version' }
        $assetArch = switch ($arch) { 'amd64' { 'x86_64' } 'arm64' { 'aarch64' } }
        $asset = "peerimeter-agent-windows-$assetArch.zip"
        $base = "https://github.com/peerimeter/peerimeter-agent/releases/download/$Version"
        $Archive = Join-Path $work 'package.zip'
        Invoke-WebRequest "$base/$asset" -OutFile $Archive
        $checksums = (Invoke-WebRequest "$base/SHA256SUMS").Content
        $matches = @($checksums -split "`n" | Where-Object { $_.Trim() -match ('^[a-fA-F0-9]{64}\s+' + [regex]::Escape($asset) + '$') })
        if ($matches.Count -ne 1) { throw 'Missing or ambiguous release checksum' }
        $SHA256 = ($matches[0].Trim() -split '\s+')[0]
    }
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
    $dll = Join-Path $unpacked 'wireguard.dll'
    $dllHash = switch ($arch) { 'amd64' { 'B1B85E072C45D81358BE29D94C599DC76652F912BE8C0F0A41E2D5D89A6461D3' } 'arm64' { '75BCDC025D6C00E8315AF5D62B869D760CA6A253FC82D70F146E789F059A3E0C' } }
    if ((Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash -ne $dllHash -or (Get-AuthenticodeSignature -LiteralPath $dll).Status -ne 'Valid') { throw 'Bundled WireGuardNT integrity/signature verification failed' }
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    if ((Get-Item -LiteralPath $InstallDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'InstallDir must not be a reparse point' }
    # Construct a fresh DACL: icacls /grant:r alone would retain unrelated
    # explicit access entries from an existing directory.
    Set-InstallerACL $InstallDir
    $moved = @(); $installed = @(); $staged = @()
    try {
        # Stage and protect the complete package before replacing any old file.
        foreach ($name in $wanted) {
            $next = (Join-Path $InstallDir $name) + '.new-' + [guid]::NewGuid()
            $staged += $next
            Copy-Item -LiteralPath (Join-Path $unpacked $name) -Destination $next
            Set-InstallerACL $next
        }
        for ($i=0; $i -lt $wanted.Count; $i++) {
            $dest = Join-Path $InstallDir $wanted[$i]
            if (Test-Path -LiteralPath $dest) {
                if ((Get-Item -LiteralPath $dest -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installed package member must not be a reparse point' }
                $backup = $dest + '.old-' + [guid]::NewGuid()
                Move-Item -LiteralPath $dest -Destination $backup
                $moved += ,@($backup,$dest)
            }
            Move-Item -LiteralPath $staged[$i] -Destination $dest
            $installed += $dest
        }
        $registerArgs = @('register-installation','--install-dir',$InstallDir)
        if ($AllowInsecureInstallDir) { $registerArgs += '--allow-insecure-install-dir' }
        & (Join-Path $InstallDir 'peerimeter-agent.exe') @registerArgs | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $InstallDir '.peerimeter-agent.install.json') -PathType Leaf)) { throw 'Installation inventory registration failed' }
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
    Write-Output "Installed $InstallDir (windows/$arch). Config and services are managed separately."
} finally { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
