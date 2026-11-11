param(
    [string]$PackageDirectory,
    [string]$Archive,
    [string]$Installer = (Join-Path $PSScriptRoot '..\..\install.ps1')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Installer = [IO.Path]::GetFullPath($Installer)
$base = Join-Path $env:ProgramFiles ('Peerimeter Installer CI ' + [guid]::NewGuid().ToString('N'))
$offline = Join-Path $base 'offline custom path'
$latest = Join-Path $base 'latest custom path'
$pinned = Join-Path $base 'pinned custom path'
$badTarget = Join-Path $base 'must not install'
$arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) { 'x64' {'amd64'} 'arm64' {'arm64'} default {throw 'Unsupported test architecture'} }
if (-not $Archive) {
    if (-not $PackageDirectory) { throw 'Supply -PackageDirectory or -Archive' }
    $packages = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter "peerimeter-agent_*_windows_${arch}.zip" -File)
    if ($packages.Count -ne 1) { throw 'Expected exactly one native Windows package ZIP' }
    $Archive = $packages[0].FullName
}
$Archive = [IO.Path]::GetFullPath($Archive)
$checksum = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
$asset = "peerimeter-agent_v0.0.0-ci_windows_${arch}.zip"
$global:PeerimeterInstallerFixture = @{
    Archive=$Archive; SHA256=$checksum; Asset=$asset; Requests=[Collections.Generic.List[string]]::new(); FailReplace=$false
}

function Assert-Package([string]$Directory) {
    foreach ($name in @('peerimeter-agent.exe','wireguard.dll','peerimeter-agent.NOTICES.txt')) {
        $path = Join-Path $Directory $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Installed package member missing: $name" }
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') { throw 'Installed package file is not owned by Administrators' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in @('S-1-5-18','S-1-5-32-544')) { continue }
            $allowed = [long][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [long][Security.AccessControl.FileSystemRights]::Synchronize
            if (([long]$rule.FileSystemRights -band (-bnot $allowed)) -ne 0) { throw 'Installed file grants untrusted write access' }
        }
    }
    $binary = Join-Path $Directory 'peerimeter-agent.exe'
    $version = & $binary version | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $version.os -ne 'windows' -or $version.go_version -ne 'go1.27.4') { throw 'Installed native agent executable failed version smoke test' }
    if (@(Get-ChildItem -LiteralPath $Directory -Force | Where-Object { $_.Name -match '\.(new|old)-' }).Count) { throw 'Installer leaked staged or backup files' }
}
function Expect-Failure([scriptblock]$Operation) {
    $failed = $false
    try { & $Operation | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected installer failure did not occur' }
}

try {
    New-Item -ItemType Directory -Path $base | Out-Null
    & $Installer -Archive $Archive -SHA256 $checksum -InstallDir $offline
    Assert-Package $offline
    Write-Output 'PASS offline local ZIP install, custom path with spaces, complete signed WireGuardNT bundle and native CLI'

    # Add a deliberately unsafe explicit grant; an upgrade must construct a
    # fresh directory/file ACL instead of retaining unrelated icacls grants.
    $acl = Get-Acl -LiteralPath $offline
    $everyone = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($everyone)
    Set-Acl -LiteralPath $offline -AclObject $acl
    & $Installer -Archive $Archive -SHA256 $checksum -InstallDir $offline
    Assert-Package $offline
    if (@((Get-Acl -LiteralPath $offline).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -eq 'S-1-1-0' -and $_.AccessControlType -eq 'Allow' }).Count) { throw 'Unsafe explicit directory ACL survived installation' }
    Write-Output 'PASS upgrade removes unrelated explicit write grants'

    Expect-Failure { & $Installer -Archive $Archive -SHA256 ('0'*64) -InstallDir $badTarget }
    if (Test-Path -LiteralPath $badTarget) { throw 'Bad checksum changed installation destination' }
    Write-Output 'PASS checksum rejection precedes installation mutation'

    # Exercise release URL selection against a local, already verified ZIP.
    # These mocks prevent dependence on a release that has not been published.
    function global:Invoke-RestMethod {
        param([string]$Uri)
        $global:PeerimeterInstallerFixture.Requests.Add($Uri)
        if ($Uri -ne 'https://api.github.com/repos/peerimeter/peerimeter-agent/releases/latest') { throw 'Unexpected release API request' }
        return [pscustomobject]@{tag_name='v0.0.0-ci'}
    }
    function global:Invoke-WebRequest {
        param([string]$Uri,[string]$OutFile)
        $fixture = $global:PeerimeterInstallerFixture
        $fixture.Requests.Add($Uri)
        $prefix = 'https://github.com/peerimeter/peerimeter-agent/releases/download/v0.0.0-ci/'
        if ($Uri -eq ($prefix+$fixture.Asset)) {
            if (-not $OutFile) { throw 'Archive request omitted output path' }
            Copy-Item -LiteralPath $fixture.Archive -Destination $OutFile
            return
        }
        if ($Uri -eq ($prefix+'SHA256SUMS')) { return [pscustomobject]@{Content=($fixture.SHA256+'  '+$fixture.Asset+"`n")} }
        throw 'Unexpected release asset request'
    }
    & $Installer -InstallDir $latest
    Assert-Package $latest
    & $Installer -Version '0.0.0-ci' -InstallDir $pinned
    Assert-Package $pinned
    $calls = @($global:PeerimeterInstallerFixture.Requests)
    if (@($calls | Where-Object { $_ -eq 'https://api.github.com/repos/peerimeter/peerimeter-agent/releases/latest' }).Count -ne 1 -or
        @($calls | Where-Object { $_ -eq "https://github.com/peerimeter/peerimeter-agent/releases/download/v0.0.0-ci/$asset" }).Count -ne 2 -or
        @($calls | Where-Object { $_ -eq 'https://github.com/peerimeter/peerimeter-agent/releases/download/v0.0.0-ci/SHA256SUMS' }).Count -ne 2) { throw 'Latest or pinned release selected unexpected URLs' }
    Write-Output 'PASS default latest and pinned version resolve exact release assets and checksums using local fixtures'

    $before = @{}
    foreach ($name in @('peerimeter-agent.exe','wireguard.dll','peerimeter-agent.NOTICES.txt')) { $before[$name] = (Get-FileHash -LiteralPath (Join-Path $offline $name)).Hash }
    function global:Move-Item {
        param([string]$LiteralPath,[string]$Destination)
        if ($LiteralPath -match '\.new-' -and [IO.Path]::GetFileName($Destination) -eq 'wireguard.dll') { throw 'Injected second-member replacement failure' }
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
    }
    Expect-Failure { & $Installer -Archive $Archive -SHA256 $checksum -InstallDir $offline }
    Remove-Item Function:\global:Move-Item
    Assert-Package $offline
    foreach ($name in $before.Keys) { if ((Get-FileHash -LiteralPath (Join-Path $offline $name)).Hash -ne $before[$name]) { throw 'Failed replacement did not restore the old package' } }
    Write-Output 'PASS injected replacement failure rolls back all files and removes every staged file'
} finally {
    foreach ($name in @('Invoke-RestMethod','Invoke-WebRequest','Move-Item')) { Remove-Item -LiteralPath "Function:\global:$name" -ErrorAction SilentlyContinue }
    Remove-Variable -Name PeerimeterInstallerFixture -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
}
Write-Output 'PASS Windows installer test cleanup'
