param(
    [string]$PackageDirectory,
    [string]$Archive,
    [string]$Installer = (Join-Path $PSScriptRoot '..\..\docs\install.ps1')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Installer = [IO.Path]::GetFullPath($Installer)
$base = Join-Path $env:ProgramFiles ('Peerimeter Installer CI ' + [guid]::NewGuid().ToString('N'))
$offline = Join-Path $base 'offline custom path'
$latest = Join-Path $base 'latest custom path'
$pinned = Join-Path $base 'pinned custom path'
$badTarget = Join-Path $base 'must not install'
$defaultTarget = Join-Path $env:ProgramFiles 'Peerimeter'
$defaultInstalled = $false
$programDataTarget = Join-Path $env:ProgramData ('Peerimeter Installer CI ' + [guid]::NewGuid().ToString('N') + ' custom path')
$programDataCreated = $false
$arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()) { 'x64' {'amd64'} 'arm64' {'arm64'} default {throw 'Unsupported test architecture'} }
if (-not $Archive) {
    if (-not $PackageDirectory) { throw 'Supply -PackageDirectory or -Archive' }
    $assetArch = switch ($arch) { 'amd64' { 'x86_64' } 'arm64' { 'aarch64' } }
    $packages = @(Get-ChildItem -LiteralPath $PackageDirectory -Filter "peerimeter-agent-windows-$assetArch.zip" -File)
    if ($packages.Count -ne 1) { throw 'Expected exactly one native Windows package ZIP' }
    $Archive = $packages[0].FullName
}
$Archive = [IO.Path]::GetFullPath($Archive)
$checksum = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
$assetArch = switch ($arch) { 'amd64' { 'x86_64' } 'arm64' { 'aarch64' } }
$asset = "peerimeter-agent-windows-$assetArch.zip"
$global:PeerimeterInstallerFixture = @{
    Archive=$Archive; SHA256=$checksum; Asset=$asset; Requests=[Collections.Generic.List[string]]::new(); FailReplace=$false
}

function Show-RecentRemovalDiagnostics {
    $logs = @(Get-ChildItem -LiteralPath $env:TEMP -Filter 'peerimeter-uninstall-*.helper.log' -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 2)
    foreach ($log in $logs) {
        Write-Host 'Recent bounded removal helper diagnostics:'
        Get-Content -LiteralPath $log.FullName -Tail 40 | ForEach-Object { Write-Host $_ }
        $receipt = $log.FullName -replace '\.helper\.log$','.result.json'
        if (Test-Path -LiteralPath $receipt) { Write-Host 'Corresponding removal receipt:'; Get-Content -LiteralPath $receipt | ForEach-Object { Write-Host $_ } }
    }
}
function Show-RemovalDiagnostics([string]$ReceiptPath) {
    if (-not $ReceiptPath) { return }
    if (Test-Path -LiteralPath $ReceiptPath) { Write-Host 'Removal receipt:'; Get-Content -LiteralPath $ReceiptPath | ForEach-Object { Write-Host $_ } }
    $workDir = $ReceiptPath -replace '\.result\.json$',''
    foreach ($log in @((Join-Path $workDir 'helper.log'),($workDir+'.helper.log'))) {
        if (Test-Path -LiteralPath $log) { Write-Host 'Bounded removal helper diagnostics:'; Get-Content -LiteralPath $log -Tail 40 | ForEach-Object { Write-Host $_ } }
    }
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
    $inventory = Join-Path $Directory '.peerimeter-agent.install.json'
    if (-not (Test-Path -LiteralPath $inventory -PathType Leaf)) { throw 'Installed package has no protected ownership inventory' }
    $inventoryACL = Get-Acl -LiteralPath $inventory
    foreach ($rule in $inventoryACL.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and [long]$rule.FileSystemRights -ne 0) { throw 'Installation inventory grants access to an unrelated user' }
    }
    $binary = Join-Path $Directory 'peerimeter-agent.exe'
    $version = & $binary version --json | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $version.os -ne 'windows' -or $version.go_version -ne 'go1.27.4') { throw 'Installed native agent executable failed version smoke test' }
    if (@(Get-ChildItem -LiteralPath $Directory -Force | Where-Object { $_.Name -match '\.(new|old)-' }).Count) { throw 'Installer leaked staged or backup files' }
}
function Remove-InstalledPackage([string]$Directory,[string]$ExternalCLI) {
    $binary = Join-Path $Directory 'peerimeter-agent.exe'
    $before = @(Get-ChildItem -LiteralPath $Directory -Force -File | Sort-Object Name | ForEach-Object { $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName).Hash + ':' + (Get-Acl -LiteralPath $_.FullName).Sddl }) -join "`n"
    $dry = & $binary uninstall --install-dir $Directory --dry-run | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $dry.state -ne 'dry_run') { throw 'Installed package dry-run failed' }
    $after = @(Get-ChildItem -LiteralPath $Directory -Force -File | Sort-Object Name | ForEach-Object { $_.Name + ':' + (Get-FileHash -LiteralPath $_.FullName).Hash + ':' + (Get-Acl -LiteralPath $_.FullName).Sddl }) -join "`n"
    if ($before -ne $after) { throw 'Installed package dry-run changed inventory, files or ACLs' }
    $sentinel = Join-Path $Directory 'unrelated.txt'
    [IO.File]::WriteAllText($sentinel,'operator data stays')
    $result = & $binary uninstall --install-dir $Directory | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { Show-RecentRemovalDiagnostics; throw 'Installed package full uninstall failed' }
    if ($result.state -eq 'pending') {
        if (-not $result.result_file) { throw 'Pending Windows removal omitted its completion report' }
        $done = $false
        for ($attempt=0; $attempt -lt 120; $attempt++) {
            if (Test-Path -LiteralPath $result.result_file) {
                try {
                    $report = Get-Content -LiteralPath $result.result_file -Raw | ConvertFrom-Json
                    if ($report.state -eq 'failed') { Show-RemovalDiagnostics $result.result_file; throw 'Windows package removal helper reported failed cleanup' }
                    if ($report.state -eq 'removed') { $done = $true; break }
                } catch { if ($_.Exception.Message -eq 'Windows package removal helper reported failed cleanup') { throw } }
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $done) { Show-RemovalDiagnostics $result.result_file; throw 'Windows package removal did not complete within 60 seconds' }
        Remove-Item -LiteralPath $result.result_file -Force
    } elseif ($result.state -ne 'removed') { throw 'Unrecognized package uninstall result' }
    foreach ($name in @('peerimeter-agent.exe','wireguard.dll','peerimeter-agent.NOTICES.txt','.peerimeter-agent.install.json','.peerimeter-agent.install.lock')) {
        if (Test-Path -LiteralPath (Join-Path $Directory $name)) { throw "Installed program member survived uninstall: $name" }
    }
    if ([IO.File]::ReadAllText($sentinel) -ne 'operator data stays') { throw 'Full uninstall removed unrelated installation-parent data' }
    $again = & $ExternalCLI uninstall --install-dir $Directory | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $again.state -ne 'already_absent') { throw 'Second package uninstall was not idempotent' }
}
function Expect-Failure([scriptblock]$Operation) {
    $failed = $false
    try { & $Operation | Out-Null } catch { $failed = $true }
    if (-not $failed) { throw 'Expected installer failure did not occur' }
}

try {
    New-Item -ItemType Directory -Path $base | Out-Null
    if (Test-Path -LiteralPath $defaultTarget) { throw 'Actual default installation destination is already occupied' }
    & $Installer -Archive $Archive -SHA256 $checksum
    $defaultInstalled = $true
    Assert-Package $defaultTarget
    Write-Output 'PASS actual Windows installer default destination and protected inventory'
    & $Installer -Archive $Archive -SHA256 $checksum -InstallDir $offline
    Assert-Package $offline
    Write-Output 'PASS offline local ZIP install, custom path with spaces, complete signed WireGuardNT bundle and native CLI'
    if (Test-Path -LiteralPath $programDataTarget) { throw 'Random ProgramData fixture destination is already occupied' }
    $programDataCreated = $true
    & $Installer -Archive $Archive -SHA256 $checksum -InstallDir $programDataTarget
    Assert-Package $programDataTarget
    Write-Output 'PASS actual custom ProgramData installer path with standard shared-root metadata ACL and protected package/inventory'

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

    $externalCLI = Join-Path $base 'uninstall verifier.exe'
    Copy-Item -LiteralPath (Join-Path $offline 'peerimeter-agent.exe') -Destination $externalCLI
    foreach ($directory in @($offline,$latest,$pinned,$defaultTarget,$programDataTarget)) { Remove-InstalledPackage $directory $externalCLI }
    $defaultInstalled = $false
    Write-Output 'PASS native installed packages full uninstall, read-only dry-run, bounded self-removal and unrelated-file/idempotency checks'
} finally {
    foreach ($name in @('Invoke-RestMethod','Invoke-WebRequest','Move-Item')) { Remove-Item -LiteralPath "Function:\global:$name" -ErrorAction SilentlyContinue }
    Remove-Variable -Name PeerimeterInstallerFixture -Scope Global -ErrorAction SilentlyContinue
    if ($defaultInstalled -and (Test-Path -LiteralPath $defaultTarget)) {
        # This path was absent before this test and is created only by its own
        # installer. Product removal is asserted above; failure cleanup is CI-only.
        Remove-Item -LiteralPath $defaultTarget -Recurse -Force
    } elseif (Test-Path -LiteralPath (Join-Path $defaultTarget 'unrelated.txt')) {
        Remove-Item -LiteralPath (Join-Path $defaultTarget 'unrelated.txt') -Force
        if (-not @(Get-ChildItem -LiteralPath $defaultTarget -Force).Count) { Remove-Item -LiteralPath $defaultTarget }
    }
    if ($programDataCreated -and (Test-Path -LiteralPath $programDataTarget)) { Remove-Item -LiteralPath $programDataTarget -Recurse -Force }
    if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
}
Write-Output 'PASS Windows installer test cleanup'
