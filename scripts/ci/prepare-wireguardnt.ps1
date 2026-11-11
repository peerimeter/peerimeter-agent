param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$work = Join-Path $env:RUNNER_TEMP ('wireguardnt-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $zip = Join-Path $work 'wireguard-nt.zip'
    Invoke-WebRequest 'https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip' -OutFile $zip
    if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne 'DCEB30A9BC4BE48CCE0F74160FC88A585A2C2627366E8F846FC6658F9038DACE') { throw 'Official WireGuardNT archive checksum mismatch' }
    Expand-Archive $zip (Join-Path $work 'unpacked')
    $arch = switch ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()) { 'X64' { 'amd64' } 'Arm64' { 'arm64' } default { throw 'Unsupported test architecture' } }
    $dll = Join-Path $work "unpacked/wireguard-nt/bin/$arch/wireguard.dll"
    if ((Get-AuthenticodeSignature $dll).Status -ne 'Valid') { throw 'WireGuardNT signature invalid' }
    Copy-Item $dll (Join-Path $Destination 'wireguard.dll')
    Write-Output 'Prepared pinned, signed WireGuardNT 1.1 beside the agent; no WireGuard application/MSI installed.'
} finally { Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue }
