$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$msi = Join-Path $env:RUNNER_TEMP 'peerimeter-wireguard-amd64-1.1.1.msi'
try {
    Invoke-WebRequest 'https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi' -OutFile $msi
    $expected = '7BFED60AD61B785C914B38B61555A975488E1D3EC472DBFB2FCDF498FCA75242'
    if ((Get-FileHash $msi -Algorithm SHA256).Hash -ne $expected) { throw 'WireGuard MSI checksum mismatch' }
    $sig = Get-AuthenticodeSignature $msi
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(^|, )CN=WireGuard LLC(,|$)') {
        throw 'WireGuard MSI signature or publisher invalid'
    }
    Write-Output ('Verified official MSI 1.1.1 signature: ' + $sig.SignerCertificate.Subject)
    $p = Start-Process msiexec.exe -ArgumentList @('/i', $msi, '/qn', 'DO_NOT_LAUNCH=1', '/norestart') -Wait -PassThru
    if ($p.ExitCode -notin @(0,3010)) { throw "WireGuard MSI failed: $($p.ExitCode)" }
    & 'C:\Program Files\WireGuard\wg.exe' --version
    if ($LASTEXITCODE -ne 0) { throw 'wg.exe unavailable after installation' }
} finally {
    Remove-Item $msi -Force -ErrorAction SilentlyContinue
}
