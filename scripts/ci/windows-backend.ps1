param([Parameter(Mandatory=$true)][string]$Helper)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$dir = Join-Path $env:RUNNER_TEMP 'peerimeter-wgprobe'
if (Test-Path $dir) { throw 'Probe directory already exists; refuse to reuse secrets' }
New-Item -ItemType Directory -Path $dir | Out-Null
Copy-Item $Helper (Join-Path $dir 'pmprobe.exe')
$helper = Join-Path $dir 'pmprobe.exe'
$wg = 'C:\Program Files\WireGuard\wg.exe'
$wireguard = 'C:\Program Files\WireGuard\wireguard.exe'
$service = 'WireGuardTunnel$pmprobe'
$ref = $null
$installed = $false
$tcpRule = 'Peerimeter-probe-TCP'
$udpRule = 'Peerimeter-probe-UDP'
function Verify-Traffic {
    $before = @(Select-String -Path "$dir\reference.log" -Pattern '^PASS reference' -ErrorAction SilentlyContinue).Count
    & $helper host $dir
    if ($LASTEXITCODE -ne 0) { throw 'Native -> reference TCP probe failed' }
    $after = @(Select-String -Path "$dir\reference.log" -Pattern '^PASS reference').Count
    if ($after -le $before) { throw 'Reference -> native TCP probe missing' }
    $hs = & $wg show pmprobe latest-handshakes
    if ($LASTEXITCODE -ne 0 -or [long](($hs.Trim() -split '\s+')[1]) -le 0) { throw 'Missing native handshake' }
    $tx = & $wg show pmprobe transfer
    $fields = $tx.Trim() -split '\s+'
    if ([long]$fields[1] -le 0 -or [long]$fields[2] -le 0) { throw 'Missing native traffic counters' }
    Write-Output $hs
    Write-Output $tx
    Get-Content "$dir\reference.log" -Tail 8
}
try {
    & icacls.exe $dir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect temporary key directory' }
    & $helper keygen $dir
    if ($LASTEXITCODE -ne 0) { throw 'Key generation failed' }
    $outerIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
    if (-not $outerIP) { throw 'Missing host IPv4 address for local native endpoint test' }
    Write-Output ('Outer endpoint address: ' + $outerIP)
    $cfg = [IO.File]::ReadAllText("$dir\pmprobe.conf").Replace('Endpoint = 127.0.0.1:51821', "Endpoint = ${outerIP}:51821")
    [IO.File]::WriteAllText("$dir\pmprobe.conf", $cfg)
    $env:PM_NATIVE_ENDPOINT = "${outerIP}:51820"
    $ref = Start-Process $helper -ArgumentList @('reference',$dir) -RedirectStandardOutput "$dir\reference.log" -RedirectStandardError "$dir\reference-error.log" -PassThru
    Start-Sleep -Seconds 2
    New-NetFirewallRule -DisplayName $udpRule -Direction Inbound -Action Allow -Protocol UDP -LocalPort 51820,51821 -RemoteAddress @('127.0.0.1',$outerIP) | Out-Null
    $p = Start-Process $wireguard -ArgumentList @('/installtunnelservice',"$dir\pmprobe.conf") -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "Tunnel service install failed: $($p.ExitCode)" }
    $installed = $true
    (Get-Service $service).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    for ($i=0; $i -lt 30; $i++) {
        if (Get-NetIPAddress -InterfaceAlias pmprobe -IPAddress 10.203.0.1 -ErrorAction SilentlyContinue) { break }
        Start-Sleep -Seconds 1
    }
    Get-NetAdapter -Name pmprobe | Format-Table Name,InterfaceDescription,Status
    $route = Get-NetRoute -DestinationPrefix '10.203.0.2/32' -InterfaceAlias pmprobe -ErrorAction Stop
    $route | Format-Table DestinationPrefix,InterfaceAlias,NextHop
    if (Get-NetIPAddress -IPAddress 10.203.0.2 -ErrorAction SilentlyContinue) { throw 'Reference IP leaked into host network stack' }
    New-NetFirewallRule -DisplayName $tcpRule -Direction Inbound -Action Allow -Protocol TCP -LocalPort 18081 -InterfaceAlias pmprobe | Out-Null
    Verify-Traffic
    Write-Output 'PASS: Windows native WireGuardNT, route, handshake, TCP initiated in both directions'
    Stop-Service $service
    (Get-Service $service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    Start-Service $service
    (Get-Service $service).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Start-Sleep -Seconds 3
    Verify-Traffic
    Write-Output 'PASS: Windows tunnel service restart and renewed traffic'
} catch {
    & $wg show pmprobe latest-handshakes
    & $wg show pmprobe transfer
    Get-Content "$dir\reference.log" -Tail 15
    Get-Content "$dir\reference-error.log" -Tail 15
    throw
} finally {
    if ($installed) { Start-Process $wireguard -ArgumentList @('/uninstalltunnelservice','pmprobe') -Wait | Out-Null }
    if ($ref -and -not $ref.HasExited) { Stop-Process -Id $ref.Id -Force -ErrorAction SilentlyContinue }
    Remove-NetFirewallRule -DisplayName $tcpRule -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $udpRule -ErrorAction SilentlyContinue
    foreach ($file in @('native.key','native.pub','reference.key','reference.pub','pmprobe.conf')) {
        Remove-Item (Join-Path $dir $file) -Force -ErrorAction SilentlyContinue
    }
}
if (Get-Service $service -ErrorAction SilentlyContinue) { throw 'Service leaked after cleanup' }
if (Get-NetAdapter -Name pmprobe -ErrorAction SilentlyContinue) { throw 'Adapter leaked after cleanup' }
if (Get-NetRoute -DestinationPrefix '10.203.0.2/32' -InterfaceAlias pmprobe -ErrorAction SilentlyContinue) { throw 'Route leaked after cleanup' }
if (Get-NetFirewallRule -DisplayName $tcpRule,$udpRule -ErrorAction SilentlyContinue) { throw 'Firewall rule leaked after cleanup' }
Remove-Item $dir -Recurse -Force
Write-Output 'PASS: Windows service/adapter/route/firewall/key cleanup'
