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
function Get-FreeUdpPort {
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $socket = [Net.Sockets.UdpClient]::new(0)
        try { $port = $socket.Client.LocalEndPoint.Port }
        finally { $socket.Dispose() }
        if ($port -ne 51820) { return $port }
    }
    throw 'Could not select a UDP probe port distinct from the native peer port'
}
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
    $referencePort = Get-FreeUdpPort
    $env:PM_REFERENCE_PORT = "$referencePort"
    & $helper keygen $dir
    if ($LASTEXITCODE -ne 0) { throw 'Key generation failed' }
    $outerIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
    if (-not $outerIP) { throw 'Missing host IPv4 address for local native endpoint test' }
    Write-Output ('Outer endpoint address: ' + $outerIP)
    $baseConfig = [IO.File]::ReadAllText("$dir\pmprobe.conf")
    $env:PM_NATIVE_ENDPOINT = "${outerIP}:51820"
    $referenceReady = $false
    for ($portAttempt = 0; $portAttempt -lt 5; $portAttempt++) {
        $referencePort = Get-FreeUdpPort
        $env:PM_REFERENCE_PORT = "$referencePort"
        $cfg = [regex]::Replace($baseConfig,'(?m)^Endpoint = .*$',"Endpoint = ${outerIP}:$referencePort")
        [IO.File]::WriteAllText("$dir\pmprobe.conf", $cfg)
        $ref = Start-Process $helper -ArgumentList @('reference',$dir) -RedirectStandardOutput "$dir\reference.log" -RedirectStandardError "$dir\reference-error.log" -PassThru
        $readyDeadline = [DateTime]::UtcNow.AddSeconds(10)
        while ([DateTime]::UtcNow -lt $readyDeadline) {
            if (Select-String -Path "$dir\reference.log" -SimpleMatch 'Reference peer ready' -Quiet -ErrorAction SilentlyContinue) { $referenceReady = $true; break }
            if ($ref.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }
        if ($referenceReady) { break }
        if (-not $ref.HasExited) {
            Stop-Process -Id $ref.Id -Force -ErrorAction SilentlyContinue
            throw 'Reference peer did not become ready within 10 seconds'
        }
        $referenceFailure = (@(Get-Content -LiteralPath "$dir\reference-error.log" -ErrorAction SilentlyContinue) + @(Get-Content -LiteralPath "$dir\reference.log" -ErrorAction SilentlyContinue)) -join "`n"
        if ($referenceFailure -notmatch '(?i)(bind:|address already in use|access.*permissions)') { throw "Reference peer failed to start: $referenceFailure" }
        Write-Output "Reference UDP port $referencePort was unavailable; retrying with another port"
        $ref = $null
    }
    if (-not $referenceReady) { throw 'Reference peer could not bind an available UDP port after 5 attempts' }
    New-NetFirewallRule -DisplayName $udpRule -Direction Inbound -Action Allow -Protocol UDP -LocalPort 51820,$referencePort -RemoteAddress @('127.0.0.1',$outerIP) | Out-Null
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
