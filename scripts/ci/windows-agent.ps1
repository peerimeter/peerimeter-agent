param(
    [Parameter(Mandatory=$true)][string]$Agent,
    [Parameter(Mandatory=$true)][string]$Helper
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run Windows agent integration as administrator' }
$id = [Guid]::NewGuid().ToString('N')
$dir = Join-Path $env:RUNNER_TEMP "peerimeter-agent-$id"
$installation = Join-Path $env:ProgramFiles "Peerimeter-CI-$id"
$agentExe = Join-Path $installation 'peerimeter-agent.exe'
$helperExe = Join-Path $installation 'pmprobe.exe'
$configPath = Join-Path $dir 'native.json'
$state = Join-Path $dir 'foreground-state'
$serviceState = Join-Path $installation 'service-state'
$udpRule = "Peerimeter-Agent-CI-UDP-$id"
$tcpRule = "Peerimeter-Agent-CI-TCP-$id"
$reference = $null
$foreground = $null
$serviceInstalled = $false
$adapterName = $null

function Protect-Resource([string]$Path) {
    $isDirectory = Test-Path -LiteralPath $Path -PathType Container
    if ($isDirectory) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    } else {
        $acl = [Security.AccessControl.FileSecurity]::new()
        $inherit = [Security.AccessControl.InheritanceFlags]::None
    }
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl.SetOwner($admins)
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($admins,$system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Invoke-Agent([string[]]$CommandArgs) {
    $output = & $agentExe @CommandArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw "Agent command failed: $($CommandArgs[0])" }
    return $output
}
function Agent-Status([string]$StateDir) {
    return (Invoke-Agent -CommandArgs @('status','--state-dir',$StateDir) | ConvertFrom-Json)
}
function Wait-Agent([string]$StateDir) {
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        try {
            $result = Agent-Status $StateDir
            if ($result.state -eq 'running') { return $result }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw 'Agent did not publish a running native adapter within 30 seconds'
}
function Start-Foreground {
    $arguments = @('run','--config',('"{0}"' -f $configPath),'--state-dir',('"{0}"' -f $state))
    $script:foreground = Start-Process -FilePath $agentExe -ArgumentList $arguments -RedirectStandardOutput (Join-Path $dir 'agent.log') -RedirectStandardError (Join-Path $dir 'agent-error.log') -PassThru
    $status = Wait-Agent $state
    $script:adapterName = $status.interface_name
    return $status
}
function Stop-Foreground {
    Invoke-Agent -CommandArgs @('stop','--state-dir',$state) | Out-Null
    if (-not $foreground.WaitForExit(30000)) { throw 'Foreground agent did not stop and clean up within 30 seconds' }
    if ($foreground.ExitCode -ne 0) { throw 'Foreground shutdown reported an error' }
}
function Assert-Removed {
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        if (-not (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 500
    }
    if (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue) { throw 'Agent adapter leaked after shutdown' }
    if (Get-NetRoute -DestinationPrefix '10.203.0.2/32' -InterfaceAlias $adapterName -ErrorAction SilentlyContinue) { throw 'Agent route leaked after shutdown' }
}
function Verify-Traffic([string]$StateDir) {
    $before = @(Select-String -Path (Join-Path $dir 'reference.log') -Pattern '^PASS reference' -ErrorAction SilentlyContinue).Count
    & $helperExe host $dir
    if ($LASTEXITCODE -ne 0) { throw 'Actual agent -> reference TCP payload failed' }
    $after = @(Select-String -Path (Join-Path $dir 'reference.log') -Pattern '^PASS reference').Count
    if ($after -le $before) { throw 'Reference -> actual agent TCP payload missing' }
    $status = Agent-Status $StateDir
    $peers = @($status.peers)
    if ($peers.Count -ne 1 -or [DateTime]$peers[0].last_handshake -lt [DateTime]::UtcNow.AddMinutes(-3) -or [long]$peers[0].received_bytes -le 0 -or [long]$peers[0].sent_bytes -le 0) { throw 'Actual agent did not report fresh native WireGuard handshake and counters' }
    $route = Get-NetRoute -DestinationPrefix '10.203.0.2/32' -InterfaceAlias $status.interface_name -ErrorAction Stop
    if (Get-NetIPAddress -IPAddress '10.203.0.2' -ErrorAction SilentlyContinue) { throw 'Reference overlay address leaked into host stack' }
    Write-Output "PASS actual Windows agent: adapter=$($status.interface_name), route=$($route.DestinationPrefix), authenticated handshake and TCP payloads in both directions"
    return $status
}

try {
    if (Get-Service -Name 'PeerimeterAgent' -ErrorAction SilentlyContinue) { throw 'Existing PeerimeterAgent service found; refusing to alter it' }
    New-Item -ItemType Directory -Path $dir,$installation | Out-Null
    Protect-Resource $dir
    Protect-Resource $installation
    Copy-Item -LiteralPath $Agent -Destination $agentExe
    Copy-Item -LiteralPath $Helper -Destination $helperExe
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $Agent) 'wireguard.dll') -Destination (Join-Path $installation 'wireguard.dll')
    foreach ($path in @($agentExe,$helperExe,(Join-Path $installation 'wireguard.dll'))) { Protect-Resource $path }
    & $helperExe keygen $dir
    if ($LASTEXITCODE -ne 0) { throw 'Reference key generation failed' }
    # The helper emits an official-client config containing a private key. It is
    # not used by the agent and is deleted before diagnostics or artifact upload.
    Remove-Item -LiteralPath (Join-Path $dir 'pmprobe.conf') -Force
    $outerIP = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1).IPv4Address.IPAddress
    if (-not $outerIP) { throw 'No physical IPv4 endpoint for native Windows test' }
    $config = @{
        version=1; mode='static'; network=@{id='windows-agent-ci'; name='CI'}
        interface=@{private_key_file=(Join-Path $dir 'native.key'); address=@('10.203.0.1/32'); listen_port=51820}
        peers=@(@{public_key=[IO.File]::ReadAllText((Join-Path $dir 'reference.pub')).Trim(); allowed_ips=@('10.203.0.2/32'); endpoint="${outerIP}:51821"; persistent_keepalive_seconds=1})
    }
    $validJSON = $config | ConvertTo-Json -Depth 8
    [IO.File]::WriteAllText($configPath,$validJSON)
    $env:PM_NATIVE_ENDPOINT = "${outerIP}:51820"
    $reference = Start-Process -FilePath $helperExe -ArgumentList @('reference',('"{0}"' -f $dir)) -RedirectStandardOutput (Join-Path $dir 'reference.log') -RedirectStandardError (Join-Path $dir 'reference-error.log') -PassThru
    New-NetFirewallRule -DisplayName $udpRule -Direction Inbound -Action Allow -Protocol UDP -LocalPort 51820,51821 -RemoteAddress @('127.0.0.1',$outerIP) | Out-Null
    New-NetFirewallRule -DisplayName $tcpRule -Direction Inbound -Action Allow -Protocol TCP -LocalPort 18081 -LocalAddress '10.203.0.1' -RemoteAddress '10.203.0.2' | Out-Null
    Start-Foreground | Out-Null
    $before = Verify-Traffic $state | Select-Object -Last 1
    $index = (Get-NetAdapter -Name $adapterName).ifIndex
    Invoke-Agent -CommandArgs @('sync','--state-dir',$state) | Out-Null
    $unchanged = Agent-Status $state
    if ((Get-NetAdapter -Name $adapterName).ifIndex -ne $index -or $unchanged.peers[0].last_handshake -ne $before.peers[0].last_handshake) { throw 'Idempotent sync restarted the native adapter or peer' }
    Write-Output 'PASS unchanged sync preserves native adapter index and handshake'
    $config.version = 99
    [IO.File]::WriteAllText($configPath,($config | ConvertTo-Json -Depth 8))
    & $agentExe sync --state-dir $state *> $null
    if ($LASTEXITCODE -eq 0) { throw 'Invalid config sync unexpectedly succeeded' }
    [IO.File]::WriteAllText($configPath,$validJSON)
    Verify-Traffic $state | Out-Null
    Write-Output 'PASS invalid config preserves existing working tunnel'
    Stop-Foreground
    Assert-Removed
    Start-Foreground | Out-Null
    Verify-Traffic $state | Out-Null
    Stop-Foreground
    Assert-Removed
    Write-Output 'PASS foreground restart, native adapter and route teardown'

    Invoke-Agent -CommandArgs @('service','install','--config',$configPath,'--state-dir',$serviceState) | Out-Null
    $serviceInstalled = $true
    Invoke-Agent -CommandArgs @('service','start') | Out-Null
    $serviceStatus = Wait-Agent $serviceState
    $adapterName = $serviceStatus.interface_name
    Verify-Traffic $serviceState | Out-Null
    Invoke-Agent -CommandArgs @('service','stop') | Out-Null
    Assert-Removed
    Invoke-Agent -CommandArgs @('service','start') | Out-Null
    Wait-Agent $serviceState | Out-Null
    Verify-Traffic $serviceState | Out-Null
    Invoke-Agent -CommandArgs @('service','uninstall') | Out-Null
    $serviceInstalled = $false
    Assert-Removed
    if (-not (Test-Path -LiteralPath (Join-Path $serviceState 'service.key')) -or -not (Test-Path -LiteralPath (Join-Path $serviceState 'service.json'))) { throw 'Service uninstall removed operator credentials or config' }
    if (Get-Service -Name 'PeerimeterAgent' -ErrorAction SilentlyContinue) { throw 'SCM registration leaked after uninstall' }
    Write-Output 'PASS Windows SCM install/start/status/stop/restart/uninstall, config/key preservation'
} catch {
    foreach ($name in @('agent-error.log','reference.log','reference-error.log')) {
        $path = Join-Path $dir $name
        if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Tail 20 }
    }
    throw
} finally {
    if ($serviceInstalled) {
        & $agentExe service uninstall *> $null
    }
    if ($foreground -and -not $foreground.HasExited) {
        & $agentExe stop --state-dir $state *> $null
        if (-not $foreground.WaitForExit(15000)) { Stop-Process -Id $foreground.Id -Force -ErrorAction SilentlyContinue }
    }
    if ($reference -and -not $reference.HasExited) { Stop-Process -Id $reference.Id -Force -ErrorAction SilentlyContinue }
    Remove-NetFirewallRule -DisplayName $tcpRule -ErrorAction SilentlyContinue
    Remove-NetFirewallRule -DisplayName $udpRule -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $dir) { Remove-Item -LiteralPath $dir -Recurse -Force }
    if (Test-Path -LiteralPath $installation) { Remove-Item -LiteralPath $installation -Recurse -Force }
}
if ($adapterName -and (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue)) { throw 'Native Windows adapter remained after cleanup' }
if (Get-NetFirewallRule -DisplayName $udpRule,$tcpRule -ErrorAction SilentlyContinue) { throw 'Temporary firewall rules leaked' }
Write-Output 'PASS Windows agent integration cleanup: no test adapter/routes/service/firewall rules/keys/install directory'
