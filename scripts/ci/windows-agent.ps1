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
$serviceState = Join-Path $installation 'service state'
$udpRule = "Peerimeter-Agent-CI-UDP-$id"
$tcpRule = "Peerimeter-Agent-CI-TCP-$id"
$reference = $null
$foreground = $null
$serviceInstalled = $false
$adapterName = $null
$operatorName = "pmci" + $id.Substring(0,12)
$operatorSID = $null
$operatorCredential = $null
$operatorCreated = $false
$operatorOutput = Join-Path $installation 'operator-output'
$removalResult = $null
$collisionInstall = Join-Path $env:ProgramFiles "Peerimeter Collision $id"

function Protect-Resource([string]$Path,[bool]$Public=$false) {
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
    if ($Public) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::ReadAndExecute,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Remove-TestDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force
    } catch {
        # SCM runs as SYSTEM and may create protected metadata. Reclaim only
        # this run's temporary test tree; grant no access to ordinary users.
        & takeown.exe /F $Path /A /R /D Y | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not reclaim temporary SYSTEM-owned test metadata' }
        & icacls.exe $Path /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /T /C | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Could not grant administrator cleanup access to temporary test tree' }
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}
function Snapshot-ManagedTrees([string[]]$Roots) {
    $items = foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $entries = @((Get-Item -LiteralPath $root -Force)) + @(Get-ChildItem -LiteralPath $root -Recurse -Force)
        foreach ($entry in $entries) {
            $acl = (Get-Acl -LiteralPath $entry.FullName).Sddl
            $data = [ordered]@{Path=$entry.FullName; Attributes=[int]$entry.Attributes; ACL=$acl}
            if (-not $entry.PSIsContainer) {
                $data.Size=$entry.Length; $data.Modified=$entry.LastWriteTimeUtc.Ticks
                $data.Hash=(Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash
            }
            [pscustomobject]$data
        }
    }
    return (@($items | Sort-Object Path) | ConvertTo-Json -Depth 5 -Compress)
}
function Invoke-Agent([string[]]$CommandArgs) {
    if ($CommandArgs.Count -gt 0 -and $CommandArgs[0] -eq 'peers' -and '--json' -notin $CommandArgs) { $CommandArgs += '--json' }
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
function Invoke-OperatorAgent([string]$Operation,[string]$StateDir,[bool]$ExpectSuccess) {
    $out = Join-Path $operatorOutput ($Operation + '.json')
    $err = Join-Path $operatorOutput ($Operation + '-error.json')
    $arguments = @($Operation,'--state-dir',('"{0}"' -f $StateDir))
    if ($Operation -eq 'peers') { $arguments += '--json' }
    $p = Start-Process -FilePath $agentExe -Credential $operatorCredential -WorkingDirectory $operatorOutput -ArgumentList $arguments -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    if (-not $p.WaitForExit(30000)) { Stop-Process -Id $p.Id -Force; throw 'Nonadmin CLI did not finish within 30 seconds' }
    if ($ExpectSuccess -and $p.ExitCode -ne 0) { throw "Delegated nonadmin CLI $Operation failed" }
    if (-not $ExpectSuccess -and $p.ExitCode -eq 0) { throw 'Undelegated nonadmin CLI unexpectedly reached the control pipe' }
    if ($ExpectSuccess) { return ([IO.File]::ReadAllText($out) | ConvertFrom-Json) }
}
function Verify-RuntimeCollision {
    $otherState = Join-Path $dir 'state for installation B'
    & (Join-Path $PSScriptRoot '..\..\install.ps1') -Archive $archive -SHA256 (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -InstallDir $collisionInstall
    $otherAgent = Join-Path $collisionInstall 'peerimeter-agent.exe'
    $marker = Join-Path $state '.peerimeter-agent.runtime'
    $markerBefore = (Get-FileHash -LiteralPath $marker).Hash
    $arguments = @('run','--config',('"{0}"' -f $configPath),'--state-dir',('"{0}"' -f $otherState),'--runtime-dir',('"{0}"' -f $state))
    $process = Start-Process -FilePath $otherAgent -ArgumentList $arguments -RedirectStandardOutput (Join-Path $dir 'collision.log') -RedirectStandardError (Join-Path $dir 'collision-error.log') -PassThru
    if (-not $process.WaitForExit(8000)) { Stop-Process -Id $process.Id -Force; throw 'Installation B failed to reject the occupied runtime promptly' }
    if ($process.ExitCode -eq 0) { throw 'Installation B accepted installation A runtime' }
    $inventory = Get-Content -LiteralPath (Join-Path $collisionInstall '.peerimeter-agent.install.json') -Raw | ConvertFrom-Json
    $profiles = @($inventory.profiles)
    if ($profiles.Count -ne 1 -or $profiles[0].runtime_owned -or $profiles[0].runtime_dir -ne $state) { throw 'Failed installation did not retain a non-owned planned runtime profile' }
    $removal = & $otherAgent uninstall --install-dir $collisionInstall | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'Installation B cleanup failed' }
    if ($removal.state -eq 'pending') {
        $done = $false
        for ($attempt=0; $attempt -lt 120; $attempt++) {
            if (Test-Path -LiteralPath $removal.result_file) {
                try {
                    $receipt = Get-Content -LiteralPath $removal.result_file -Raw | ConvertFrom-Json
                    if ($receipt.state -eq 'failed') { throw 'Installation B removal helper could not finish' }
                    if ($receipt.state -eq 'removed') { $done = $true; break }
                } catch { if ($_.Exception.Message -eq 'Installation B removal helper could not finish') { throw } }
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $done) { throw 'Installation B cleanup exceeded 60 seconds' }
        Remove-Item -LiteralPath $removal.result_file -Force
    } elseif ($removal.state -ne 'removed') { throw 'Unexpected installation B cleanup status' }
    if ((Get-FileHash -LiteralPath $marker).Hash -ne $markerBefore -or (Agent-Status $state).state -ne 'running') { throw 'Installation B uninstall changed installation A runtime or stopped its manager' }
    Verify-Traffic $state | Out-Null
    Write-Output 'PASS failed installation B startup/full uninstall preserves installation A runtime identity, named pipe and real tunnel traffic'
}
function Assert-OperatorCannotReadKey {
    $path = Join-Path $serviceState 'service.key'
    $scriptText = '$ErrorActionPreference = "Stop"; try { $null = [IO.File]::ReadAllBytes(' + "'" + $path.Replace("'","''") + "'" + '); exit 1 } catch { if ($_.Exception.GetBaseException() -is [UnauthorizedAccessException]) { exit 0 }; exit 2 }'
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($scriptText))
    $powershell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $p = Start-Process -FilePath $powershell -Credential $operatorCredential -WorkingDirectory $operatorOutput -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded) -PassThru
    if (-not $p.WaitForExit(30000)) { Stop-Process -Id $p.Id -Force; throw 'Private-key access test timed out' }
    if ($p.ExitCode -ne 0) { throw 'Delegated nonadmin operator could read the protected service private key' }
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
    if ($status.public_key -ne [IO.File]::ReadAllText((Join-Path $dir 'native.pub')).Trim() -or $status.listen_port -ne 51820 -or @($peers[0].allowed_ips).Count -ne 1 -or $peers[0].allowed_ips[0] -ne '10.203.0.2/32' -or $peers[0].persistent_keepalive_seconds -ne 1) { throw 'Native public key/listen port/AllowedIPs/keepalive snapshot is incorrect' }
    $human = (& $agentExe peers --state-dir $StateDir | Out-String)
    if ($LASTEXITCODE -ne 0) { throw 'Human-readable peers command failed' }
    foreach ($label in @('interface:','public key:','listening port:','peer:','allowed ips:','latest handshake:','transfer:','private key: (hidden)')) { if (-not $human.Contains($label)) { throw 'Human peers output omitted a wgshow-style field' } }
    if ($human.Contains([IO.File]::ReadAllText((Join-Path $dir 'native.key')).Trim())) { throw 'Human peers output leaked private key material' }
    $route = Get-NetRoute -DestinationPrefix '10.203.0.2/32' -InterfaceAlias $status.interface_name -ErrorAction Stop
    if (Get-NetIPAddress -IPAddress '10.203.0.2' -ErrorAction SilentlyContinue) { throw 'Reference overlay address leaked into host stack' }
    Write-Output "PASS actual Windows agent: adapter=$($status.interface_name), route=$($route.DestinationPrefix), authenticated handshake and TCP payloads in both directions"
    return $status
}

try {
    if (Get-Service -Name 'PeerimeterAgent' -ErrorAction SilentlyContinue) { throw 'Existing PeerimeterAgent service found; refusing to alter it' }
    New-Item -ItemType Directory -Path $dir,$installation | Out-Null
    Protect-Resource $dir
    Protect-Resource $installation $true
    # Use the real verified operator installer so inventory ownership is tested,
    # not a manually copied executable that full uninstall must refuse to own.
    $stage = Join-Path $dir 'package staging'
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item -LiteralPath $Agent -Destination (Join-Path $stage 'peerimeter-agent.exe')
    Copy-Item -LiteralPath (Join-Path (Split-Path -Parent $Agent) 'wireguard.dll') -Destination (Join-Path $stage 'wireguard.dll')
    [IO.File]::WriteAllText((Join-Path $stage 'peerimeter-agent.NOTICES.txt'),'Native integration archive fixture; release packages carry full dependency notices.')
    $archive = Join-Path $dir 'native package.zip'
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $archive
    & (Join-Path $PSScriptRoot '..\..\install.ps1') -Archive $archive -SHA256 (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -InstallDir $installation
    if (-not (Test-Path -LiteralPath (Join-Path $installation '.peerimeter-agent.install.json'))) { throw 'Verified installer did not register its protected inventory' }
    Copy-Item -LiteralPath $Helper -Destination $helperExe
    Protect-Resource $helperExe $true
    $securePassword = ConvertTo-SecureString ('Pm!' + [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $newUser = New-LocalUser -Name $operatorName -Password $securePassword -AccountNeverExpires -PasswordNeverExpires -UserMayNotChangePassword
    $operatorCreated = $true
    $operatorSID = $newUser.SID.Value
    $usersSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    if (-not (Get-LocalGroupMember -SID $usersSID | Where-Object { $_.SID.Value -eq $operatorSID })) { Add-LocalGroupMember -SID $usersSID -Member $operatorName }
    $operatorCredential = [Management.Automation.PSCredential]::new(($env:COMPUTERNAME + '\' + $operatorName),$securePassword)
    New-Item -ItemType Directory -Path $operatorOutput | Out-Null
    Protect-Resource $operatorOutput
    $outputACL = Get-Acl -LiteralPath $operatorOutput
    $outputACL.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($operatorSID),[Security.AccessControl.FileSystemRights]::Modify,[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit',[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
    Set-Acl -LiteralPath $operatorOutput -AclObject $outputACL
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
    Verify-RuntimeCollision
    Invoke-OperatorAgent 'status' $state $false
    Write-Output 'PASS undelegated nonadmin CLI is denied access to the agent control pipe'
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

    Invoke-Agent -CommandArgs @('service','install','--config',$configPath,'--state-dir',$serviceState,'--operator',$operatorSID) | Out-Null
    $serviceInstalled = $true
    Invoke-Agent -CommandArgs @('service','start') | Out-Null
    $serviceStatus = Wait-Agent $serviceState
    $adapterName = $serviceStatus.interface_name
    Verify-Traffic $serviceState | Out-Null
    $delegated = Invoke-OperatorAgent 'status' $serviceState $true
    if ($delegated.state -ne 'running') { throw 'Delegated nonadmin status did not report the native service' }
    $null = Invoke-OperatorAgent 'peers' $serviceState $true
    Assert-OperatorCannotReadKey
    Write-Output 'PASS delegated nonadmin CLI status/peers with private key access denied'
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

    # Reinstall the preserved profile and prove full uninstall stops a live
    # service, rather than merely deleting an already stopped package.
    Invoke-Agent -CommandArgs @('service','install','--config',$configPath,'--state-dir',$serviceState,'--operator',$operatorSID) | Out-Null
    $serviceInstalled = $true
    Invoke-Agent -CommandArgs @('service','start') | Out-Null
    Wait-Agent $serviceState | Out-Null
    Verify-Traffic $serviceState | Out-Null
    $originalKeyHash = (Get-FileHash -LiteralPath (Join-Path $dir 'native.key')).Hash
    foreach ($folder in @($installation,$state,$serviceState)) { [IO.File]::WriteAllText((Join-Path $folder 'unrelated.txt'),'unrelated operator file') }
    $beforeDry = Snapshot-ManagedTrees @($installation,$state)
    $dry = Invoke-Agent -CommandArgs @('uninstall','--install-dir',$installation,'--dry-run') | ConvertFrom-Json
    if ($dry.state -ne 'dry_run' -or @($dry.paths).Count -lt 5) { throw 'Full uninstall dry-run omitted tracked resources' }
    if ((Snapshot-ManagedTrees @($installation,$state)) -ne $beforeDry) { throw 'Full uninstall dry-run mutated files, ACLs or inventory' }
    if ((Agent-Status $serviceState).state -ne 'running') { throw 'Dry-run stopped the live service' }
    $noticePath = Join-Path $installation 'peerimeter-agent.NOTICES.txt'
    $noticeBytes = [IO.File]::ReadAllBytes($noticePath)
    [IO.File]::AppendAllText($noticePath,'modified tracked notice')
    & $agentExe uninstall --install-dir $installation *> $null
    if ($LASTEXITCODE -eq 0) { throw 'Full uninstall ignored a changed inventoried program file' }
    if ((Agent-Status $serviceState).state -ne 'running') { throw 'Hash-conflict preflight stopped the working service' }
    [IO.File]::WriteAllBytes($noticePath,$noticeBytes)
    # Resume safely when a previous attempt already removed one tracked member.
    Remove-Item -LiteralPath $noticePath -Force
    $removal = Invoke-Agent -CommandArgs @('uninstall','--install-dir',$installation) | ConvertFrom-Json
    if ($removal.state -eq 'pending') {
        $removalResult = $removal.result_file
        if (-not $removalResult) { throw 'Windows pending removal omitted its result path' }
        $completed = $false
        for ($attempt=0; $attempt -lt 120; $attempt++) {
            if (Test-Path -LiteralPath $removalResult) {
                try {
                    $result = Get-Content -LiteralPath $removalResult -Raw | ConvertFrom-Json
                    if ($result.state -eq 'failed') { throw 'Bounded Windows removal helper reported remaining files' }
                    if ($result.state -eq 'removed') { $completed = $true; break }
                } catch { if ($_.Exception.Message -eq 'Bounded Windows removal helper reported remaining files') { throw } }
            }
            Start-Sleep -Milliseconds 500
        }
        if (-not $completed) { throw 'Windows removal helper did not report complete deletion within 60 seconds' }
    } elseif ($removal.state -ne 'removed') { throw 'Unexpected full uninstall status' }
    $serviceInstalled = $false
    Assert-Removed
    if (Get-Service -Name 'PeerimeterAgent' -ErrorAction SilentlyContinue) { throw 'Full uninstall left an SCM registration' }
    foreach ($path in @($agentExe,(Join-Path $installation 'wireguard.dll'),(Join-Path $installation 'peerimeter-agent.NOTICES.txt'),(Join-Path $installation '.peerimeter-agent.install.json'),(Join-Path $installation '.peerimeter-agent.install.lock'),(Join-Path $serviceState 'service.key'),(Join-Path $serviceState 'service.json'),(Join-Path $serviceState 'ownership'),(Join-Path $serviceState 'agent.lock'),(Join-Path $state 'ownership'),(Join-Path $state 'agent.lock'),(Join-Path $serviceState '.peerimeter-agent.profile'),(Join-Path $state '.peerimeter-agent.profile'))) {
        if (Test-Path -LiteralPath $path) { throw "Tracked resource survived full uninstall: $path" }
    }
    foreach ($folder in @($installation,$state,$serviceState)) {
        if ([IO.File]::ReadAllText((Join-Path $folder 'unrelated.txt')) -ne 'unrelated operator file') { throw 'Full uninstall deleted unrelated data' }
    }
    if (-not (Test-Path -LiteralPath $helperExe) -or (Get-FileHash -LiteralPath (Join-Path $dir 'native.key')).Hash -ne $originalKeyHash) { throw 'Full uninstall removed an unrelated helper or original source key' }
    $again = & $Agent uninstall --install-dir $installation | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $again.state -ne 'already_absent') { throw 'Repeated full uninstall was not safe and idempotent' }
    Write-Output 'PASS Windows actual installer inventory, read-only dry-run, live full removal, changed-file refusal, partial-state retry, idempotency and unrelated/source-key preservation'
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
    if ($operatorCreated) { Remove-LocalUser -Name $operatorName -ErrorAction SilentlyContinue }
    Remove-TestDirectory $dir
    Remove-TestDirectory $installation
    Remove-TestDirectory $collisionInstall
    if ($removalResult -and (Test-Path -LiteralPath $removalResult)) { Remove-Item -LiteralPath $removalResult -Force }
}
if ($operatorCreated -and (Get-LocalUser -Name $operatorName -ErrorAction SilentlyContinue)) { throw 'Ephemeral nonadmin test account leaked' }
if ($adapterName -and (Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue)) { throw 'Native Windows adapter remained after cleanup' }
if (Get-NetFirewallRule -DisplayName $udpRule,$tcpRule -ErrorAction SilentlyContinue) { throw 'Temporary firewall rules leaked' }
Write-Output 'PASS Windows agent integration cleanup: no test adapter/routes/service/firewall rules/keys/install directory'
