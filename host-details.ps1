<#
Script Name: host-details.ps1
Author: Alexa Celestine
Platform: CrowdStrike Falcon RTR

Description:
    CrowdStrike RTR remediation script that collects host-level information
    for endpoint investigation. Retrieves:
      - Local users and active sessions
      - Running processes
      - Services
      - Security and PowerShell event logs
      - Scheduled tasks
      - Network connections
      - Installed software from registry
      - Command history (PowerShell, cmd.exe, WSL)

Usage:
    Run this script in the CrowdStrike RTR console:
        runscript -CloudFile "host-details"

Purpose:
    Supports endpoint investigation and remediation workflows within
    CrowdStrike Falcon RTR.

Output:
    Formatted tables displaying all collected host information

#>

# === USER / ACCOUNT INFORMATION ===
Write-Output "=== USER INFORMATION ==="

# Get local users from CIM and Get-LocalUser (merged)
$cimUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" |
Select-Object Name, Domain, SID, Disabled, Lockout

$localUsers = Get-LocalUser |
Select-Object Name, @{Name='Domain';Expression={'Local'}}, SID,
@{Name='Disabled';Expression={!$_.Enabled}},
@{Name='Lockout';Expression={'Unknown'}}

$allLocalUsers = @{}
foreach ($user in $cimUsers) { $allLocalUsers[$user.Name.ToLower()] = $user }
foreach ($user in $localUsers) { if (-not $allLocalUsers.ContainsKey($user.Name.ToLower())) { $allLocalUsers[$user.Name.ToLower()] = $user } }

# Get active user sessions
$sessionsRaw = quser 2>$null | Where-Object { $_ -match '\s+\d+\s+' }
$sessions = foreach ($line in $sessionsRaw) {
    $parts = ($line -replace '\s{2,}', '|') -split '\|'
    [PSCustomObject]@{
        Username = $parts[0].Trim()
        SessionId = [int]$parts[2]
        State = $parts[3].Trim()
        IdleTime = $parts[4].Trim()
        LogonTime = $parts[5].Trim()
    }
}

# Get members of Administrators group
try {
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop | Select-Object -ExpandProperty Name
} catch {
    $admins = @()
}

# Build user objects
$userResults = foreach ($user in $allLocalUsers.Values) {
    $isAdmin = $admins -contains $user.Name
    [PSCustomObject]@{
        Username = $user.Name
        Domain = $user.Domain
        SID = $user.SID
        Disabled = $user.Disabled
        LockedOut = $user.Lockout
        Admin = $isAdmin
        LoggedIn = $false
        SessionId = $null
        SessionState = $null
        LogonTime = $null
    }
}

# Add session info to users
foreach ($session in $sessions) {
    if ([string]::IsNullOrWhiteSpace($session.Username) -or $session.Username -eq 'USERNAME') { continue }

    $existing = $userResults | Where-Object { $_.Username -eq $session.Username }
    if ($existing) {
        foreach ($u in $existing) {
            $u.LoggedIn = $true
            $u.SessionId = $session.SessionId
            $u.SessionState = $session.State
            $u.LogonTime = $session.LogonTime
        }
        continue
    }

    # Domain and SID best-effort
    try {
        $userInfo = Get-CimInstance -ClassName Win32_Account -Filter "Name='$($session.Username)'" -ErrorAction SilentlyContinue | Select-Object -First 1
    } catch {
        $userInfo = $null
    }

    $domain = if ($userInfo) { $userInfo.Domain } else { "Unknown" }
    $sid = if ($userInfo) { $userInfo.SID } else { "Unknown" }
    $isAdmin = $admins -contains $session.Username

    $userResults += [PSCustomObject]@{
        Username = $session.Username
        Domain = $domain
        SID = $sid
        Disabled = $false
        LockedOut = 'Unknown'
        Admin = $isAdmin
        LoggedIn = $true
        SessionId = $session.SessionId
        SessionState = $session.State
        LogonTime = $session.LogonTime
    }
}

Write-Output($userResults | Sort-Object -Property @{Expression = 'LoggedIn';Descending=$true}, 'Username' | Format-Table -AutoSize | Out-String)

# === PROCESSES ===
Write-Output "`n=== PROCESS INFORMATION ==="
try {
    $processes = Get-Process
    $procResults = @()
    foreach ($proc in $processes) {
        $owner = "N/A"
        try {
            $wmiProc = Get-WmiObject Win32_Process -Filter "ProcessId=$($proc.Id)" -ErrorAction Stop
            $ownerInfo = $wmiProc.GetOwner()
            if ($ownerInfo.ReturnValue -eq 0) { $owner = $ownerInfo.User }
        } catch {}
        try { $startTime = $proc.StartTime } catch { $startTime = "N/A" }

        $procResults += [PSCustomObject]@{
            Name = $proc.Name
            PID = $proc.Id
            CPU = $proc.CPU
            MemoryMB = [Math]::Round($proc.WorkingSet64 / 1MB, 2)
            StartTime= $startTime
            Owner = $owner
        }
    }
    Write-Output($procResults | Sort-Object Name, Owner | Format-Table -AutoSize | Out-String)
} catch {
    Write-Output "Failed to retrieve processes."
}

# === SERVICES ===
Write-Output "`n=== SERVICE INFORMATION ==="
try {
    $services = Get-CimInstance -ClassName Win32_Service
    $serviceResults = $services | Select-Object Name, DisplayName, State, StartMode, Status, @{Name='PID';Expression={$_.ProcessId}}
    Write-Output($serviceResults | Format-Table -AutoSize | Out-String)
} catch { Write-Output "Failed to retrieve services." }

# === EVENT LOGS ===
Write-Output "`n=== SECURITY EVENT LOG (Last 50 entries) ==="
try {
    $secEvents = Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($secEvents) { Write-Output ($secEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize | Out-String) }
    else { Write-Output "No security events found." }
} catch { Write-Output "Failed to retrieve security event logs." }

# === SCHEDULED TASKS ===
Write-Output "`n=== SCHEDULED TASKS ==="
try {
    $tasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State
    Write-Output ($tasks | Format-Table -AutoSize | Out-String)
} catch { Write-Output "Failed to retrieve scheduled tasks." }

# === NETWORK CONNECTIONS ===
Write-Output "`n=== NETWORK CONNECTIONS ==="
try {
    $netConns = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, @{Name='ProcessName';Expression={try {(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName} catch {"N/A"}}}
    Write-Output ($netConns | Format-Table -AutoSize | Out-String)
} catch { Write-Output "Failed to retrieve network connections." }

# === INSTALLED SOFTWARE (Registry) ===
Write-Output "`n=== INSTALLED SOFTWARE FROM REGISTRY ==="
try {
    $installedSoftware = Get-ChildItem 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object { $_.DisplayName }
    Write-Output ($installedSoftware | Format-Table -AutoSize | Out-String)
} catch { Write-Output "Failed to retrieve installed software." }

# === COMMAND HISTORY ===
Write-Output "`n=== COMMAND HISTORY ==="

# PowerShell PSReadLine history
Write-Output "`n--- PowerShell PSReadLine History ---"
try {
    $loadedProfiles = Get-CimInstance Win32_UserProfile | Where-Object { $_.Loaded -eq $true -and $_.LocalPath -match "Users" }
    foreach ($profile in $loadedProfiles) {
        $psHistoryPath = Join-Path $profile.LocalPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $psHistoryPath) {
            Write-Output "`nPowerShell history for user at $($profile.LocalPath):"
            Write-Output (Get-Content $psHistoryPath -ErrorAction SilentlyContinue | Select-Object -Last 20 | Out-String)
        }
    }
} catch { Write-Output "Failed to retrieve PowerShell history." }

# Cmd.exe related registry keys
Write-Output "`n--- Cmd.exe Registry Keys ---"
try {
    $regKeys = @("HKCU:\Software\Microsoft\Command Processor","HKLM:\Software\Microsoft\Command Processor")
    foreach ($key in $regKeys) {
        if (Test-Path $key) {
            Write-Output "`nCmd.exe Registry History Keys: $key"
            Get-ItemProperty -Path $key | Format-List | Out-String | Write-Output
        }
    }
} catch { Write-Output "Failed to retrieve cmd.exe registry keys." }

# WSL Bash history
Write-Output "`n--- WSL Bash History ---"
try {
    foreach ($profile in $loadedProfiles) {
        $bashHistoryPath = Join-Path $profile.LocalPath "AppData\Local\Packages\CanonicalGroupLimited*\\LocalState\\rootfs\\home\\*\\.bash_history"
        $bashHistoryFiles = Get-ChildItem -Path $bashHistoryPath -ErrorAction SilentlyContinue
        foreach ($file in $bashHistoryFiles) {
            Write-Output "`nWSL Bash history for user at $($profile.LocalPath):"
            Get-Content $file -ErrorAction SilentlyContinue | Select-Object -Last 20 | Out-String | Write-Output
        }
    }
} catch { Write-Output "Failed to retrieve WSL bash history." }

# PowerShell Operational Logs
Write-Output "`n--- PowerShell Operational Event Logs (Last 50 entries) ---"
try {
    $psEvents = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue
    if ($psEvents) { Write-Output ($psEvents | Select-Object TimeCreated, Id, LevelDisplayName, Message | Format-Table -AutoSize | Out-String) }
    else { Write-Output "No PowerShell operational events found." }
} catch { Write-Output "Failed to retrieve PowerShell operational event logs." }

# === SCRIPT COMPLETION ===
Write-Output "`nScript completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

