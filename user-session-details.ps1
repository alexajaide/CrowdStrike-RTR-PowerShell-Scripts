<#
Script Name: user-session-details.ps1
Author: Alexa Celestine
Platform: CrowdStrike Falcon RTR

Description:
    CrowdStrike RTR remediation script that takes a user session ID or username
    and performs a session-level investigation by collecting:
      - User session details
      - User SID and profile path
      - Running processes associated with the session
      - Recently created or modified files (last 2 hours)

Usage:
    1. Retrieve the session ID using:
        quser
    2. Run the script in the CrowdStrike RTR console:
        runscript -CloudFile "user-session-details" -CommandLine "<SessionID or Username>"
    3. To terminate a session after review:
        logoff <SessionID>

Purpose:
    Supports endpoint investigation and remediation workflows within
    CrowdStrike Falcon RTR.

Input:
    Username or session ID

Output:
    Formatted tables displaying:
      - User session details
      - Running processes
      - Recent file activity

#>

param(
    [Parameter(Mandatory)]
    [string]$Identity
)

# Retrieve session info
$session = quser 2>$null |
Where-Object {$_ -match '\s+\d+\s+'} |
ForEach-Object {
    $parts = ($_ -replace '\s{2,}', '|') -split '\|'
    [PSCustomObject]@{Username=$parts[0].Trim(); Id=[int]$parts[2]}
} | Where-Object { $_.Username -ieq $Identity -or $_.Id -eq $Identity } | Select-Object -First 1

if (-not $session) {
    Write-Output "No session found for identity: $Identity"
    exit
}

$username = $session.Username
$sessionId = $session.Id
$userPath = "C:\Users\$username"

# SID retrieval
$sid = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
Where-Object { (Get-ItemProperty $_.PSPath).ProfileImagePath -like "*\$username" } |
Select-Object -ExpandProperty PSChildName -First 1)

# Output user session info
Write-Output "`n=== USER SESSION DETAILS ==="
$userInfo = [PSCustomObject]@{
    Username = $username
    SessionID = $sessionId
    SID = $sid
    UserProfile = $userPath
}
Write-Output ($userInfo | Format-Table -AutoSize | Out-String)

# Retrieve running processes for user session
try {
    $allProcs = Get-WmiObject Win32_Process -ErrorAction SilentlyContinue
    $userProcs = @()

    foreach ($proc in $allProcs) {
        $owner = $null
        try { $owner = $proc.GetOwner() } catch { continue }
        if ($owner -and $owner.User -ieq $username) {
            $userProcs += [PSCustomObject]@{
                Name = $proc.Name
                PID = $proc.ProcessId
                ParentPID = $proc.ParentProcessId
                CommandLine = $proc.CommandLine
            }
        }
    }

    if ($userProcs.Count -gt 0) {
        Write-Output "=== RUNNING PROCESSES (Alphabetical) ==="
        Write-Output ($userProcs | Sort-Object Name | Format-Table Name, PID, ParentPID, CommandLine -AutoSize | Out-String)
    } else {
        Write-Output "No running processes found for user."
    }
} catch {
    Write-Output "Failed to retrieve process list."
}

Write-Output ""

# Retrieve recent file activity
if (Test-Path $userPath) {
    $files = @()
    $counter = 0
    $maxFiles = 5000

    try {
        Get-ChildItem -Path $userPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.LastWriteTime -gt (Get-Date).AddHours(-2) -or
            $_.CreationTime -gt (Get-Date).AddHours(-2) -or
            $_.LastAccessTime -gt (Get-Date).AddHours(-2)
        } |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object {
            if ($counter -ge $maxFiles) { return }
            $files += [PSCustomObject]@{
                FileName = $_.FullName
                Created = $_.CreationTime
                Modified = $_.LastWriteTime
                LastAccessed = $_.LastAccessTime
            }
            $counter++
        }

        if ($files.Count -gt 0) {
            Write-Output "=== RECENT FILE ACTIVITY (Last 2 Hours) ==="
            Write-Output ($files | Format-Table Created, Modified, LastAccessed, FileName -AutoSize | Out-String)
        } else {
            Write-Output "No file activity in the last 2 hours."
        }
    } catch {
        Write-Output "Failed to retrieve file activity."
    }
} else {
    Write-Output "User path $userPath does not exist or is inaccessible."
}

