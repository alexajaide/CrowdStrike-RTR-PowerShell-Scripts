<#
Script Name: file-process-delete.ps1
Author: Alexa Celestine
Platform: CrowdStrike Falcon RTR

Description:
    CrowdStrike RTR remediation script that identifies processes
    using a specified file and optionally terminates those processes
    and deletes the file.

    Best practice:
      1. Run without the "yes" argument to view processes using the file.
      2. Verify the processes and file.
      3. Run again with the optional "yes" argument to terminate processes and delete the file.

Usage:
    View-only: runscript -CloudFile "file-process-delete" -CommandLine "<filepath>"
    Termination: runscript -CloudFile "file-process-delete" -CommandLine "<filepath> yes"

Input:
    - File path (mandatory)
    - Optional: "yes" to terminate processes and delete the file

Output:
    - List of processes using the file
    - Confirmation of process termination and file deletion (if "yes" is used)

#>

# --- Utility Functions ---

# Convert object to hashtable for structured output
function Convert-Hashtable([Parameter(Mandatory=$true)][psobject]$Object){
    [hashtable]$i=@{}
    $Object.PSObject.Properties |
        Where-Object {![string]::IsNullOrEmpty($_.Value)} |
        ForEach-Object { $i[($_.Name -replace '\s','_' -replace '\W',$null)] = $_.Value }
    return $i
}

# Test if file is locked (in use)
function Test-FileLocked {
    param([string]$Path)
    try {
        $stream = [System.IO.File]::Open($Path, 'Open', 'ReadWrite', 'None')
        $stream.Close()
        return $false
    } catch {
        return $true
    }
}

# Get all processes using a specified file
function Get-DetailedProcessInfoByFileUsage {
    param([string]$FilePath)
    
    $filePathLower = $FilePath.ToLower()
    $matched = Get-CimInstance Win32_Process | Where-Object {
        $_.CommandLine -and $_.CommandLine.ToLower().Contains($filePathLower)
    }

    $result = @()
    foreach ($proc in $matched) {
        try {
            $procInfo = Convert-Hashtable $proc
            $procInfo["Modules"] = ([string[]](Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue).Modules | ForEach-Object { $_.FileName })
            $result += $procInfo
        } catch {}
    }
    return $result
}

# --- Main Script ---
$filePath = $args[0] 

if (-not (Test-Path $filePath)) {
    Write-Output "`nError: File not found at '$filePath'."
    return
}

$fileLocked = Test-FileLocked -Path $filePath
$processInfo = Get-DetailedProcessInfoByFileUsage -FilePath $filePath

Write-Output "`n========== File Usage Check =========="

if ($fileLocked) {
    Write-Output "`nThe file is locked — likely in use or preventing modifications."
    foreach ($proc in $processInfo) {
        Write-Output " - $($proc.ProcessName) (PID: $($proc.ProcessId))"
    }
}
elseif ($processInfo.Count -gt 0) {
    Write-Output "`nThe file is not locked, but it appears to be used by the following process(es):"
    foreach ($proc in $processInfo) {
        Write-Output " - $($proc.ProcessName) (PID: $($proc.ProcessId))"
    }
} else {
    Write-Output "`nThe file is not locked and no processes appear to be using it."
    exit
}

# Check optional termination argument
$termChoice = $args[1]
if(-not [string]::IsNullOrEmpty($termChoice) -and $termChoice.ToLower() -eq "yes"){
    Write-Output "`n========== File Termination Confirmation =========="
    foreach ($proc in $processInfo){
        Stop-Process -Id $proc.ProcessId -Force
        Write-Output "Process '$($proc.Name)' terminated."
    }
    
    Remove-Item -Path $filePath -Force
    Write-Output "File '$($filePath)' deleted."
} else {
    Write-Output "`nTo terminate all processes and delete the file, run the script again with '<filepath> yes' in CommandLine."
}
