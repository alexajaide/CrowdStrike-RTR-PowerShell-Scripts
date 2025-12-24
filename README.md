# CrowdStrike-RTR-PowerShell-Scripts

This repository contains **PowerShell scripts designed for CrowdStrike Falcon RTR**, demonstrating endpoint investigation and remediation workflows.  

---

## Scripts Overview

| Script | Description |
|--------|-------------|
| `user-session-details.ps1` | Retrieves detailed information about a user session, including session ID, SID, user profile, running processes, and recent file activity. |
| `host-details.ps1` | Collects host-level information, including users, sessions, processes, services, event logs, scheduled tasks, network connections, installed software, and command history. |
| `file-process-delete.ps1` | Identifies processes using a specified file and optionally terminates those processes and deletes the file. |
| `file-process-preserve.ps1` | Identifies processes using a specified file and optionally terminates those processes while preserving the file as Read-Only. |

---

## Usage

All scripts are designed to run in the **CrowdStrike Falcon RTR console**. Each script includes instructions in the comments. Common parameters include usernames, session IDs, or file paths.

### Examples

**Neutral CommandLine Input:**
```powershell
runscript -CloudFile "<file-name>" -CommandLine "<optional/mandatory arguments>"


