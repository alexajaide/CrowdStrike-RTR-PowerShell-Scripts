# CrowdStrike-RTR-PowerShell-Scripts

This repository contains PowerShell scripts designed for **CrowdStrike Falcon RTR** to demonstrate endpoint investigation and remediation workflows.

## Scripts Overview

| Script | Description |
|--------|-------------|
| `user-session-details.ps1` | Retrieves detailed information about a user session, including session ID, SID, and user profile. |
| `host-details.ps1` | Collects host-level details for a machine, such as system info and configuration data. |
| `process-file-delete.ps1` | Reads a list of running processes and files, then deletes specified processes and associated files. |
| `process-file-preserve.ps1` | Reads a list of running processes and files, deletes specified processes while preserving specified files. |

## Usage

Each script includes instructions in the comments on how to run it in the CrowdStrike RTR console. Parameters typically include usernames, session IDs, or file paths.

Example (user session details):
```powershell
runscript -CloudFile "user-session-details" -CommandLine "<Username or SessionID>"

