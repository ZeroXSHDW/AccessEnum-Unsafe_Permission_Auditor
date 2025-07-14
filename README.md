# AccessEnum Permission Auditor

## Overview

This project includes a PowerShell script, `Analyze-AccessEnum.ps1`, designed to analyze the output from Sysinternals AccessEnum. The script highlights insecure permissions on files and directories, prints a summary to the screen, and generates a detailed CSV report with compliance status for each entry.

## Features
- Parses AccessEnum tab-delimited output files.
- Identifies and highlights insecure permissions based on advanced rules.
- Prints insecure entries to the screen with reasons.
- Generates a CSV file with all entries, including compliance status and reasons.

## Usage

1. Run AccessEnum and export the results as a tab-delimited text file (e.g., `AccessEnum.txt`).
2. Place `Analyze-AccessEnum.ps1` in the same directory as your output file.
3. Open PowerShell and run:
   ```powershell
   .\Analyze-AccessEnum.ps1 -InputPath .\AccessEnum.txt
   ```
   Optionally, specify a custom output CSV:
   ```powershell
   .\Analyze-AccessEnum.ps1 -InputPath .\AccessEnum.txt -OutputCsv .\MyResults.csv
   ```
4. Review the printed insecure permissions and open the generated CSV for a full report.

## Permission Classification

### Insecure Permissions
The following are considered **insecure**:
- Any of these principals with **Full Control**, **Modify**, **Write**, or **Special** access:
  - Everyone
  - Users
  - Authenticated Users
  - Guest / Guests
  - Anonymous Logon
  - INTERACTIVE
  - NETWORK
  - Null SID
  - CREATOR OWNER
- "CREATOR OWNER" with Full Control on folders
- Any Deny rule present on critical system paths (e.g., `C:\Windows`, `C:\Program Files`)
- Unknown or Null SIDs (e.g., entries matching `S-*-*` or "Null SID")

### Secure Permissions
All other permissions not matching the above criteria are considered **secure** ("Compliant").

## Output
- **Screen:** Insecure permissions are printed with path, user, access, and reason.
- **CSV:** All entries are included, with columns for Path, Type, User, Access, Deny, Status (Compliant/Non-Secure), and Reason.

## Customization
You can modify the rules for secure/insecure permissions by editing the arrays and logic in `Analyze-AccessEnum.ps1`. 