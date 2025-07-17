param(
    [Parameter(Mandatory)]
    [string]$InputPath,
    [string]$OutputCsv = "AccessEnum_Analysis.csv"
)

# Check if input file exists
if (!(Test-Path $InputPath)) {
    Write-Host "ERROR: Input file '$InputPath' does not exist. Please check the path and try again." -ForegroundColor Red
    exit 1
}

# Define critical system paths and ignore paths
$CriticalSystemPaths = @(
    "C:\Windows", "C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)"
)
$IgnorePaths = @(
    "C:\Users\Public"
)

# --- BEGIN SID TO NAME MAPPING AND CONVERSION PLATFORM ---
# This hashtable maps well-known SIDs to their friendly names. Expand as needed for your environment.
$WellKnownSIDs = @{
    # Universal well-known SIDs
    "S-1-0-0" = "Null SID"
    "S-1-1-0" = "World (Everyone)"
    "S-1-2-0" = "Local"
    "S-1-2-1" = "Console Logon"
    "S-1-3-0" = "Creator Owner ID"
    "S-1-3-1" = "Creator Group ID"
    "S-1-3-2" = "Owner Server"
    "S-1-3-3" = "Group Server"
    "S-1-3-4" = "Owner Rights"
    # NT Authority SIDs
    "S-1-5" = "NT Authority"
    "S-1-5-1" = "Dialup"
    "S-1-5-2" = "Network"
    "S-1-5-3" = "Batch"
    "S-1-5-4" = "Interactive"
    "S-1-5-5" = "Logon Session"
    "S-1-5-6" = "Service"
    "S-1-5-7" = "Anonymous Logon"
    "S-1-5-8" = "Proxy"
    "S-1-5-9" = "Enterprise Domain Controllers"
    "S-1-5-10" = "Self"
    "S-1-5-11" = "Authenticated Users"
    "S-1-5-12" = "Restricted Code"
    "S-1-5-13" = "Terminal Server User"
    "S-1-5-14" = "Remote Interactive Logon"
    "S-1-5-15" = "This Organization"
    "S-1-5-17" = "IUSR"
    "S-1-5-18" = "System (LocalSystem)"
    "S-1-5-19" = "NT Authority (LocalService)"
    "S-1-5-20" = "NetworkService"
    # Built-in groups
    "S-1-5-32-544" = "Administrators"
    "S-1-5-32-545" = "Users"
    "S-1-5-32-546" = "Guests"
    "S-1-5-32-547" = "Power Users"
    "S-1-5-32-548" = "Account Operators"
    "S-1-5-32-549" = "Server Operators"
    "S-1-5-32-550" = "Print Operators"
    "S-1-5-32-551" = "Backup Operators"
    "S-1-5-32-552" = "Replicators"
    "S-1-5-32-554" = "Pre-Windows 2000 Compatible Access"
    "S-1-5-32-555" = "Remote Desktop Users"
    "S-1-5-32-556" = "Network Configuration Operators"
    "S-1-5-32-557" = "Incoming Forest Trust Builders"
    "S-1-5-32-558" = "Performance Monitor Users"
    "S-1-5-32-559" = "Performance Log Users"
    "S-1-5-32-560" = "Windows Authorization Access Group"
    "S-1-5-32-561" = "Terminal Server License Servers"
    "S-1-5-32-562" = "Distributed COM Users"
    "S-1-5-32-568" = "IIS_IUSRS"
    "S-1-5-32-569" = "Cryptographic Operators"
    "S-1-5-32-573" = "Event Log Readers"
    "S-1-5-32-574" = "Certificate Service DCOM Access"
    "S-1-5-32-575" = "RDS Remote Access Servers"
    "S-1-5-32-576" = "RDS Endpoint Servers"
    "S-1-5-32-577" = "RDS Management Servers"
    "S-1-5-32-578" = "Hyper-V Administrators"
    "S-1-5-32-579" = "Access Control Assistance Operators"
    "S-1-5-32-580" = "Remote Management Users"
    # Service SIDs
    "S-1-5-80-0" = "All Services"
    # Add more SIDs as needed for your environment
}

<#[
    SID Conversion Platform Instructions:
    - The $WellKnownSIDs hashtable maps SIDs to friendly names. Expand this table as needed.
    - To add a new SID, add a new entry: "SID string" = "Friendly Name"
    - For domain or custom SIDs, consider implementing pattern matching in Convert-SIDToName (see below).
    - For advanced detection, you can add regex-based rules for SID patterns (e.g., S-1-5-21-... for domain users).
    - This platform is extensible: you can add lookups from AD, external files, or web APIs if needed.
#]>

function Convert-SIDToName {
    <#
    .SYNOPSIS
        Converts a SID string to a friendly name if known, otherwise returns the original value.
    .DESCRIPTION
        Uses the $WellKnownSIDs hashtable for direct matches. For domain SIDs and other patterns, attempts to provide a best-effort description.
        You can expand this function to query Active Directory or other sources for unknown SIDs.
    .PARAMETER Principal
        The SID or name to convert.
    .EXAMPLE
        Convert-SIDToName "S-1-5-32-544" # Returns "Administrators"
    #>
    param($Principal)
    if (-not $Principal) { return $Principal }
    $Principal = $Principal.Trim()
    # Direct match in table
    if ($WellKnownSIDs.ContainsKey($Principal)) {
        return $WellKnownSIDs[$Principal]
    }
    # Pattern match for domain/local accounts (e.g., S-1-5-21-domain-500)
    if ($Principal -match '^S-1-5-21-([\d-]+)-500$') {
        return "Administrator (Domain/Local)"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-501$') {
        return "Guest (Domain/Local)"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-512$') {
        return "Domain Admins"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-513$') {
        return "Domain Users"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-514$') {
        return "Domain Guests"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-515$') {
        return "Domain Computers"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-516$') {
        return "Domain Controllers"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-517$') {
        return "Cert Publishers"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-518$') {
        return "Schema Admins"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-519$') {
        return "Enterprise Admins"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-520$') {
        return "Group Policy Creator Owners"
    }
    if ($Principal -match '^S-1-5-21-([\d-]+)-521$') {
        return "Read-only Domain Controllers"
    }
    # Builtin aliases (RID 544-580)
    if ($Principal -match '^S-1-5-32-(\d+)$') {
        $rid = $Matches[1]
        if ($WellKnownSIDs.ContainsKey("S-1-5-32-$rid")) {
            return $WellKnownSIDs["S-1-5-32-$rid"]
        } else {
            return "Builtin Group (RID: $rid)"
        }
    }
    # Service SIDs
    if ($Principal -match '^S-1-5-80(-\d+)*$') {
        return "NT Service Account or All Services"
    }
    # If it looks like a SID but is unknown, return as-is with a note
    if ($Principal -match '^S-1-\d+(-\d+)+$') {
        return "$Principal (Unknown SID)"
    }
    # Otherwise, return the original principal (likely already a name)
    return $Principal
}
# --- END SID TO NAME MAPPING AND CONVERSION PLATFORM ---

function Is-InsecurePrincipal {
    param($Principal)
    $Principal = ($Principal -as [string])
    $p = $Principal.ToLower()
    if ($p -match 'guest|anonymous|null sid|everyone|users|authenticated users|interactive|network|creator owner') {
        return $true
    }
    if ($p -match '^s-1-') {
        return $true
    }
    return $false
}

function Is-InsecureAccess {
    param($AccessType)
    $a = $AccessType.ToLower()
    if ($a -match 'write|deny') {
        return $true
    }
    return $false
}

function Is-CriticalSystemPath {
    param($Path)
    foreach ($critical in $CriticalSystemPaths) {
        if ($Path -like "$critical*") { return $true }
    }
    return $false
}

function Is-IgnoredPath {
    param($Path)
    foreach ($ignore in $IgnorePaths) {
        if ($Path -like "$ignore*") { return $true }
    }
    return $false
}

function Is-GuestOrAnonymousOrNullOrUnknownSID {
    param($Principal)
    $Principal = ($Principal -as [string])
    $p = $Principal.ToLower()
    if ($p -match 'guest|anonymous|null sid' -or $p -match '^s-1-') {
        return $true
    }
    return $false
}

function Is-SafeDefaultPrincipal {
    param($Principal)
    $Principal = ($Principal -as [string]).ToLower()
    return (
        $Principal -match '^(nt authority\\system|system|builtin\\administrators|administrators|nt service|local service|network service|trustedinstaller)$'
    )
}

function Analyze-Entry {
    param($Path, $AccessType, $Principal, $DenyValue)
    $Reasons = @()
    $IsNonSecure = $false

    # Safe default Windows principals with standard access are compliant
    if (Is-SafeDefaultPrincipal $Principal) {
        # Only flag as Non-Secure if there is an explicit Deny
        if ($AccessType -eq "Deny") {
            $denyUser = if ($Principal) { $Principal } else { "No user/principal specified" }
            $denyValue = if ($DenyValue) { $DenyValue } else { "Unknown" }
            $Reasons += "Deny rule ('$denyValue') present for safe default principal. This may block legitimate access for: $denyUser."
            $IsNonSecure = $true
        } else {
            $Status = "Compliant"
            $ReasonString = "Safe default Windows principal with standard access."
            return [PSCustomObject]@{
                Path = $Path
                AccessType = $AccessType
                Principal = $Principal
                Deny = $DenyValue
                Status = $Status
                Reason = $ReasonString
            }
        }
    }

    # Rule 1: Guest/Anonymous/Null SID/Unknown SID - any access is insecure
    if (Is-GuestOrAnonymousOrNullOrUnknownSID $Principal) {
        $Reasons += "Guest/Anonymous/Null SID/Unknown SID principal with any access"
        $IsNonSecure = $true
    }
    # Rule 2: Insecure principal with insecure access
    elseif (Is-InsecurePrincipal $Principal -and Is-InsecureAccess $AccessType) {
        $Reasons += "Insecure principal '$Principal' with access type '$AccessType'"
        $IsNonSecure = $true
    }
    # Rule 3: CREATOR OWNER with Write/Deny
    if ($Principal.ToLower() -like '*creator owner*' -and ($AccessType -eq "Write" -or $AccessType -eq "Deny")) {
        $Reasons += "CREATOR OWNER has $AccessType access"
        $IsNonSecure = $true
    }
    # Rule 4: Deny rules on critical system paths (improved description)
    if (($AccessType -eq "Deny") -and (Is-CriticalSystemPath $Path)) {
        $denyUser = if ($Principal) { $Principal } else { "No user/principal specified" }
        $denyValue = if ($DenyValue) { $DenyValue } else { "Unknown" }
        $Reasons += "Deny rule ('$denyValue') present on critical system path. This may block legitimate access for: $denyUser."
        $IsNonSecure = $true
    }

    $Status = if ($IsNonSecure) { "Non-Secure" } else { "Compliant" }
    $ReasonString = if ($Reasons.Count -gt 0) { $Reasons -join "; " } else { "" }

    return [PSCustomObject]@{
        Path = $Path
        AccessType = $AccessType
        Principal = $Principal
        Deny = $DenyValue
        Status = $Status
        Reason = $ReasonString
    }
}

# Read and parse the file
$Results = @()
$InsecureEntries = @()

# Read as tab-delimited, skip header
$lines = Get-Content -Path $InputPath
if ($lines.Count -le 1) {
    Write-Host "ERROR: Input file '$InputPath' is empty or only contains a header." -ForegroundColor Red
    exit 1
}
$header = $lines[0] -replace '"','' -split "\t"
$lines = $lines[1..($lines.Count-1)]

$totalLines = $lines.Count
Write-Host "Processing $totalLines entries..." -ForegroundColor Cyan
$lineNum = 0

# Write header to CSV before processing
$csvHeader = "Path,AccessType,Principal,Deny,Status,Reason"
Set-Content -Path $OutputCsv -Value $csvHeader -Encoding UTF8

foreach ($line in $lines) {
    $lineNum++
    if ($lineNum % 1000 -eq 0) {
        Write-Host ("Processed $lineNum of $totalLines lines...") -ForegroundColor DarkGray
    }
    if ($line.Trim() -eq "") { continue }
    $fields = $line -split "\t"
    $Path = $fields[0] -replace '"',''
    $Read = $fields[1] -replace '"',''
    $Write = $fields[2] -replace '"',''
    $Deny = $fields[3] -replace '"',''

    $newResults = @()
    # For each permission type, split by comma and analyze each principal
    foreach ($perm in @(@{"Type"="Read";"Value"=$Read},@{"Type"="Write";"Value"=$Write},@{"Type"="Deny";"Value"=$Deny})) {
        $AccessType = $perm.Type
        $Value = $perm.Value
        if ($Value -and $Value -ne "" -and $Value -ne "Access Denied") {
            $principals = $Value -split ","
            foreach ($principal in $principals) {
                $principal = $principal.Trim()
                if ($principal -eq "") { continue }
                $analysis = Analyze-Entry -Path $Path -AccessType $AccessType -Principal $principal -DenyValue $Deny
                $Results += $analysis
                $newResults += $analysis
                if ($analysis.Status -eq "Non-Secure") {
                    $InsecureEntries += $analysis
                }
            }
        }
    }
    # Append new results to CSV after each line
    if ($newResults.Count -gt 0) {
        $newResults | ForEach-Object {
            $principalFriendly = Convert-SIDToName $_.Principal
            $csvLine = '"' + $_.Path.Replace('"','""') + '","' + $_.AccessType + '","' + $principalFriendly.Replace('"','""') + '","' + $_.Deny.Replace('"','""') + '","' + $_.Status + '","' + $_.Reason.Replace('"','""') + '"'
            Add-Content -Path $OutputCsv -Value $csvLine -Encoding UTF8
        }
    }
}

Write-Host "Processing complete. Writing results..." -ForegroundColor Cyan

# Output insecure entries to screen
if ($InsecureEntries.Count -eq 0) {
    Write-Host "No insecure permissions found." -ForegroundColor Green
} else {
    Write-Host "`nInsecure Permissions Detected:`n" -ForegroundColor Red
    foreach ($entry in $InsecureEntries) {
        Write-Host "Path: $($entry.Path)" -ForegroundColor Yellow
        Write-Host "AccessType: $($entry.AccessType)"
        Write-Host "Principal: $(Convert-SIDToName $entry.Principal)"
        if ($entry.Deny) { Write-Host "Deny: $($entry.Deny)" }
        Write-Host "Status: $($entry.Status)" -ForegroundColor Cyan
        Write-Host "Reason: $($entry.Reason)" -ForegroundColor Cyan
        Write-Host ("-"*40)
    }
}

Write-Host "`nAnalysis complete. Results saved to $OutputCsv" -ForegroundColor Green 