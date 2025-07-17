param(
    [Parameter(Mandatory)]
    [string]$InputPath,
    [string]$OutputCsv = "AccessEnum_Analysis.csv",
    [string]$ProgressFile = "AccessEnum_Progress.json",
    [int]$BatchSize = 1000
)

# Check if input file exists
if (!(Test-Path $InputPath)) {
    Write-Host "ERROR: Input file '$InputPath' does not exist. Please check the path and try again." -ForegroundColor Red
    exit 1
}

# Dynamic critical system paths
$CriticalSystemPaths = @(
    $env:windir,
    $env:ProgramFiles,
    ${env:ProgramFiles(x86)}
) | Where-Object { $_ -and $_.Trim() -ne "" }
$IgnorePaths = @(
    "C:\Users\Public"
) | Where-Object { $_ -and $_.Trim() -ne "" }

# --- AUDIT AND FIX $WellKnownSIDs USAGE ---
# (Ensure only one definition, all mappings included, and case-insensitive matching)
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
    "S-1-5-64-10" = "NTLM Authentication"
    "S-1-5-64-14" = "SChannel Authentication"
    "S-1-5-64-21" = "Digest Authentication"
    # Application Package Authority
    "S-1-15-2-1" = "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES"
    "S-1-15-2-2" = "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES"
    # Additional NT Authority
    "S-1-5-33" = "NT AUTHORITY\WRITE RESTRICTED"
    "S-1-5-1000" = "NT AUTHORITY\USER MODE DRIVERS"
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
    "S-1-5-32-582" = "Storage Replica Administrators"
    # Service SIDs
    "S-1-5-80-0" = "All Services"
    "S-1-5-90-0" = "Window Manager"
    # Common names and principal strings
    "Everyone" = "World (Everyone)"
    "Users" = "Users"
    "NT AUTHORITY\\Authenticated Users" = "Authenticated Users"
    "NT AUTHORITY\\RESTRICTED" = "Restricted"
    "NT AUTHORITY\\INTERACTIVE" = "Interactive"
    "NT AUTHORITY\\BATCH" = "Batch"
    "NT AUTHORITY\\ANONYMOUS LOGON" = "Anonymous Logon"
    "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES" = "All Application Packages"
    "APPLICATION PACKAGE AUTHORITY\\ALL RESTRICTED APPLICATION PACKAGES" = "All Restricted Application Packages"
    "APPLICATION PACKAGE AUTHORITY\\Software and hardware certificates or a smart card" = "Software/Hardware Certs or Smart Card"
    "Guest (Domain/Local)" = "Guest (Domain/Local)"
    "Domain Account/Group" = "Domain Account/Group"
    "Application Package SID" = "Application Package SID"
    "Capability SID" = "Capability SID"
    "WIN-EMU0LP3FCRP\\tomcat" = "Tomcat Service Account"
}

# Add these mappings to $WellKnownSIDs (after the last entry in the hashtable)
$WellKnownSIDs["S-1-5-32-449500426-4112254358-3456904286-1727260714-2501084857-171973213-3131658879-2198086578"] = "Custom Group 1 (Unknown, please verify)"
$WellKnownSIDs["S-1-5-32-3035980445-2343077072-2039973919-2593655016-2336600711-3402322490-2613491542-1611519126"] = "Custom Group 2 (Unknown, please verify)"
$WellKnownSIDs["NT AUTHORITY\\Authenticated Users"] = "Authenticated Users"
$WellKnownSIDs["World (Everyone)"] = "Everyone"
$WellKnownSIDs["NT AUTHORITY\\RESTRICTED"] = "Restricted"
$WellKnownSIDs["Guest (Domain/Local)"] = "Guest"
$WellKnownSIDs["NT AUTHORITY\\INTERACTIVE"] = "Interactive"
$WellKnownSIDs["WIN-EMU0LP3FCRP\\tomcat"] = "Tomcat Service Account"
$WellKnownSIDs["APPLICATION PACKAGE AUTHORITY\\Software and hardware certificates or a smart card"] = "Software/Hardware Certs or Smart Card"
$WellKnownSIDs["NT AUTHORITY\\BATCH"] = "Batch"
$WellKnownSIDs["NT AUTHORITY\\ANONYMOUS LOGON"] = "Anonymous Logon"

# Cache for resolved SIDs
$global:ResolvedSIDs = @{}
# List to collect unknown SIDs
$global:UnknownSIDs = @()
# List to collect malformed principal inputs
$global:MalformedPrincipals = @()

<#
.SYNOPSIS
    Converts a SID or a comma-separated list of SIDs to friendly names.
.DESCRIPTION
    - Checks if input is a friendly name before attempting SID processing.
    - Uses $WellKnownSIDs for direct matches (case-insensitive).
    - Pattern matches for domain/local SIDs and capability SIDs.
    - Attempts AD and local system lookup for unknown SIDs.
    - Supports SID history resolution if AD module is available.
    - Caches results to improve performance.
    - Logs unknown SIDs and malformed principals silently for review.
.PARAMETER Principal
    The SID string, friendly name, or comma-separated list to convert.
.EXAMPLE
    Convert-SIDToName "S-1-5-32-544"
    Convert-SIDToName "Administrators"
.NOTES
    - Update $WellKnownSIDs or patterns for new SIDs.
    - Review $global:UnknownSIDs and $global:MalformedPrincipals for issues.
#>
function Convert-SIDToName {
    param($Principal)
    if (-not $Principal) { return $Principal }
    $Principal = $Principal.Trim()
    $results = @()

    # Normalization map for common malformed principal strings
    $PrincipalNormalizationMap = @{
        "nt authority\\authenticated users" = "Authenticated Users"
        "world (everyone)" = "Everyone"
        "nt authority\\restricted" = "Restricted"
        "guest (domain/local)" = "Guest"
        "nt authority\\interactive" = "Interactive"
        "win-emu0lp3fcrp\\tomcat" = "Tomcat Service Account"
        "application package authority\\software and hardware certificates or a smart card" = "Software/Hardware Certs or Smart Card"
        "nt authority\\batch" = "Batch"
        "nt authority\\anonymous logon" = "Anonymous Logon"
        "custom group 1 (unknown, please verify)" = "Custom Group 1 (Unknown, please verify)"
        "custom group 2 (unknown, please verify)" = "Custom Group 2 (Unknown, please verify)"
    }

    foreach ($item in $Principal -split ',') {
        $sid = $item.Trim()
        if (-not $sid) { continue }
        # Caching: check if already resolved
        if ($global:ResolvedSIDs.ContainsKey($sid)) {
            $results += $global:ResolvedSIDs[$sid]
            continue
        }
        # Remove parenthetical notes (e.g., (Invalid SID format))
        $sidClean = $sid -replace '\s*\(.*\)$',''
        $sidLower = $sidClean.ToLower()
        $found = $false

        # --- Normalization block for malformed principal strings ---
        if ($PrincipalNormalizationMap.ContainsKey($sidLower)) {
            $results += $PrincipalNormalizationMap[$sidLower]
            $global:ResolvedSIDs[$sid] = $PrincipalNormalizationMap[$sidLower]
            $found = $true
            continue
        }
        # Try to match after removing domain prefix (e.g., 'nt authority\')
        $sidNoDomain = $sidLower -replace '^[^\\]+\\',''
        if ($PrincipalNormalizationMap.ContainsKey($sidNoDomain)) {
            $results += $PrincipalNormalizationMap[$sidNoDomain]
            $global:ResolvedSIDs[$sid] = $PrincipalNormalizationMap[$sidNoDomain]
            $found = $true
            continue
        }
        # Check keys (case-insensitive)
        foreach ($key in $WellKnownSIDs.Keys) {
            if ($sidLower -eq $key.ToLower()) {
                $results += $WellKnownSIDs[$key]
                $global:ResolvedSIDs[$sid] = $WellKnownSIDs[$key]
                $found = $true
                break
            }
        }
        if ($found) { continue }
        # Check values (case-insensitive)
        foreach ($val in $WellKnownSIDs.Values) {
            if ($sidLower -eq $val.ToLower()) {
                $results += $val
                $global:ResolvedSIDs[$sid] = $val
                $found = $true
                break
            }
        }
        if ($found) { continue }

        # Additional friendly name checks for common account names
        if ($sidLower -match '^(nt authority\\)?[a-z\s]+$' -or $sidLower -match '^application package authority\\[a-z\s]+$' -or $sidLower -match '^[a-z0-9\-]+\\[a-z0-9\-]+$') {
            # If not mapped, treat as malformed
            $results += "Malformed Principal: $sid"
            if ($global:MalformedPrincipals -notcontains $sid) { $global:MalformedPrincipals += $sid }
            continue
        }

        # Validate SID format
        if ($sid -notmatch '^S-1-[\d-]+$' -or $sid -eq 'S-1-') {
            $results += "$sid (Invalid SID format)"
            if ($global:MalformedPrincipals -notcontains $sid) { $global:MalformedPrincipals += $sid }
            $global:ResolvedSIDs[$sid] = "$sid (Invalid SID format)"
            continue
        }

        $sidKey = $sid.ToUpper()
        $found = $false

        # Direct match (case-insensitive)
        foreach ($knownSID in $WellKnownSIDs.Keys) {
            if ($sidKey -eq $knownSID.ToUpper()) {
                $results += $WellKnownSIDs[$knownSID]
                $global:ResolvedSIDs[$sid] = $WellKnownSIDs[$knownSID]
                $found = $true
                break
            }
        }
        if ($found) { continue }

        # Pattern matches for domain/local SIDs and capability SIDs
        switch -Regex ($sid) {
            '^S-1-5-21-[\d-]+-500$' { $results += 'Administrator (Domain/Local)'; $global:ResolvedSIDs[$sid] = 'Administrator (Domain/Local)'; $found = $true; break }
            '^S-1-5-21-[\d-]+-501$' { $results += 'Guest (Domain/Local)'; $global:ResolvedSIDs[$sid] = 'Guest (Domain/Local)'; $found = $true; break }
            '^S-1-5-21-[\d-]+-512$' { $results += 'Domain Admins'; $global:ResolvedSIDs[$sid] = 'Domain Admins'; $found = $true; break }
            '^S-1-5-21-[\d-]+-513$' { $results += 'Domain Users'; $global:ResolvedSIDs[$sid] = 'Domain Users'; $found = $true; break }
            '^S-1-5-21-[\d-]+-514$' { $results += 'Domain Guests'; $global:ResolvedSIDs[$sid] = 'Domain Guests'; $found = $true; break }
            '^S-1-5-21-[\d-]+-515$' { $results += 'Domain Computers'; $global:ResolvedSIDs[$sid] = 'Domain Computers'; $found = $true; break }
            '^S-1-5-21-[\d-]+-516$' { $results += 'Domain Controllers'; $global:ResolvedSIDs[$sid] = 'Domain Controllers'; $found = $true; break }
            '^S-1-5-21-[\d-]+-517$' { $results += 'Cert Publishers'; $global:ResolvedSIDs[$sid] = 'Cert Publishers'; $found = $true; break }
            '^S-1-5-21-[\d-]+-518$' { $results += 'Schema Admins'; $global:ResolvedSIDs[$sid] = 'Schema Admins'; $found = $true; break }
            '^S-1-5-21-[\d-]+-519$' { $results += 'Enterprise Admins'; $global:ResolvedSIDs[$sid] = 'Enterprise Admins'; $found = $true; break }
            '^S-1-5-21-[\d-]+-520$' { $results += 'Group Policy Creator Owners'; $global:ResolvedSIDs[$sid] = 'Group Policy Creator Owners'; $found = $true; break }
            '^S-1-5-21-[\d-]+-521$' { $results += 'Read-only Domain Controllers'; $global:ResolvedSIDs[$sid] = 'Read-only Domain Controllers'; $found = $true; break }
            '^S-1-5-21-[\d-]+-\d+$' { $results += 'Domain Account/Group'; $global:ResolvedSIDs[$sid] = 'Domain Account/Group'; $found = $true; break }
            '^S-1-5-32-(\d+)$' {
                $rid = $Matches[1]
                if ($WellKnownSIDs.ContainsKey("S-1-5-32-$rid")) {
                    $results += $WellKnownSIDs["S-1-5-32-$rid"]
                    $global:ResolvedSIDs[$sid] = $WellKnownSIDs["S-1-5-32-$rid"]
                } else {
                    $results += "Builtin Group (RID: $rid)"
                    $global:ResolvedSIDs[$sid] = "Builtin Group (RID: $rid)"
                }
                $found = $true; break
            }
            '^S-1-5-80(-\d+)*$' { $results += 'NT Service Account or All Services'; $global:ResolvedSIDs[$sid] = 'NT Service Account or All Services'; $found = $true; break }
            '^S-1-15-2(-\d+)+$' { $results += 'Application Package SID'; $global:ResolvedSIDs[$sid] = 'Application Package SID'; $found = $true; break }
            '^S-1-15-3(-\d+)+$' { $results += 'Capability SID'; $global:ResolvedSIDs[$sid] = 'Capability SID'; $found = $true; break }
        }
        if ($found) { continue }

        # Try to resolve via AD or local system
        try {
            if ($sid -match '^S-1-\d+(-\d+)+$') {
                $adAvailable = (Get-Command Get-ADUser -ErrorAction SilentlyContinue) -and (Get-Command Get-ADGroup -ErrorAction SilentlyContinue)
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
                $ntAccount = $sidObj.Translate([System.Security.Principal.NTAccount]) -as [string]
                if ($ntAccount) {
                    $results += $ntAccount
                    $global:ResolvedSIDs[$sid] = $ntAccount
                    $found = $true
                } elseif ($adAvailable) {
                    # Try AD user
                    $adUser = Get-ADUser -Filter "objectSid -eq '$sid'" -Properties Name -ErrorAction SilentlyContinue
                    if ($adUser) {
                        $results += $adUser.Name
                        $global:ResolvedSIDs[$sid] = $adUser.Name
                        $found = $true
                    } else {
                        # Try AD group
                        $adGroup = Get-ADGroup -Filter "objectSid -eq '$sid'" -Properties Name -ErrorAction SilentlyContinue
                        if ($adGroup) {
                            $results += $adGroup.Name
                            $global:ResolvedSIDs[$sid] = $adGroup.Name
                            $found = $true
                        }
                    }
                    # Check SID history
                    if ($adAvailable -and -not $found) {
                        $adObjects = Get-ADObject -Filter "sidHistory -eq '$sid'" -Properties Name, objectClass -ErrorAction SilentlyContinue
                        if ($adObjects) {
                            $obj = $adObjects | Select-Object -First 1
                            $results += "$($obj.Name) ($($obj.objectClass) via SIDHistory)"
                            $global:ResolvedSIDs[$sid] = "$($obj.Name) ($($obj.objectClass) via SIDHistory)"
                            $found = $true
                        }
                    }
                }
                # Fallback to local system lookup
                if (-not $found) {
                    $localAccount = Get-WmiObject -Class Win32_Account -Filter "SID='$sid'" -ErrorAction SilentlyContinue
                    if ($localAccount) {
                        $results += $localAccount.Name
                        $global:ResolvedSIDs[$sid] = $localAccount.Name
                        $found = $true
                    }
                }
            }
        } catch {
            # Log silently to avoid console noise
            if ($global:UnknownSIDs -notcontains $sid) { $global:UnknownSIDs += $sid }
        }

        # If not found, log as unknown
        if (-not $found) {
            $results += "$sid (Unknown SID)"
            if ($global:UnknownSIDs -notcontains $sid) { $global:UnknownSIDs += $sid }
            $global:ResolvedSIDs[$sid] = "$sid (Unknown SID)"
        }
    }
    return ($results -join ', ')
}

# Add this helper function near the top (after $WellKnownSIDs and before any function that uses GetFullPath)
function Try-GetFullPath {
    param($Path)
    if (-not $Path -or $Path.Trim() -eq "") { return $null }
    try {
        return [System.IO.Path]::GetFullPath($Path)
    } catch {
        return $null
    }
}

# --- END ADVANCED SID TO NAME MAPPING AND CONVERSION PLATFORM ---

# Whitelist for acceptable Deny rules
$DenyRuleWhitelist = @(
    @{ Principal = "Administrators"; AccessType = "Write"; PathPattern = "C:\ProgramData\*" }
)

function Is-InsecurePrincipal {
    param($Principal)
    $Principal = ($Principal -as [string]).ToLower()
    return ($Principal -match 'guest|anonymous|null sid|everyone|users|authenticated users|interactive|network|creator owner')
}

function Is-CriticalSystemPath {
    param($Path)
    $normalizedPath = Try-GetFullPath $Path
    if (-not $normalizedPath) { return $false }
    foreach ($critical in $CriticalSystemPaths) {
        if (-not $critical) { continue }
        $critNorm = Try-GetFullPath $critical
        if (-not $critNorm) { continue }
        if ($normalizedPath -like "$critNorm*") { return $true }
    }
    return $false
}

function Is-IgnoredPath {
    param($Path)
    $normalizedPath = Try-GetFullPath $Path
    if (-not $normalizedPath) { return $false }
    foreach ($ignore in $IgnorePaths) {
        if (-not $ignore) { continue }
        $ignNorm = Try-GetFullPath $ignore
        if (-not $ignNorm) { continue }
        if ($normalizedPath -like "$ignNorm*") { return $true }
    }
    return $false
}

function Is-SafeDefaultPrincipal {
    param($Principal)
    $Principal = ($Principal -as [string]).ToLower()
    return ($Principal -match '^(nt authority\\system|system|builtin\\administrators|administrators|nt service|local service|network service|trustedinstaller|builtin\\backup operators|builtin\\server operators|domain admins|enterprise admins|schema admins|group policy creator owners|cert publishers|read-only domain controllers|rds management servers|hyper-v administrators)$')
}

# --- BEGIN CUSTOM POLICY TABLE (INLINE EXAMPLE, CAN BE LOADED FROM CSV/JSON) ---
# Each entry: PathPattern, Principal, AccessType, Allowed, Severity, Notes
$CustomPolicy = @(
    @{ PathPattern = 'C:\Data\*'; Principal = 'Domain Users'; AccessType = 'Read'; Allowed = $true; Severity = 'Low'; Notes = 'Business justified read' },
    @{ PathPattern = 'C:\Sensitive\*'; Principal = 'Domain Users'; AccessType = 'Write'; Allowed = $false; Severity = 'High'; Notes = 'No write to sensitive' },
    @{ PathPattern = '*'; Principal = 'Backup Operators'; AccessType = 'Write'; Allowed = $true; Severity = 'Low'; Notes = 'Backup operators allowed' }
    # Add more as needed, or load from CSV/JSON
)

<#
.SYNOPSIS
    Checks if a given Path, Principal, and AccessType is allowed by custom policy.
.DESCRIPTION
    Returns $true (allowed), $false (denied), or $null (no policy match).
    If a match is found, also returns Severity and Notes.
#>
function Is-PolicyCompliant {
    param($Path, $Principal, $AccessType)
    foreach ($rule in $CustomPolicy) {
        if ($Path -like $rule.PathPattern -and $Principal -like "*$($rule.Principal)*" -and $AccessType -eq $rule.AccessType) {
            return @{ Allowed = $rule.Allowed; Severity = $rule.Severity; Notes = $rule.Notes }
        }
    }
    return $null # No policy found
}

# --- END CUSTOM POLICY TABLE ---

# --- BEGIN PRIVILEGED PRINCIPAL DETECTION ---
$PrivilegedSIDs = @(
    'S-1-5-18', # LocalSystem
    'S-1-5-32-544', # Administrators
    'S-1-5-32-551', # Backup Operators
    'S-1-5-32-549', # Server Operators
    'S-1-5-32-550' # Print Operators
    # Add more as needed
)
$PrivilegedNames = @(
    'nt authority\\system', 'system', 'builtin\\administrators', 'administrators',
    'nt service', 'local service', 'network service', 'trustedinstaller',
    'domain admins', 'enterprise admins', 'schema admins', 'group policy creator owners',
    'cert publishers', 'read-only domain controllers', 'rds management servers', 'hyper-v administrators',
    'backup operators', 'server operators', 'print operators'
)
<#
Checks if a principal is privileged by SID or name.
#>
function Is-PrivilegedPrincipal {
    param($Principal, $PrincipalSID)
    $p = $Principal.ToLower()
    if ($PrivilegedNames | Where-Object { $p -like "*$_*" }) { return $true }
    if ($PrivilegedSIDs | Where-Object { $_ -eq $PrincipalSID }) { return $true }
    return $false
}
# --- END PRIVILEGED PRINCIPAL DETECTION ---

# --- BEGIN ADVANCED COMPLIANCE ANALYSIS FUNCTION (THREE-STATE, POLICY-DRIVEN) ---
<#
.SYNOPSIS
    Analyzes a file/folder permission entry for compliance (policy-driven, three-state).
.DESCRIPTION
    - Checks custom policy first (if match, uses policy result).
    - Uses refined privileged user detection.
    - Returns Compliant, Needs Review, or Non-Secure.
    - Severity and ComplianceStatusDetail are set by rule or policy.
    - Prepares for future access type expansion.
    - See summary table in comments for logic.
.PARAMETER Path
    The file or folder path.
.PARAMETER AccessType
    The access type (Read, Write, Deny, etc.).
.PARAMETER Principal
    The user/group/SID.
.PARAMETER DenyValue
    The raw Deny field value.
.NOTES
    - Add new rules in the 'Custom Rules' section.
    - Uses Convert-SIDToName for principal names.
    - Uses Is-PrivilegedPrincipal for privilege detection.
    - Uses Is-PolicyCompliant for business exceptions.
    - See summary table below for logic.

Summary Table for Compliance:
| Principal Type      | Access Type | Path Type      | Default Status | Notes                        |
|---------------------|-------------|----------------|---------------|------------------------------|
| Privileged          | Any         | Any            | Compliant     | Unless Deny (then NeedsReview/Non-Secure) |
| Guest/Anonymous     | Any         | Any            | Non-Secure    |                              |
| Non-Privileged      | Write/Deny  | Critical       | Non-Secure    |                              |
| Non-Privileged      | Write/Deny  | Non-Critical   | Needs Review  |                              |
| Capability SID      | Write       | Critical       | Needs Review  |                              |
| Capability SID      | Read        | Any            | Compliant     |                              |
| Everyone/World      | Write/Deny  | Any            | Non-Secure    |                              |
| Policy Exception    | Any         | Any            | Compliant     | If policy allows             |
#>
function Analyze-Entry {
    param(
        $Path, $AccessType, $Principal, $DenyValue, $OriginalPath
    )
    $Reasons = @()
    $Status = "Compliant"
    $Severity = "Low"
    $ComplianceStatusDetail = "No issues detected"
    $principalName = Convert-SIDToName $Principal
    $principalSID = $Principal
    $principalLower = $principalName.ToLower()
    $accessLower = $AccessType.ToLower()
    $normalizedPath = Try-GetFullPath $Path
    $isCritical = Is-CriticalSystemPath $normalizedPath
    $isIgnored = Is-IgnoredPath $normalizedPath

    # --- Policy Table Check ---
    $policyResult = Is-PolicyCompliant $normalizedPath $principalName $AccessType
    if ($policyResult) {
        if ($policyResult.Allowed) {
            $Status = "Compliant"
            $Severity = $policyResult.Severity
            $ComplianceStatusDetail = "Policy Exception: $($policyResult.Notes)"
            $Reasons += "Allowed by custom policy."
        } else {
            $Status = "Non-Secure"
            $Severity = $policyResult.Severity
            $ComplianceStatusDetail = "Denied by custom policy: $($policyResult.Notes)"
            $Reasons += "Denied by custom policy."
        }
        return [PSCustomObject]@{
            Path = $OriginalPath
            AccessType = $AccessType
            Principal = $principalName
            Deny = $DenyValue
            Status = $Status
            Severity = $Severity
            ComplianceStatusDetail = $ComplianceStatusDetail
            Reason = $Reasons -join '; '
        }
    }

    # --- Deny is always compliant unless overridden by policy ---
    if ($accessLower -eq 'deny') {
        $Status = "Compliant"
        $Severity = "Low"
        $ComplianceStatusDetail = "Access Denied"
        $Reasons += "Access is denied to this principal, so no risk."
        return [PSCustomObject]@{
            Path = $OriginalPath
            AccessType = $AccessType
            Principal = $principalName
            Deny = $DenyValue
            Status = $Status
            Severity = $Severity
            ComplianceStatusDetail = $ComplianceStatusDetail
            Reason = $Reasons -join '; '
        }
    }

    # --- Built-in categories ---
    $isPrivileged = Is-PrivilegedPrincipal $principalName $principalSID
    $isGuestOrAnon = Is-InsecurePrincipal $principalName
    $isUnknownSID = ($Principal -match '^S-1-' -and $principalName -match 'Unknown SID')
    $isCapabilitySID = ($principalName -match 'application package sid|capability sid|application package authority\\')
    $isMalformed = ($principalName -like 'Malformed Principal*')

    # --- Custom Rules Section ---
    if ($isMalformed) {
        $Status = "Needs Review"
        $Severity = "Medium"
        $ComplianceStatusDetail = "Malformed Principal"
        $Reasons += "Principal could not be mapped to a known SID or name."
        return [PSCustomObject]@{
            Path = $OriginalPath
            AccessType = $AccessType
            Principal = $principalName
            Deny = $DenyValue
            Status = $Status
            Severity = $Severity
            ComplianceStatusDetail = $ComplianceStatusDetail
            Reason = $Reasons -join '; '
        }
    }

    if ($isIgnored) {
        $Status = "Compliant (Ignored Path)"
        $Severity = "Low"
        $ComplianceStatusDetail = "Ignored Path"
        $Reasons += "Path is in ignore list. Skipping strict checks."
        return [PSCustomObject]@{
            Path = $OriginalPath
            AccessType = $AccessType
            Principal = $principalName
            Deny = $DenyValue
            Status = $Status
            Severity = $Severity
            ComplianceStatusDetail = $ComplianceStatusDetail
            Reason = $Reasons -join '; '
        }
    }

    if ($isGuestOrAnon -or $isUnknownSID) {
        $Status = "Non-Secure"
        $Severity = "High"
        $ComplianceStatusDetail = if ($isGuestOrAnon) { "Guest/Anonymous Access" } else { "Unknown SID" }
        $Reasons += "Guest/Anonymous/Unknown SID/Non-unique principal with any access is insecure."
    }
    elseif ($isCapabilitySID -and $accessLower -eq 'write' -and $isCritical) {
        $Status = "Needs Review"
        $Severity = "Medium"
        $ComplianceStatusDetail = "Capability SID Write Access to Critical Path"
        $Reasons += "Capability SID has Write access to critical system path."
    }
    elseif ($isCapabilitySID) {
        $Status = "Compliant"
        $Severity = "Low"
        $ComplianceStatusDetail = "Capability SID Detected"
        $Reasons += "Capability SID detected; typically low-risk unless Write on critical paths."
    }
    elseif ($isPrivileged) {
        if ($accessLower -eq 'deny') {
            $Status = "Needs Review"
            $Severity = "Medium"
            $ComplianceStatusDetail = "Privileged Deny Rule"
            $Reasons += "Deny rule for privileged principal may break system functionality."
        } else {
            $Status = "Compliant"
            $Severity = "Low"
            $ComplianceStatusDetail = "Privileged Access"
            $Reasons += "Privileged principal with standard access."
        }
    }
    elseif ($principalLower -match 'world|everyone' -and $accessLower -match 'write|deny') {
        $Status = "Non-Secure"
        $Severity = "High"
        $ComplianceStatusDetail = "Everyone/World Access"
        $Reasons += "'Everyone' or 'World' has $AccessType access. This is highly insecure."
    }
    elseif (-not $isPrivileged -and $accessLower -match 'write|deny') {
        if ($isCritical) {
            $Status = "Non-Secure"
            $Severity = "High"
            $ComplianceStatusDetail = "Non-Privileged Write/Deny on Critical Path"
            $Reasons += "Non-privileged principal has Write/Deny access to critical system path."
        } else {
            $Status = "Needs Review"
            $Severity = "Medium"
            $ComplianceStatusDetail = "Non-Privileged Write/Deny on Non-Critical Path"
            $Reasons += "Non-privileged principal has Write/Deny access to non-critical path."
        }
    }
    else {
        $Status = "Compliant"
        $Severity = "Low"
        $ComplianceStatusDetail = "No issues detected"
        $Reasons += "No issues detected."
    }

    return [PSCustomObject]@{
        Path = $OriginalPath
        AccessType = $AccessType
        Principal = $principalName
        Deny = $DenyValue
        Status = $Status
        Severity = $Severity
        ComplianceStatusDetail = $ComplianceStatusDetail
        Reason = $Reasons -join '; '
    }
}
# --- END ADVANCED COMPLIANCE ANALYSIS FUNCTION (THREE-STATE, POLICY-DRIVEN) ---

# Read and parse the file
$Results = @()
$InsecureEntries = @()
$csvLines = @()

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

# --- Check for progress file and resume if needed ---
$startLine = 0
if (Test-Path $ProgressFile) {
    try {
        $progressData = Get-Content $ProgressFile | ConvertFrom-Json
        $startLine = [int]$progressData.LastProcessedLine + 1
        Write-Host "Resuming from line $startLine (progress file found)..." -ForegroundColor Yellow
    } catch {
        Write-Host "Could not read progress file. Starting from beginning." -ForegroundColor Red
        $startLine = 0
    }
}

# If resuming, skip lines and append to CSV (skip header)
if ($startLine -gt 0) {
    $lines = $lines[$startLine..($lines.Count-1)]
    $appendMode = $true
} else {
    $appendMode = $false
}

# Write header to CSV if not appending
$csvHeader = "Path,AccessType,Principal,Deny,Status,Severity,ComplianceStatusDetail,Reason"
$csvLines = @($csvHeader)
if ($appendMode -and (Test-Path $OutputCsv)) {
    $csvLines = @() # Don't write header if appending
}

# Detect PowerShell version
$pwshVersion = $PSVersionTable.PSVersion.Major
if ($pwshVersion -ge 7) {
    # All required variables for parallel block
    $CriticalSystemPathsCopy = $CriticalSystemPaths
    $IgnorePathsCopy = $IgnorePaths
    $CustomPolicyCopy = $CustomPolicy
    $WellKnownSIDsCopy = $WellKnownSIDs
    $PrivilegedSIDsCopy = $PrivilegedSIDs
    $PrivilegedNamesCopy = $PrivilegedNames

    $Results = $lines | ForEach-Object -Parallel {
        param($line, $CriticalSystemPaths, $IgnorePaths, $CustomPolicy, $WellKnownSIDs, $PrivilegedSIDs, $PrivilegedNames)
        # All helper functions must be defined here
        function Try-GetFullPath {
            param($Path)
            if (-not $Path -or $Path.Trim() -eq "") { return $null }
            try { return [System.IO.Path]::GetFullPath($Path) } catch { return $null }
        }
        function Is-CriticalSystemPath {
            param($Path)
            $normalizedPath = Try-GetFullPath $Path
            if (-not $normalizedPath) { return $false }
            foreach ($critical in $CriticalSystemPaths) {
                if (-not $critical) { continue }
                $critNorm = Try-GetFullPath $critical
                if (-not $critNorm) { continue }
                if ($normalizedPath -like "$critNorm*") { return $true }
            }
            return $false
        }
        function Is-IgnoredPath {
            param($Path)
            $normalizedPath = Try-GetFullPath $Path
            if (-not $normalizedPath) { return $false }
            foreach ($ignore in $IgnorePaths) {
                if (-not $ignore) { continue }
                $ignNorm = Try-GetFullPath $ignore
                if (-not $ignNorm) { continue }
                if ($normalizedPath -like "$ignNorm*") { return $true }
            }
            return $false
        }
        function Is-InsecurePrincipal {
            param($Principal)
            $Principal = ($Principal -as [string]).ToLower()
            return ($Principal -match 'guest|anonymous|null sid|everyone|users|authenticated users|interactive|network|creator owner')
        }
        function Is-PolicyCompliant {
            param($Path, $Principal, $AccessType)
            foreach ($rule in $CustomPolicy) {
                if ($Path -like $rule.PathPattern -and $Principal -like "*$($rule.Principal)*" -and $AccessType -eq $rule.AccessType) {
                    return @{ Allowed = $rule.Allowed; Severity = $rule.Severity; Notes = $rule.Notes }
                }
            }
            return $null
        }
        function Is-PrivilegedPrincipal {
            param($Principal, $PrincipalSID)
            $p = $Principal.ToLower()
            if ($PrivilegedNames | Where-Object { $p -like "*$_*" }) { return $true }
            if ($PrivilegedSIDs | Where-Object { $_ -eq $PrincipalSID }) { return $true }
            return $false
        }
        function Convert-SIDToName {
            param($Principal)
            if (-not $Principal) { return $Principal }
            $Principal = $Principal.Trim()
            $results = @()
            $PrincipalNormalizationMap = @{
                "nt authority\\authenticated users" = "Authenticated Users"
                "world (everyone)" = "Everyone"
                "nt authority\\restricted" = "Restricted"
                "guest (domain/local)" = "Guest"
                "nt authority\\interactive" = "Interactive"
                "win-emu0lp3fcrp\\tomcat" = "Tomcat Service Account"
                "application package authority\\software and hardware certificates or a smart card" = "Software/Hardware Certs or Smart Card"
                "nt authority\\batch" = "Batch"
                "nt authority\\anonymous logon" = "Anonymous Logon"
                "custom group 1 (unknown, please verify)" = "Custom Group 1 (Unknown, please verify)"
                "custom group 2 (unknown, please verify)" = "Custom Group 2 (Unknown, please verify)"
            }
            foreach ($item in $Principal -split ',') {
                $sid = $item.Trim()
                if (-not $sid) { continue }
                $sidClean = $sid -replace '\s*\(.*\)$',''
                $sidLower = $sidClean.ToLower()
                $found = $false
                if ($PrincipalNormalizationMap.ContainsKey($sidLower)) {
                    $results += $PrincipalNormalizationMap[$sidLower]
                    $found = $true
                    continue
                }
                $sidNoDomain = $sidLower -replace '^[^\\]+\\',''
                if ($PrincipalNormalizationMap.ContainsKey($sidNoDomain)) {
                    $results += $PrincipalNormalizationMap[$sidNoDomain]
                    $found = $true
                    continue
                }
                foreach ($key in $WellKnownSIDs.Keys) {
                    if ($sidLower -eq $key.ToLower()) {
                        $results += $WellKnownSIDs[$key]
                        $found = $true
                        break
                    }
                }
                if ($found) { continue }
                foreach ($val in $WellKnownSIDs.Values) {
                    if ($sidLower -eq $val.ToLower()) {
                        $results += $val
                        $found = $true
                        break
                    }
                }
                if ($found) { continue }
                if ($sidLower -match '^(nt authority\\)?[a-z\s]+$' -or $sidLower -match '^application package authority\\[a-z\s]+$' -or $sidLower -match '^[a-z0-9\-]+\\[a-z0-9\-]+$') {
                    $results += "Malformed Principal: $sid"
                    continue
                }
                if ($sid -notmatch '^S-1-[\d-]+$' -or $sid -eq 'S-1-') {
                    $results += "$sid (Invalid SID format)"
                    continue
                }
                $sidKey = $sid.ToUpper()
                $found = $false
                foreach ($knownSID in $WellKnownSIDs.Keys) {
                    if ($sidKey -eq $knownSID.ToUpper()) {
                        $results += $WellKnownSIDs[$knownSID]
                        $found = $true
                        break
                    }
                }
                if ($found) { continue }
                switch -Regex ($sid) {
                    '^S-1-5-21-[\d-]+-500$' { $results += 'Administrator (Domain/Local)'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-501$' { $results += 'Guest (Domain/Local)'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-512$' { $results += 'Domain Admins'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-513$' { $results += 'Domain Users'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-514$' { $results += 'Domain Guests'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-515$' { $results += 'Domain Computers'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-516$' { $results += 'Domain Controllers'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-517$' { $results += 'Cert Publishers'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-518$' { $results += 'Schema Admins'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-519$' { $results += 'Enterprise Admins'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-520$' { $results += 'Group Policy Creator Owners'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-521$' { $results += 'Read-only Domain Controllers'; $found = $true; break }
                    '^S-1-5-21-[\d-]+-\d+$' { $results += 'Domain Account/Group'; $found = $true; break }
                    '^S-1-5-32-(\d+)$' {
                        $rid = $Matches[1]
                        if ($WellKnownSIDs.ContainsKey("S-1-5-32-$rid")) {
                            $results += $WellKnownSIDs["S-1-5-32-$rid"]
                        } else {
                            $results += "Builtin Group (RID: $rid)"
                        }
                        $found = $true; break
                    }
                    '^S-1-5-80(-\d+)*$' { $results += 'NT Service Account or All Services'; $found = $true; break }
                    '^S-1-15-2(-\d+)+$' { $results += 'Application Package SID'; $found = $true; break }
                    '^S-1-15-3(-\d+)+$' { $results += 'Capability SID'; $found = $true; break }
                }
                if ($found) { continue }
                $results += "$sid (Unknown SID)"
            }
            return ($results -join ', ')
        }
        function Analyze-Entry {
            param(
                $Path, $AccessType, $Principal, $DenyValue, $OriginalPath
            )
            $Reasons = @()
            $Status = "Compliant"
            $Severity = "Low"
            $ComplianceStatusDetail = "No issues detected"
            $principalName = Convert-SIDToName $Principal
            $principalSID = $Principal
            $principalLower = $principalName.ToLower()
            $accessLower = $AccessType.ToLower()
            $normalizedPath = Try-GetFullPath $Path
            $isCritical = Is-CriticalSystemPath $normalizedPath
            $isIgnored = Is-IgnoredPath $normalizedPath
            $policyResult = Is-PolicyCompliant $normalizedPath $principalName $AccessType
            if ($policyResult) {
                if ($policyResult.Allowed) {
                    $Status = "Compliant"
                    $Severity = $policyResult.Severity
                    $ComplianceStatusDetail = "Policy Exception: $($policyResult.Notes)"
                    $Reasons += "Allowed by custom policy."
                } else {
                    $Status = "Non-Secure"
                    $Severity = $policyResult.Severity
                    $ComplianceStatusDetail = "Denied by custom policy: $($policyResult.Notes)"
                    $Reasons += "Denied by custom policy."
                }
                return [PSCustomObject]@{
                    Path = $OriginalPath
                    AccessType = $AccessType
                    Principal = $principalName
                    Deny = $DenyValue
                    Status = $Status
                    Severity = $Severity
                    ComplianceStatusDetail = $ComplianceStatusDetail
                    Reason = $Reasons -join '; '
                }
            }
            if ($accessLower -eq 'deny') {
                $Status = "Compliant"
                $Severity = "Low"
                $ComplianceStatusDetail = "Access Denied"
                $Reasons += "Access is denied to this principal, so no risk."
                return [PSCustomObject]@{
                    Path = $OriginalPath
                    AccessType = $AccessType
                    Principal = $principalName
                    Deny = $DenyValue
                    Status = $Status
                    Severity = $Severity
                    ComplianceStatusDetail = $ComplianceStatusDetail
                    Reason = $Reasons -join '; '
                }
            }
            $isPrivileged = Is-PrivilegedPrincipal $principalName $principalSID
            $isGuestOrAnon = Is-InsecurePrincipal $principalName
            $isUnknownSID = ($Principal -match '^S-1-' -and $principalName -match 'Unknown SID')
            $isCapabilitySID = ($principalName -match 'application package sid|capability sid|application package authority\\')
            $isMalformed = ($principalName -like 'Malformed Principal*')
            if ($isMalformed) {
                $Status = "Needs Review"
                $Severity = "Medium"
                $ComplianceStatusDetail = "Malformed Principal"
                $Reasons += "Principal could not be mapped to a known SID or name."
                return [PSCustomObject]@{
                    Path = $OriginalPath
                    AccessType = $AccessType
                    Principal = $principalName
                    Deny = $DenyValue
                    Status = $Status
                    Severity = $Severity
                    ComplianceStatusDetail = $ComplianceStatusDetail
                    Reason = $Reasons -join '; '
                }
            }
            if ($isIgnored) {
                $Status = "Compliant (Ignored Path)"
                $Severity = "Low"
                $ComplianceStatusDetail = "Ignored Path"
                $Reasons += "Path is in ignore list. Skipping strict checks."
                return [PSCustomObject]@{
                    Path = $OriginalPath
                    AccessType = $AccessType
                    Principal = $principalName
                    Deny = $DenyValue
                    Status = $Status
                    Severity = $Severity
                    ComplianceStatusDetail = $ComplianceStatusDetail
                    Reason = $Reasons -join '; '
                }
            }
            if ($isGuestOrAnon -or $isUnknownSID) {
                $Status = "Non-Secure"
                $Severity = "High"
                $ComplianceStatusDetail = if ($isGuestOrAnon) { "Guest/Anonymous Access" } else { "Unknown SID" }
                $Reasons += "Guest/Anonymous/Unknown SID/Non-unique principal with any access is insecure."
            }
            elseif ($isCapabilitySID -and $accessLower -eq 'write' -and $isCritical) {
                $Status = "Needs Review"
                $Severity = "Medium"
                $ComplianceStatusDetail = "Capability SID Write Access to Critical Path"
                $Reasons += "Capability SID has Write access to critical system path."
            }
            elseif ($isCapabilitySID) {
                $Status = "Compliant"
                $Severity = "Low"
                $ComplianceStatusDetail = "Capability SID Detected"
                $Reasons += "Capability SID detected; typically low-risk unless Write on critical paths."
            }
            elseif ($isPrivileged) {
                if ($accessLower -eq 'deny') {
                    $Status = "Needs Review"
                    $Severity = "Medium"
                    $ComplianceStatusDetail = "Privileged Deny Rule"
                    $Reasons += "Deny rule for privileged principal may break system functionality."
                } else {
                    $Status = "Compliant"
                    $Severity = "Low"
                    $ComplianceStatusDetail = "Privileged Access"
                    $Reasons += "Privileged principal with standard access."
                }
            }
            elseif ($principalLower -match 'world|everyone' -and $accessLower -match 'write|deny') {
                $Status = "Non-Secure"
                $Severity = "High"
                $ComplianceStatusDetail = "Everyone/World Access"
                $Reasons += "'Everyone' or 'World' has $AccessType access. This is highly insecure."
            }
            elseif (-not $isPrivileged -and $accessLower -match 'write|deny') {
                if ($isCritical) {
                    $Status = "Non-Secure"
                    $Severity = "High"
                    $ComplianceStatusDetail = "Non-Privileged Write/Deny on Critical Path"
                    $Reasons += "Non-privileged principal has Write/Deny access to critical system path."
                } else {
                    $Status = "Needs Review"
                    $Severity = "Medium"
                    $ComplianceStatusDetail = "Non-Privileged Write/Deny on Non-Critical Path"
                    $Reasons += "Non-privileged principal has Write/Deny access to non-critical path."
                }
            }
            else {
                $Status = "Compliant"
                $Severity = "Low"
                $ComplianceStatusDetail = "No issues detected"
                $Reasons += "No issues detected."
            }
            return [PSCustomObject]@{
                Path = $OriginalPath
                AccessType = $AccessType
                Principal = $principalName
                Deny = $DenyValue
                Status = $Status
                Severity = $Severity
                ComplianceStatusDetail = $ComplianceStatusDetail
                Reason = $Reasons -join '; '
            }
        }
        # Main parallel processing logic
        if ($line.Trim() -eq "") { return $null }
        $fields = $line -split "\t"
        $Path = $fields[0] -replace '"',''
        $Read = $fields[1] -replace '"',''
        $Write = $fields[2] -replace '"',''
        $Deny = $fields[3] -replace '"',''
        $newResults = @()
        foreach ($perm in @(@{"Type"="Read";"Value"=$Read},@{"Type"="Write";"Value"=$Write},@{"Type"="Deny";"Value"=$Deny})) {
            $AccessType = $perm.Type
            $Value = $perm.Value
            if ($Value -and $Value -ne "" -and $Value -ne "Access Denied") {
                $principals = $Value -split ","
                foreach ($principal in $principals) {
                    $principal = $principal.Trim()
                    if ($principal -eq "") { continue }
                    $analysis = Analyze-Entry -Path $Path -AccessType $AccessType -Principal $principal -DenyValue $Deny -OriginalPath $Path
                    $newResults += $analysis
                }
            }
        }
        return $newResults
    } -ArgumentList $CriticalSystemPathsCopy, $IgnorePathsCopy, $CustomPolicyCopy, $WellKnownSIDsCopy, $PrivilegedSIDsCopy, $PrivilegedNamesCopy -ThrottleLimit 4
    # Flatten results (since each parallel task returns an array)
    $Results = $Results | Where-Object { $_ } | ForEach-Object { $_ }
} else {
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
        foreach ($perm in @(@{"Type"="Read";"Value"=$Read},@{"Type"="Write";"Value"=$Write},@{"Type"="Deny";"Value"=$Deny})) {
            $AccessType = $perm.Type
            $Value = $perm.Value
            if ($Value -and $Value -ne "" -and $Value -ne "Access Denied") {
                $principals = $Value -split ","
                foreach ($principal in $principals) {
                    $principal = $principal.Trim()
                    if ($principal -eq "") { continue }
                    $analysis = Analyze-Entry -Path $Path -AccessType $AccessType -Principal $principal -DenyValue $Deny -OriginalPath $Path
                    $Results += $analysis
                    $newResults += $analysis
                }
            }
        }
    }
}
foreach ($result in $Results) {
    $principalFriendly = Convert-SIDToName $result.Principal
    $csvLine = '"' + $result.Path.Replace('"','""') + '","' + $result.AccessType + '","' + $principalFriendly.Replace('"','""') + '","' + $result.Deny.Replace('"','""') + '","' + $result.Status + '","' + $result.Severity + '","' + $result.ComplianceStatusDetail.Replace('"','""') + '","' + $result.Reason.Replace('"','""') + '"'
    $csvLines += $csvLine
}
Set-Content -Path $OutputCsv -Value $csvLines -Encoding UTF8

Write-Host "`nAnalysis complete. Results saved to $OutputCsv" -ForegroundColor Green