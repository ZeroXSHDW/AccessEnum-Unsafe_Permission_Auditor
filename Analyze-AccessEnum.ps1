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
            $csvLine = '"' + $_.Path.Replace('"','""') + '","' + $_.AccessType + '","' + $_.Principal.Replace('"','""') + '","' + $_.Deny.Replace('"','""') + '","' + $_.Status + '","' + $_.Reason.Replace('"','""') + '"'
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
        Write-Host "Principal: $($entry.Principal)"
        if ($entry.Deny) { Write-Host "Deny: $($entry.Deny)" }
        Write-Host "Status: $($entry.Status)" -ForegroundColor Cyan
        Write-Host "Reason: $($entry.Reason)" -ForegroundColor Cyan
        Write-Host ("-"*40)
    }
}

Write-Host "`nAnalysis complete. Results saved to $OutputCsv" -ForegroundColor Green 