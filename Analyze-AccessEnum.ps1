param(
    [Parameter(Mandatory)]
    [string]$InputPath,
    [string]$OutputCsv = "AccessEnum_Analysis.csv"
)

# Define critical system paths and ignore paths
$CriticalSystemPaths = @(
    "C:\Windows", "C:\Windows\System32", "C:\Program Files", "C:\Program Files (x86)"
)
$IgnorePaths = @(
    "C:\Users\Public"
)

function Is-InsecurePrincipal {
    param($Principal)
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
    param($Access)
    $a = $Access.ToLower()
    if ($a -match 'full control|modify|write|special') {
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
    $p = $Principal.ToLower()
    if ($p -match 'guest|anonymous|null sid' -or $p -match '^s-1-') {
        return $true
    }
    return $false
}

function Analyze-Entry {
    param($Entry)
    $Path = $Entry.Path
    $Type = $Entry.Type
    $Principal = $Entry.User
    $Access = $Entry.Access
    $Deny = $Entry.Deny

    $Reasons = @()
    $IsNonSecure = $false

    # Rule 1: Guest/Anonymous/Null SID/Unknown SID - any access is insecure
    if (Is-GuestOrAnonymousOrNullOrUnknownSID $Principal) {
        $Reasons += "Guest/Anonymous/Null SID/Unknown SID principal with any access"
        $IsNonSecure = $true
    }
    # Rule 2: Insecure principal with insecure access
    elseif (Is-InsecurePrincipal $Principal -and Is-InsecureAccess $Access) {
        $Reasons += "Insecure principal '$Principal' with access '$Access'"
        $IsNonSecure = $true
    }
    # Rule 3: CREATOR OWNER with Full Control on folders
    if ($Principal.ToLower() -like '*creator owner*' -and $Access.ToLower() -like '*full control*' -and $Type -eq "Folder") {
        $Reasons += "CREATOR OWNER has Full Control on folder"
        $IsNonSecure = $true
    }
    # Rule 4: Deny rules on critical system paths
    if (($Deny -and $Deny -ne "") -and (Is-CriticalSystemPath $Path)) {
        $Reasons += "Deny rule present on critical system path"
        $IsNonSecure = $true
    }

    $Status = if ($IsNonSecure) { "Non-Secure" } else { "Compliant" }
    $ReasonString = if ($Reasons.Count -gt 0) { $Reasons -join "; " } else { "" }

    return [PSCustomObject]@{
        Path = $Path
        Type = $Type
        User = $Principal
        Access = $Access
        Deny = $Deny
        Status = $Status
        Reason = $ReasonString
    }
}

# Read and parse the file
$Results = @()
$InsecureEntries = @()

Import-Csv -Path $InputPath -Delimiter "`t" | ForEach-Object {
    $Analysis = Analyze-Entry $_
    $Results += $Analysis
    if ($Analysis.Status -eq "Non-Secure") {
        $InsecureEntries += $Analysis
    }
}

# Output insecure entries to screen
if ($InsecureEntries.Count -eq 0) {
    Write-Host "No insecure permissions found." -ForegroundColor Green
} else {
    Write-Host "`nInsecure Permissions Detected:`n" -ForegroundColor Red
    foreach ($entry in $InsecureEntries) {
        Write-Host "Path: $($entry.Path)" -ForegroundColor Yellow
        Write-Host "Type: $($entry.Type)"
        Write-Host "User: $($entry.User)"
        Write-Host "Access: $($entry.Access)"
        if ($entry.Deny) { Write-Host "Deny: $($entry.Deny)" }
        Write-Host "Status: $($entry.Status)" -ForegroundColor Cyan
        Write-Host "Reason: $($entry.Reason)" -ForegroundColor Cyan
        Write-Host ("-"*40)
    }
}

# Export all results to CSV
$Results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
Write-Host "`nAnalysis complete. Results saved to $OutputCsv" -ForegroundColor Green 