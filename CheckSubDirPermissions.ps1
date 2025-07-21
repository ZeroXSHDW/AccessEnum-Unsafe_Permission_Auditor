# PowerShell script to use AccessChk to audit permissions of all subdirectories under a specified root directory
# Assumes AccessChk.exe is in the same directory as the script
# Enhanced with detailed error logging, symbolic link filtering, and Get-Acl fallback
# Does not attempt to set SeSecurityPrivilege, SeBackupPrivilege, or other privileges

# Check if a root directory is provided as a command-line argument
if ($args.Count -eq 0) {
    Write-Host "Error: Please provide a root directory path as a command-line argument."
    Write-Host "Usage: .\CheckSubDirPermissions.ps1 <RootDirectoryPath>"
    exit 1
}

# Get the root directory from command-line argument
$RootDir = $args[0]

# Validate if the directory exists
if (-not (Test-Path $RootDir -PathType Container)) {
    Write-Host "Error: The specified directory '$RootDir' does not exist or is not a directory."
    exit 1
}

# Define AccessChk path in the current directory
$AccessChkPath = ".\accesschk.exe"

# Ensure AccessChk exists in the current directory
if (-not (Test-Path $AccessChkPath)) {
    Write-Host "Error: accesschk.exe not found in the current directory. Please ensure it is placed in the same directory as this script."
    exit 1
}

# Define output CSV and log file paths (in the script's directory with timestamp)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = ".\SubDirPermissionsReport_$Timestamp.csv"
$ErrorLogFile = ".\SubDirPermissionsErrors_$Timestamp.log"

# Initialize CSV header and content
$CsvHeader = "Directory,UserOrGroup,Permissions,AccessType,Source"
$CsvContent = @()
$CsvContent += $CsvHeader

# Initialize error log
$ErrorLog = @()
$ErrorLog += "AccessChk Permission Check Error Log - $Timestamp"

# List of system directories to skip
$ExcludedDirs = @(
    "C:\System Volume Information",
    "C:\$Recycle.Bin",
    "C:\Windows",
    "C:\Program Files",
    "C:\Program Files (x86)"
)

# Get all subdirectories recursively, excluding system directories and symbolic links
$SubDirs = Get-ChildItem -Path $RootDir -Directory -Recurse -ErrorAction SilentlyContinue |
    Where-Object {
        $FullPath = $_.FullName
        # Skip excluded directories and symbolic links/junctions
        (-not ($ExcludedDirs | Where-Object { $FullPath -like "$_*" })) -and
        (-not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint))
    }

# Track skipped and fallback directories
$SkippedDirs = @()
$FallbackDirs = @()

# Check permissions for each subdirectory using AccessChk, with Get-Acl fallback
foreach ($Dir in $SubDirs) {
    $DirPath = $Dir.FullName
    Write-Host "Checking permissions for: $DirPath"
    
    # Check if the directory is accessible
    try {
        $null = Get-Item -Path $DirPath -ErrorAction Stop
    }
    catch {
        $ErrorMessage = "Inaccessible directory: $DirPath - Error: $($_.Exception.Message)"
        Write-Host "Warning: $ErrorMessage"
        $ErrorLog += $ErrorMessage
        $SkippedDirs += $DirPath
        continue
    }
    
    # Try AccessChk first
    $AccessChkSuccess = $false
    try {
        $AccessChkOutput = & $AccessChkPath -d -q "$DirPath" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $AccessChkSuccess = $true
        }
        else {
            $ErrorMessage = "AccessChk failed for: $DirPath - Exit Code: $LASTEXITCODE - Output: $AccessChkOutput"
            Write-Host "Warning: $ErrorMessage"
            $ErrorLog += $ErrorMessage
        }
    }
    catch {
        $ErrorMessage = "AccessChk error for: $DirPath - Error: $($_.Exception.Message)"
        Write-Host "Warning: $ErrorMessage"
        $ErrorLog += $ErrorMessage
    }
    
    # Parse AccessChk output if successful
    if ($AccessChkSuccess) {
        $CurrentUserOrGroup = ""
        foreach ($Line in $AccessChkOutput) {
            $Line = $Line.Trim()
            
            # Skip empty lines or lines starting with certain characters
            if ([string]::IsNullOrWhiteSpace($Line) -or $Line.StartsWith("AccessChk") -or $Line.StartsWith("---")) {
                continue
            }
            
            # Check if the line is a user or group name
            if ($Line -notmatch "^\s") {
                $CurrentUserOrGroup = $Line
            }
            else {
                # Line is a permission entry
                $Permission = $Line.Trim()
                # Determine access type (Allow or Deny)
                $AccessType = if ($Permission -match "DENY") { "Deny" } else { "Allow" }
                # Clean up permission string (remove DENY prefix if present)
                $Permission = $Permission -replace "^DENY\s*", ""
                
                # Add to CSV content with AccessChk as source
                $CsvContent += "$DirPath,$CurrentUserOrGroup,$Permission,$AccessType,AccessChk"
            }
        }
    }
    else {
        # Fallback to Get-Acl for failed directories
        $FallbackDirs += $DirPath
        Write-Host "Attempting fallback with Get-Acl for: $DirPath"
        try {
            $Acl = Get-Acl -Path $DirPath -ErrorAction Stop
            foreach ($Access in $Acl.Access) {
                $UserOrGroup = $Access.IdentityReference
                $Permissions = $Access.FileSystemRights
                $AccessType = if ($Access.AccessControlType -eq "Deny") { "Deny" } else { "Allow" }
                # Add to CSV content with Get-Acl as source
                $CsvContent += "$DirPath,$UserOrGroup,$Permissions,$AccessType,Get-Acl"
            }
        }
        catch {
            $ErrorMessage = "Get-Acl failed for: $DirPath - Error: $($_.Exception.Message)"
            Write-Host "Warning: $ErrorMessage"
            $ErrorLog += $ErrorMessage
            $SkippedDirs += $DirPath
        }
    }
}

# Write to CSV file
$CsvContent | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Permissions report generated at: $OutputFile"

# Write error log
$ErrorLog += "Total directories skipped: $($SkippedDirs.Count)"
$ErrorLog += "Total directories using Get-Acl fallback: $($FallbackDirs.Count)"
if ($SkippedDirs.Count -gt 0) {
    $ErrorLog += "Skipped directories:"
    $ErrorLog += $SkippedDirs
}
if ($FallbackDirs.Count -gt 0) {
    $ErrorLog += "Fallback directories (using Get-Acl):"
    $ErrorLog += $FallbackDirs
}
$ErrorLog | Out-File -FilePath $ErrorLogFile -Encoding UTF8
Write-Host "Error log generated at: $ErrorLogFile"

# Summary
$TotalDirs = $SubDirs.Count
$ProcessedDirs = $TotalDirs - $SkippedDirs.Count
Write-Host "Total directories scanned: $TotalDirs"
Write-Host "Directories processed (AccessChk): $($ProcessedDirs - $FallbackDirs.Count)"
Write-Host "Directories processed (Get-Acl fallback): $($FallbackDirs.Count)"
Write-Host "Directories skipped: $($SkippedDirs.Count)"
Write-Host "Script completed."
