# PowerShell script to use AccessChk to audit permissions of all subdirectories under a specified root directory
# Assumes AccessChk.exe is in the same directory as the script
# Enhanced with privilege elevation, detailed error logging, and symbolic link filtering

# Function to enable privileges (SeSecurityPrivilege and SeBackupPrivilege)
function Enable-Privilege {
    param (
        [string]$Privilege
    )
    $whoami = whoami /priv
    if ($whoami -notmatch $Privilege) {
        Write-Host "Attempting to enable $Privilege..."
        try {
            # Use a simple .NET method to adjust token privileges (requires admin)
            Add-Type -TypeDefinition @"
                using System;
                using System.Runtime.InteropServices;
                public class TokenAdjuster {
                    [DllImport("advapi32.dll", SetLastError=true)]
                    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
                    [DllImport("advapi32.dll", SetLastError=true)]
                    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref Int64 lpLuid);
                    [StructLayout(LayoutKind.Sequential)]
                    public struct TOKEN_PRIVILEGES {
                        public int PrivilegeCount;
                        public Int64 Luid;
                       车辆
                        public int Attributes;
                    }
                    public const int SE_PRIVILEGE_ENABLED = 0x00000002;
                    public static void EnablePrivilege(string privilege) {
                        IntPtr token;
                        TOKEN_PRIVILEGES tp;
                        tp.PrivilegeCount = 1;
                        tp.Luid = 0;
                        tp.Attributes = SE_PRIVILEGE_ENABLED;
                        if (!OpenThreadToken(GetCurrentThread(), 0x0020, true, out token)) {
                            OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token);
                        }
                        LookupPrivilegeValue(null, privilege, ref tp.Luid);
                        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                    }
                    [DllImport("kernel32.dll")]
                    public static extern IntPtr GetCurrentThread();
                    [DllImport("kernel32.dll")]
                    public static extern IntPtr GetCurrentProcess();
                    [DllImport("advapi32.dll", SetLastError=true)]
                    public static extern bool OpenThreadToken(IntPtr ThreadHandle, int DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);
                    [DllImport("advapi32.dll", SetLastError=true)]
                    public static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);
                }
"@
            [TokenAdjuster]::EnablePrivilege($Privilege)
            Write-Host "$Privilege enabled successfully."
        }
        catch {
            Write-Host "Warning: Failed to enable $Privilege - $($_.Exception.Message)"
        }
    }
}

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

# Attempt to enable necessary privileges
Enable-Privilege -Privilege "SeSecurityPrivilege"
Enable-Privilege -Privilege "SeBackupPrivilege"

# Define output CSV and log file paths (in the script's directory with timestamp)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = ".\SubDirPermissionsReport_$Timestamp.csv"
$ErrorLogFile = ".\SubDirPermissionsErrors_$Timestamp.log"

# Initialize CSV header and content
$CsvHeader = "Directory,UserOrGroup,Permissions,AccessType"
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

# Track skipped directories
$SkippedDirs = @()

# Check permissions for each subdirectory using AccessChk
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
    
    # Run AccessChk in directory mode (-d) to get permissions
    try {
        $AccessChkOutput = & $AccessChkPath -d -q "$DirPath" 2>&1
        if ($LASTEXITCODE -ne 0) {
            $ErrorMessage = "AccessChk failed for: $DirPath - Exit Code: $LASTEXITCODE - Output: $AccessChkOutput"
            Write-Host "Warning: $ErrorMessage"
            $ErrorLog += $ErrorMessage
            $SkippedDirs += $DirPath
            continue
        }
    }
    catch {
        $ErrorMessage = "AccessChk error for: $DirPath - Error: $($_.Exception.Message)"
        Write-Host "Warning: $ErrorMessage"
        $ErrorLog += $ErrorMessage
        $SkippedDirs += $DirPath
        continue
    }
    
    # Parse AccessChk output
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
            
            # Add to CSV content
            $CsvContent += "$DirPath,$CurrentUserOrGroup,$Permission,$AccessType"
        }
    }
}

# Write to CSV file
$CsvContent | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host "Permissions report generated at: $OutputFile"

# Write error log
$ErrorLog += "Total directories skipped: $($SkippedDirs.Count)"
if ($SkippedDirs.Count -gt 0) {
    $ErrorLog += "Skipped directories:"
    $ErrorLog += $SkippedDirs
}
$ErrorLog | Out-File -FilePath $ErrorLogFile -Encoding UTF8
Write-Host "Error log generated at: $ErrorLogFile"

# Summary
$TotalDirs = $SubDirs.Count
$ProcessedDirs = $TotalDirs - $SkippedDirs.Count
Write-Host "Total directories scanned: $TotalDirs"
Write-Host "Directories processed: $ProcessedDirs"
Write-Host "Directories skipped: $($SkippedDirs.Count)"
Write-Host "Script completed."
