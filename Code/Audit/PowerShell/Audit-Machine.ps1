[Cmdletbinding()]
Param(
    # The target we want to probe
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$Target,

    # Credentials object
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [System.Object[]]$Credentials
)

# Set E|P|W prefs and start time
$ErrorActionPreference = "Stop";
$ProgressPreference = "SilentlyContinue";
$WarningPreference = "SilentlyContinue";
$StartTime = Get-Date;

# Import the utils module
try {
    Import-Module "$PSScriptRoot\Utility.psm1" -Force -DisableNameChecking;
} catch {
    throw "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Error] Error importing utility module: $($_.Exception.Message)";
}

# Add a probe object to our target
$Target | Add-Member -MemberType NoteProperty -Name Audit -Value $(New-Audit);

