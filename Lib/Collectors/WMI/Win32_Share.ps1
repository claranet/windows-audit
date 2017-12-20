[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Return the goods
return $(Get-WMIObject -Class "Win32_Share" | Select -Property * | %{
    # Return a new PSCustomObject to the pipeline
    New-Object PSCustomObject -Property @{
        MachineIdentifier = $ID;
        Status            = $_.Status;
        Type              = $_.Type;
        Name              = $_.Name;
        AccessMask        = $_.AccessMask;
        AllowMaximum      = $_.AllowMaximum;
        Caption           = $_.Caption;
        Description       = $_.Description;
        InstallDate       = $_.InstallDate;
        MaximumAllowed    = $_.MaximumAllowed;
        Path              = $_.Path;
    };
});