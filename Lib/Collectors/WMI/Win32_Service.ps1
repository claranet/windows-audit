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
return $(Get-WMIObject -Class "Win32_Service" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier        = $ID;
        Name                     = $_.Name;
        Status                   = $_.Status;
        ExitCode                 = $_.ExitCode;
        DesktopInteract          = $_.DesktopInteract;
        ErrorControl             = $_.ErrorControl;
        PathName                 = $_.PathName;
        ServiceType              = $_.ServiceType;
        StartMode                = $_.StartMode;
        AcceptPause              = $_.AcceptPause;
        AcceptStop               = $_.AcceptStop;
        Caption                  = $_.Caption;
        CheckPoint               = $_.CheckPoint;
        CreationClassName        = $_.CreationClassName;
        DelayedAutoStart         = $_.DelayedAutoStart;
        Description              = $_.Description;
        DisplayName              = $_.DisplayName;
        InstallDate              = $_.InstallDate;
        ProcessId                = $_.ProcessId;
        ServiceSpecificExitCode  = $_.ServiceSpecificExitCode;
        Started                  = $_.Started;
        StartName                = $_.StartName;
        State                    = $_.State;
        SystemCreationClassName  = $_.SystemCreationClassName;
        SystemName               = $_.SystemName;
        TagId                    = $_.TagId;
        WaitHint                 = $_.WaitHint;
    }
});