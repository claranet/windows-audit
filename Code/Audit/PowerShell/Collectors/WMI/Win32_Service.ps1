[Cmdletbinding()]
Param(
    # The server we're targetting
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$Target,

    # The credential we're using to connect
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$Credential,

    # The machine identifier
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$MachineIdentifier
)

# Set EAP
$ErrorActionPreference = "Stop";

# Return the goods
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Service" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier        = $MachineIdentifier;
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
