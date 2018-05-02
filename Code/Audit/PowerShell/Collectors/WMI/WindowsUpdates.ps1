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

# And get the data
return $(Get-WmiObject -ComputerName $Target -Credential $Credential -Class "Win32_QuickFixEngineering" | Select -Property * | %{
    [PSCustomObject]@{
        MachineIdentifier   = $MachineIdentifier;
        InstalledOn         = $_.InstalledOn
        Status              = $_.Status;
        Caption             = $_.Caption;
        CSName              = $_.CSName;
        Description         = $_.Description;
        FixComments         = $_.FixComments;
        HotFixID            = $_.HotFixID;
        InstallDate         = $_.InstallDate;
        InstalledBy         = $_.InstalledBy;
        Name                = $_.Name;
        ServicePackInEffect = $_.ServicePackInEffect;
    };
});