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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Cim_Chassis" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier         = $MachineIdentifier;
        Tag                       = $_.Tag;
        Status                    = $_.Status;
        Name                      = $_.Name;
        SecurityStatus            = $_.SecurityStatus;
        AudibleAlarm              = $_.AudibleAlarm;
        BreachDescription         = $_.BreachDescription;
        CableManagementStrategy   = $_.CableManagementStrategy;
        Caption                   = $_.Caption;
        ChassisTypes              = $_.ChassisTypes;
        CurrentRequiredOrProduced = $_.CurrentRequiredOrProduced;
        Depth                     = $_.Depth;
        Description               = $_.Description;
        HeatGeneration            = $_.HeatGeneration;
        Height                    = $_.Height;
        HotSwappable              = $_.HotSwappable;
        InstallDate               = $_.InstallDate;
        LockPresent               = $_.LockPresent;
        Manufacturer              = $_.Manufacturer;
        Model                     = $_.Model;
        NumberOfPowerCords        = $_.NumberOfPowerCords;
        OtherIdentifyingInfo      = $_.OtherIdentifyingInfo;
        PartNumber                = $_.PartNumber;
        PoweredOn                 = $_.PoweredOn;
        Removable                 = $_.Removable;
        Replaceable               = $_.Replaceable;
        SecurityBreach            = $_.SecurityBreach;
        SerialNumber              = $_.SerialNumber;
        ServiceDescriptions       = $_.ServiceDescriptions;
        ServicePhilosophy         = $_.ServicePhilosophy;
        SKU                       = $_.SKU;
        SMBIOSAssetTag            = $_.SMBIOSAssetTag;
        TypeDescriptions          = $_.TypeDescriptions;
        Version                   = $_.Version;
        VisibleAlarm              = $_.VisibleAlarm;
        Weight                    = $_.Weight;
        Width                     = $_.Width;
    }
});
