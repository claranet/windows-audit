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
return $(Get-WMIObject -Class "Cim_Chassis" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier         = $ID;
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