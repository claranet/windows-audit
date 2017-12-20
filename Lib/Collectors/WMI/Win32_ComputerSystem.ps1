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
return $(Get-WMIObject -Class "Win32_ComputerSystem" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier           = $ID;
        AdminPasswordStatus         = $_.AdminPasswordStatus;
        BootupState                 = $_.BootupState;
        ChassisBootupState          = $_.ChassisBootupState;
        KeyboardPasswordStatus      = $_.KeyboardPasswordStatus;
        PowerOnPasswordStatus       = $_.PowerOnPasswordStatus;
        PowerSupplyState            = $_.PowerSupplyState;
        PowerState                  = $_.PowerState;
        FrontPanelResetStatus       = $_.FrontPanelResetStatus;
        ThermalState                = $_.ThermalState;
        Status                      = $_.Status;
        Name                        = $_.Name;
        PowerManagementCapabilities = $_.PowerManagementCapabilities;
        PowerManagementSupported    = $_.PowerManagementCapabilities;
        AutomaticManagedPagefile    = $_.AutomaticManagedPagefile;
        AutomaticResetBootOption    = $_.AutomaticResetBootOption;
        AutomaticResetCapability    = $_.AutomaticResetCapability
        BootOptionOnLimit           = $_.BootOptionOnLimit;
        BootOptionOnWatchDog        = $_.BootOptionOnWatchDog;
        BootROMSupported            = $_.BootROMSupported;
        BootStatus                  = $_.BootStatus;
        Caption                     = $_.Caption;
        CurrentTimeZone             = $_.CurrentTimeZone;
        DaylightInEffect            = $_.DaylightInEffect;
        Description                 = $_.Description;
        DNSHostName                 = $_.DNSHostName;
        Domain                      = $_.Domain;
        DomainRole                  = $_.DomainRole;
        EnableDaylightSavingsTime   = $_.EnableDaylightSavingsTime;
        HypervisorPresent           = $_.HypervisorPresent;
        InfraredSupported           = $_.InfraredSupported;
        InitialLoadInfo             = $_.InitialLoadInfo;
        InstallDate                 = $_.InstallDate;
        LastLoadInfo                = $_.LastLoadInfo;
        Manufacturer                = $_.Manufacturer;
        Model                       = $_.Model;
        NameFormat                  = $_.NameFormat;
        NetworkServerModeEnabled    = $_.NetworkServerModeEnabled;
        NumberOfLogicalProcessors   = $_.NumberOfLogicalProcessors;
        NumberOfProcessors          = $_.NumberOfLogicalProcessors;
        OEMLogoBitmap               = $_.OEMLogoBitmap;
        OEMStringArray              = $_.OEMStringArray;
        PartOfDomain                = $_.PartOfDomain;
        PauseAfterReset             = $_.PauseAfterReset;
        PCSystemType                = $_.PCSystemType;
        PCSystemTypeEx              = $_.PCSystemTypeEx;
        PrimaryOwnerContact         = $_.PrimaryOwnerContact;
        PrimaryOwnerName            = $_.PrimaryOwnerName;
        ResetCapability             = $_.ResetCapability;
        ResetCount                  = $_.ResetCount;
        ResetLimit                  = $_.ResetLimit;
        Roles                       = $_.Roles;
        SupportContactDescription   = $_.SupportContactDescription;
        SystemFamily                = $_.SystemFamily;
        SystemSKUNumber             = $_.SystemSKUNumber;
        SystemStartupDelay          = $_.SystemStartupDelay;
        SystemStartupOptions        = $_.SystemStartupOptions;
        SystemStartupSetting        = $_.SystemStartupSetting;
        SystemType                  = $_.SystemType;
        TotalPhysicalMemory         = $_.TotalPhysicalMemory;
        UserName                    = $_.UserName;
        WakeUpType                  = $_.WakeUpType;
        Workgroup                   = $_.Workgroup;
    }
});