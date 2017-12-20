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
return $(Get-WMIObject -Class "Win32_Processor" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier                       = $ID;
        Availability                            = $_.Availability;
        CpuStatus                               = $_.CpuStatus;
        CurrentVoltage                          = $_.CurrentVoltage;
        DeviceID                                = $_.DeviceID;
        ErrorCleared                            = $_.ErrorCleared;
        ErrorDescription                        = $_.ErrorDescription;
        LastErrorCode                           = $_.LastErrorCode;
        LoadPercentage                          = $_.LoadPercentage;
        Status                                  = $_.Status;
        StatusInfo                              = $_.StatusInfo;
        AddressWidth                            = $_.AddressWidth;
        DataWidth                               = $_.DataWidth;
        ExtClock                                = $_.ExtClock;
        L2CacheSize                             = $_.L2CacheSize;
        L2CacheSpeed                            = $_.L2CacheSpeed;
        MaxClockSpeed                           = $_.MaxClockSpeed;
        PowerManagementSupported                = $_.PowerManagementSupported;
        ProcessorType                           = $_.ProcessorType;
        Revision                                = $_.Revision;
        SocketDesignation                       = $_.SocketDesignation;
        Version                                 = $_.Version;
        VoltageCaps                             = $_.VoltageCaps;
        Architecture                            = $_.Architecture;
        AssetTag                                = $_.AssetTag;
        Caption                                 = $_.Caption;
        Characteristics                         = $_.Characteristics;
        ConfigManagerErrorCode                  = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig                 = $_.ConfigManagerUserConfig;
        CurrentClockSpeed                       = $_.CurrentClockSpeed;
        Description                             = $_.Description;
        Family                                  = $_.Family;
        InstallDate                             = $_.InstallDate;
        L3CacheSize                             = $_.L3CacheSize;
        L3CacheSpeed                            = $_.L3CacheSpeed;
        Level                                   = $_.Level;
        Manufacturer                            = $_.Manufacturer;
        Name                                    = $_.Name;
        NumberOfCores                           = $_.NumberOfCores;
        NumberOfEnabledCore                     = $_.NumberOfEnabledCore;
        NumberOfLogicalProcessors               = $_.NumberOfLogicalProcessors;
        OtherFamilyDescription                  = $_.OtherFamilyDescription;
        PartNumber                              = $_.PartNumber;
        PNPDeviceID                             = $_.PNPDeviceID;
        PowerManagementCapabilities             = $_.PowerManagementCapabilities;
        ProcessorId                             = $_.ProcessorId;
        Role                                    = $_.Role;
        SecondLevelAddressTranslationExtensions = $_.SecondLevelAddressTranslationExtensions;
        SerialNumber                            = $_.SerialNumber;
        Stepping                                = $_.Stepping;
        SystemName                              = $_.SystemName;
        ThreadCount                             = $_.ThreadCount;
        UniqueId                                = $_.UniqueId;
        UpgradeMethod                           = $_.UpgradeMethod;
        VirtualizationFirmwareEnabled           = $_.VirtualizationFirmwareEnabled;
        VMMonitorModeExtensions                 = $_.VMMonitorModeExtensions;
    }
});