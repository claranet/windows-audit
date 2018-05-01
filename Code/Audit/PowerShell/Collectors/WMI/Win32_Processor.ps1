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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Processor" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier                       = $MachineIdentifier;
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
