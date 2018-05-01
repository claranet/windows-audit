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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_OperatingSystem" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier                         = $MachineIdentifier;
        Hostname                                  = $_.CSName;
        Status                                    = $_.Status;
        FreePhysicalMemory                        = $_.FreePhysicalMemory;
        FreeSpaceInPagingFiles                    = $_.FreeSpaceInPagingFiles;
        FreeVirtualMemory                         = $_.FreeVirtualMemory;
        BootDevice                                = $_.BootDevice;
        BuildNumber                               = $_.BuildNumber;
        BuildType                                 = $_.BuildType;
        Caption                                   = $_.Caption;
        CodeSet                                   = $_.CodeSet;
        CountryCode                               = $_.CountryCode;
        CSDVersion                                = $_.CSDVersion;
        CurrentTimeZone                           = $_.CurrentTimeZone;
        DataExecutionPrevention_32BitApplications = $_.DataExecutionPrevention_32BitApplications;
        DataExecutionPrevention_Available         = $_.DataExecutionPrevention_Available;
        DataExecutionPrevention_Drivers           = $_.DataExecutionPrevention_Drivers;
        DataExecutionPrevention_SupportPolicy     = $_.DataExecutionPrevention_SupportPolicy;
        Debug                                     = $_.Debug;
        Description                               = $_.Description;
        Distributed                               = $_.Distributed;
        EncryptionLevel                           = $_.EncryptionLevel;
        ForegroundApplicationBoost                = $_.ForegroundApplicationBoost;
        InstallDate                               = $_.InstallDate;
        LargeSystemCache                          = $_.LargeSystemCache;
        LastBootUpTime                            = $_.LastBootUpTime;
        LocalDateTime                             = $_.LocalDateTime;
        Locale                                    = $_.Locale;
        Manufacturer                              = $_.Manufacturer;
        MaxNumberOfProcesses                      = $_.MaxNumberOfProcesses;
        MaxProcessMemorySize                      = $_.MaxProcessMemorySize;
        MUILanguages                              = $_.MUILanguages;
        NumberOfLicensedUsers                     = $_.NumberOfLicensedUsers;
        NumberOfProcesses                         = $_.NumberOfProcesses;
        NumberOfUsers                             = $_.NumberOfUsers;
        OperatingSystemSKU                        = $_.OperatingSystemSKU;
        Organization                              = $_.Organization;
        OSArchitecture                            = $_.OSArchitecture;
        OSLanguage                                = $_.OSLanguage;
        OSProductSuite                            = $_.OSProductSuite;
        OSType                                    = $_.OSType;
        OtherTypeDescription                      = $_.OtherTypeDescription;
        PAEEnabled                                = $_.PAEEnabled;
        PlusProductID                             = $_.PlusProductID;
        PlusVersionNumber                         = $_.PlusVersionNumber;
        PortableOperatingSystem                   = $_.PortableOperatingSystem;
        Primary                                   = $_.Primary;
        ProductType                               = $_.ProductType;
        RegisteredUser                            = $_.RegisteredUser;
        SerialNumber                              = $_.SerialNumber;
        ServicePackMajorVersion                   = $_.ServicePackMajorVersion;
        ServicePackMinorVersion                   = $_.ServicePackMinorVersion;
        SizeStoredInPagingFiles                   = $_.SizeStoredInPagingFiles;
        SuiteMask                                 = $_.SuiteMask;
        SystemDevice                              = $_.SystemDevice;
        SystemDirectory                           = $_.SystemDevice;
        SystemDrive                               = $_.SystemDrive;
        TotalSwapSpaceSize                        = $_.TotalSwapSpaceSize;
        TotalVirtualMemorySize                    = $_.TotalVirtualMemorySize;
        TotalVisibleMemorySize                    = $_.TotalVisibleMemorySize;
        Version                                   = $_.Version;
        WindowsDirectory                          = $_.WindowsDirectory;
    }
});
