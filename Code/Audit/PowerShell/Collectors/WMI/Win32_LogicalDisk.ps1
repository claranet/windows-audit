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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_LogicalDisk" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $MachineIdentifier;
        Status                       = $_.Status;
        Availability                 = $_.Availability;
        DeviceID                     = $_.DeviceID;
        StatusInfo                   = $_.StatusInfo;
        Access                       = $_.Access;
        BlockSize                    = $_.BlockSize;
        Caption                      = $_.Caption;
        Compressed                   = $_.Compressed;
        ConfigManagerErrorCode       = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig      = $_.ConfigManagerUserConfig;
        Description                  = $_.Description;
        DriveType                    = $_.DriveType;
        ErrorCleared                 = $_.ErrorCleared;
        ErrorDescription             = $_.ErrorDescription;
        ErrorMethodology             = $_.ErrorMethodology;
        FileSystem                   = $_.FileSystem;
        FreeSpace                    = $_.FreeSpace;
        InstallDate                  = $_.InstallDate;
        LastErrorCode                = $_.LastErrorCode;
        MaximumComponentLength       = $_.MaximumComponentLength;
        MediaType                    = $_.MediaType;
        Name                         = $_.Name;
        NumberOfBlocks               = $_.NumberOfBlocks;
        PNPDeviceID                  = $_.PNPDeviceID;
        PowerManagementCapabilities  = $_.PowerManagementCapabilities;
        PowerManagementSupported     = $_.PowerManagementSupported;
        ProviderName                 = $_.ProviderName;
        Purpose                      = $_.Purpose;
        QuotasDisabled               = $_.QuotasDisabled;
        QuotasIncomplete             = $_.QuotasIncomplete;
        QuotasRebuilding             = $_.QuotasRebuilding;
        Size                         = $_.Size;
        SupportsDiskQuotas           = $_.SupportsDiskQuotas;
        SupportsFileBasedCompression = $_.SupportsFileBasedCompression;
        SystemName                   = $_.SystemName;
        VolumeDirty                  = $_.VolumeDirty;
        VolumeName                   = $_.VolumeName;
        VolumeSerialNumber           = $_.VolumeSerialNumber;
    }
});
