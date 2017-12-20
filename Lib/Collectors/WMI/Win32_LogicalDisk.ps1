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
return $(Get-WMIObject -Class "Win32_LogicalDisk" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $ID;
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