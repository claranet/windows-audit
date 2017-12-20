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
return $(Get-WMIObject -Class "Win32_Volume" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier             = $ID;
        Access                        = $_.Access;
        Automount                     = $_.Automount;
        Availability                  = $_.Availability;
        BlockSize                     = $_.BlockSize;
        BootVolume                    = $_.BootVolume;
        Capacity                      = $_.Capacity;
        Caption                       = $_.Caption;
        Compressed                    = $_.Compressed;
        ConfigManagerErrorCode        = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig       = $_.ConfigManagerUserConfig;
        CreationClassName             = $_.CreationClassName;
        Description                   = $_.Description;
        DeviceID                      = $_.DeviceID;
        DirtyBitSet                   = $_.DirtyBitSet;
        DriveLetter                   = $_.DriveLetter;
        DriveType                     = $_.DriveType;
        ErrorCleared                  = $_.ErrorCleared;
        ErrorDescription              = $_.ErrorDescription;
        ErrorMethodology              = $_.ErrorMethodology;
        FileSystem                    = $_.FileSystem;
        FreeSpace                     = $_.FreeSpace;
        IndexingEnabled               = $_.IndexingEnabled;
        InstallDate                   = $_.InstallDate;
        Label                         = $_.Label;
        LastErrorCode                 = $_.LastErrorCode;
        MaximumFileNameLength         = $_.MaximumFileNameLength;
        Name                          = $_.Name;
        NumberOfBlocks                = $_.NumberOfBlocks;
        PageFilePresent               = $_.PageFilePresent;
        PNPDeviceID                   = $_.PNPDeviceID;
        PowerManagementCapabilities   = $_.PowerManagementCapabilities;
        PowerManagementSupported      = $_.PowerManagementSupported;
        Purpose                       = $_.Purpose;
        QuotasEnabled                 = $_.QuotasEnabled;
        QuotasIncomplete              = $_.QuotasIncomplete;
        QuotasRebuilding              = $_.QuotasRebuilding;
        SerialNumber                  = $_.SerialNumber;
        Status                        = $_.Status;
        StatusInfo                    = $_.StatusInfo;
        SupportsDiskQuotas            = $_.SupportsDiskQuotas;
        SupportsFileBasedCompression  = $_.SupportsFileBasedCompression;
        SystemCreationClassName       = $_.SystemCreationClassName;
        SystemName                    = $_.SystemName;
        SystemVolume                  = $_.SystemVolume;
    }
});