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

# Return the goods
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Volume" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier             = $MachineIdentifier;
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
