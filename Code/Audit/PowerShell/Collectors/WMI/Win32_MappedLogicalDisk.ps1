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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_MappedLogicalDisk" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier             = $MachineIdentifier;
        Access                        = $_.Access;
        Availability                  = $_.Availability;
        BlockSize                     = $_.BlockSize;
        Caption                       = $_.Caption;
        Compressed                    = $_.Compressed;
        ConfigManagerErrorCode        = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig       = $_.ConfigManagerUserConfig;
        CreationClassName             = $_.CreationClassName;
        Description                   = $_.Description;
        DeviceID                      = $_.DeviceID;
        ErrorCleared                  = $_.ErrorCleared;
        ErrorDescription              = $_.ErrorDescription;
        ErrorMethodology              = $_.ErrorMethodology;
        FileSystem                    = $_.FileSystem;
        FreeSpace                     = $_.FreeSpace;
        InstallDate                   = $_.InstallDate;
        LastErrorCode                 = $_.LastErrorCode;
        MaximumComponentLength        = $_.MaximumComponentLength;
        Name                          = $_.Name;
        NumberOfBlocks                = $_.NumberOfBlocks;
        PNPDeviceID                   = $_.PNPDeviceID;
        PowerManagementCapabilities   = $_.PowerManagementCapabilities;
        PowerManagementSupported      = $_.PowerManagementSupported;
        ProviderName                  = $_.ProviderName;
        Purpose                       = $_.Purpose;
        QuotasDisabled                = $_.QuotasDisabled;
        QuotasIncomplete              = $_.QuotasIncomplete;
        QuotasRebuilding              = $_.QuotasRebuilding;
        SessionID                     = $_.SessionID;
        Size                          = $_.Size;
        Status                        = $_.Status;
        StatusInfo                    = $_.StatusInfo;
        SupportsDiskQuotas            = $_.SupportsDiskQuotas;
        SupportsFileBasedCompression  = $_.SupportsFileBasedCompression;
        SystemCreationClassName       = $_.SystemCreationClassName;
        SystemName                    = $_.SystemName;
        VolumeName                    = $_.VolumeName;
        VolumeSerialNumber            = $_.VolumeSerialNumber;
    }
});
