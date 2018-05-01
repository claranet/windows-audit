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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_DiskDrive" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier           = $MachineIdentifier;
        ConfigManagerErrorCode      = $_.ConfigManagerErrorCode;
        LastErrorCode               = $_.LastErrorCode;
        NeedsCleaning               = $_.NeedsCleaning;
        Status                      = $_.Status;
        DeviceID                    = $_.DeviceID;
        StatusInfo                  = $_.StatusInfo;
        Partitions                  = $_.Partitions;
        BytesPerSector              = $_.BytesPerSector;
        ConfigManagerUserConfig     = $_.ConfigManagerUserConfig;
        DefaultBlockSize            = $_.DefaultBlockSize;
        Index                       = $_.Index;
        InstallDate                 = $_.InstallDate;
        InterfaceType               = $_.InterfaceType;
        MaxBlockSize                = $_.MaxBlockSize;
        MaxMediaSize                = $_.MaxMediaSize;
        MinBlockSize                = $_.MinBlockSize;
        NumberOfMediaSupported      = $_.NumberOfMediaSupported;
        SectorsPerTrack             = $_.SectorsPerTrack;
        Size                        = $_.Size;
        TotalCylinders              = $_.TotalCylinders;
        TotalHeads                  = $_.TotalHeads;
        TotalSectors                = $_.TotalSectors;
        TotalTracks                 = $_.TotalTracks;
        TracksPerCylinder           = $_.TracksPerCylinder;
        Availability                = $_.Availability;
        Capabilities                = $_.Capabilities;
        CapabilityDescriptions      = $_.CapabilityDescriptions;
        Caption                     = $_.Caption;
        CompressionMethod           = $_.CompressionMethod;
        Description                 = $_.Description;
        ErrorCleared                = $_.ErrorCleared;
        ErrorDescription            = $_.ErrorDescription;
        ErrorMethodology            = $_.ErrorMethodology;
        FirmwareRevision            = $_.FirmwareRevision;
        Manufacturer                = $_.Manufacturer;
        MediaLoaded                 = $_.MediaLoaded;
        MediaType                   = $_.MediaType;
        Model                       = $_.Model;
        Name                        = $_.Name;
        PNPDeviceID                 = $_.PNPDeviceID;
        PowerManagementCapabilities = $_.PowerManagementCapabilities;
        PowerManagementSupported    = $_.PowerManagementSupported;
        SCSIBus                     = $_.SCSIBus;
        SCSILogicalUnit             = $_.SCSILogicalUnit;
        SCSIPort                    = $_.SCSIPort;
        SCSITargetId                = $_.SCSITargetId;
        SerialNumber                = $_.SerialNumber;
        Signature                   = $_.Signature;
        SystemName                  = $_.SystemName;
    }
});
