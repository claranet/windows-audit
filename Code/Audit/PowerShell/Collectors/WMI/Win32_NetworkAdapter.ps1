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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_NetworkAdapter" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $MachineIdentifier;
        Availability                 = $_.Availability;
        Name                         = $_.Name;
        Status                       = $_.Status;
        StatusInfo                   = $_.StatusInfo;
        DeviceID                     = $_.DeviceID;
        AdapterType                  = $_.AdapterType;
        AdapterTypeId                = $_.AdapterTypeId;
        AutoSense                    = $_.AutoSense;
        Caption                      = $_.Caption;
        ConfigManagerErrorCode       = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig      = $_.ConfigManagerUserConfig;
        CreationClassName            = $_.CreationClassName;
        Description                  = $_.Description;
        ErrorCleared                 = $_.ErrorCleared;
        ErrorDescription             = $_.ErrorDescription;
        GUID                         = $_.GUID;
        Index                        = $_.Index;
        InstallDate                  = $_.InstallDate;
        Installed                    = $_.Installed;
        InterfaceIndex               = $_.InterfaceIndex;
        LastErrorCode                = $_.LastErrorCode;
        MACAddress                   = $_.MACAddress;
        Manufacturer                 = $_.Manufacturer;
        MaxNumberControlled          = $_.MaxNumberControlled;
        MaxSpeed                     = $_.MaxSpeed;
        NetConnectionID              = $_.NetConnectionID;
        NetConnectionStatus          = $_.NetConnectionStatus;
        NetEnabled                   = $_.NetEnabled;
        NetworkAddresses             = $_.NetworkAddresses;
        PermanentAddress             = $_.PermanentAddress;
        PhysicalAdapter              = $_.PhysicalAdapter;
        PNPDeviceID                  = $_.PNPDeviceID;
        PowerManagementCapabilities  = $_.PowerManagementCapabilities;
        PowerManagementSupported     = $_.PowerManagementSupported;
        ProductName                  = $_.ProductName;
        ServiceName                  = $_.ServiceName;
        Speed                        = $_.Speed;
        TimeOfLastReset              = $_.TimeOfLastReset;
    }
});
