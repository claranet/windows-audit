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
return $(Get-WMIObject -Class "Win32_NetworkAdapter" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $ID;
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