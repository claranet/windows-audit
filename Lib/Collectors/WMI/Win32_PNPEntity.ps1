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
return $(Get-WMIObject -Class "Win32_PnPEntity" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $ID;
        Availability                 = $_.Availability;
        Caption                      = $_.Caption;
        ClassGuid                    = $_.ClassGuid;
        CompatibleID                 = $_.CompatibleID;
        ConfigManagerErrorCode       = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig      = $_.ConfigManagerUserConfig;
        CreationClassName            = $_.CreationClassName;
        Description                  = $_.Description;
        DeviceID                     = $_.DeviceID;
        ErrorCleared                 = $_.ErrorCleared;
        ErrorDescription             = $_.ErrorDescription;
        HardwareID                   = $_.HardwareID;
        InstallDate                  = $_.InstallDate;
        LastErrorCode                = $_.LastErrorCode;
        Manufacturer                 = $_.Manufacturer;
        Name                         = $_.Name;
        PNPDeviceID                  = $_.PNPDeviceID;
        PowerManagementCapabilities  = $_.PowerManagementCapabilities;
        PowerManagementSupported     = $_.PowerManagementSupported;
        Service                      = $_.Service;
        Status                       = $_.Status;
        StatusInfo                   = $_.StatusInfo;
    }
});