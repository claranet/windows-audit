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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_USBControllerDevice" | %{[Wmi]$_.Dependent} | Select -Property * | %{
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
        PNPClass                     = $_.PNPClass;
        PNPDeviceID                  = $_.PNPDeviceID;
        PowerManagementCapabilities  = $_.PowerManagementCapabilities;
        PowerManagementSupported     = $_.PowerManagementSupported;
        Present                      = $_.Present;
        Service                      = $_.Service;
        Status                       = $_.Status;
        StatusInfo                   = $_.StatusInfo;
    }
});