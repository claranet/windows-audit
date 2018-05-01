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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_BIOS" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier              = $MachineIdentifier;
        Status                         = $_.Status;
        Name                           = $_.Name;
        Caption                        = $_.Caption;
        SMBIOSPresent                  = $_.SMBIOSPresent;
        BiosCharacteristics            = $_.BiosCharacteristics
        BIOSVersion                    = $_.BIOSVersion;
        BuildNumber                    = $_.BuildNumber;
        CodeSet                        = $_.CodeSet;
        CurrentLanguage                = $_.CurrentLanguage;
        Description                    = $_.Description;
        EmbeddedControllerMajorVersion = $_.EmbeddedControllerMajorVersion;
        EmbeddedControllerMinorVersion = $_.EmbeddedControllerMinorVersion;
        IdentificationCode             = $_.IdentificationCode;
        InstallableLanguages           = $_.InstallableLanguages;
        InstallDate                    = $_.InstallDate;
        LanguageEdition                = $_.LanguageEdition;
        ListOfLanguages                = $_.ListOfLanguages;
        Manufacturer                   = $_.Manufacturer;
        OtherTargetOS                  = $_.OtherTargetOS;
        PrimaryBIOS                    = $_.PrimaryBIOS;
        ReleaseDate                    = $_.ReleaseDate;
        SerialNumber                   = $_.SerialNumber;
        SMBIOSBIOSVersion              = $_.SMBIOSBIOSVersion;
        SMBIOSMajorVersion             = $_.SMBIOSMajorVersion;
        SMBIOSMinorVersion             = $_.SMBIOSMinorVersion;
        SoftwareElementID              = $_.SoftwareElementID;
        SoftwareElementState           = $_.SoftwareElementState;
        SystemBiosMajorVersion         = $_.SystemBiosMajorVersion;
        SystemBiosMinorVersion         = $_.SystemBiosMinorVersion;
        TargetOperatingSystem          = $_.TargetOperatingSystem;
        Version                        = $_.Version;
    }
});
