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
return $(Get-WMIObject -Class "Win32_BIOS" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier              = $ID;
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