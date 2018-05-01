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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Printer" | Select -Property * | %{
    New-Object PSCustomObject -Property @{
        MachineIdentifier            = $MachineIdentifier;
        Status                       = $_.Status;
        Name                         = $_.Name;
        Attributes                   = $_.Attributes;
        Availability                 = $_.Availability;
        AvailableJobSheets           = $_.AvailableJobSheets;
        AveragePagesPerMinute        = $_.AveragePagesPerMinute;
        Capabilities                 = $_.Capabilities;
        CapabilityDescriptions       = $_.CapabilityDescriptions;
        Caption                      = $_.Caption;
        CharSetsSupported            = $_.CharSetsSupported;
        Comment                      = $_.Comment;
        ConfigManagerErrorCode       = $_.ConfigManagerErrorCode;
        ConfigManagerUserConfig      = $_.ConfigManagerUserConfig;
        CurrentCapabilities          = $_.CurrentCapabilities;
        CurrentCharSet               = $_.CurrentCharSet;
        CurrentLanguage              = $_.CurrentLanguage;
        CurrentMimeType              = $_.CurrentMimeType;
        CurrentNaturalLanguage       = $_.CurrentNaturalLanguage;
        CurrentPaperType             = $_.CurrentPaperType;
        Default                      = $_.Default;
        DefaultCapabilities          = $_.DefaultCapabilities;
        DefaultCopies                = $_.DefaultCopies;
        DefaultLanguage              = $_.DefaultLanguage;
        DefaultMimeType              = $_.DefaultMimeType;
        DefaultNumberUp              = $_.DefaultNumberUp;
        DefaultPaperType             = $_.DefaultPaperType;
        DefaultPriority              = $_.DefaultPriority;
        Description                  = $_.Description;
        DetectedErrorState           = $_.DetectedErrorState;
        DeviceID                     = $_.DeviceID;
        Direct                       = $_.Direct;
        DoCompleteFirst              = $_.DoCompleteFirst;
        DriverName                   = $_.DriverName;
        EnableBIDI                   = $_.EnableBIDI;
        EnableDevQueryPrint          = $_.EnableDevQueryPrint;
        ErrorCleared                 = $_.ErrorCleared;
        ErrorDescription             = $_.ErrorDescription;
        ErrorInformation             = $_.ErrorInformation;
        ExtendedDetectedErrorState   = $_.ExtendedDetectedErrorState;
        ExtendedPrinterStatus        = $_.ExtendedPrinterStatus;
        Hidden                       = $_.Hidden;
        HorizontalResolution         = $_.HorizontalResolution;
        InstallDate                  = $_.InstallDate;
        JobCountSinceLastReset       = $_.JobCountSinceLastReset;
        KeepPrintedJobs              = $_.KeepPrintedJobs;
        LanguagesSupported           = $_.LanguagesSupported;
        LastErrorCode                = $_.LastErrorCode;
        Local                        = $_.Local;
        Location                     = $_.Location;
        MarkingTechnology            = $_.MarkingTechnology;
        MaxCopies                    = $_.MaxCopies;
        MaxNumberUp                  = $_.MaxNumberUp;
        MaxSizeSupported             = $_.MaxSizeSupported;
        MimeTypesSupported           = $_.MimeTypesSupported;
        NaturalLanguagesSupported    = $_.NaturalLanguagesSupported;
        Network                      = $_.Network;
        PaperSizesSupported          = $_.PaperSizesSupported;
        PaperTypesAvailable          = $_.PaperTypesAvailable;
        Parameters                   = $_.Parameters;
        PNPDeviceID                  = $_.PNPDeviceID;
        PortName                     = $_.PortName;
        PowerManagementCapabilities  = $_.PowerManagementCapabilities;
        PowerManagementSupported     = $_.PowerManagementSupported;
        PrinterPaperNames            = $_.PrinterPaperNames;
        PrinterState                 = $_.PrinterState;
        PrinterStatus                = $_.PrinterStatus;
        PrintJobDataType             = $_.PrintJobDataType;
        PrintProcessor               = $_.PrintProcessor;
        Priority                     = $_.Priority;
        Published                    = $_.Published;
        Queued                       = $_.Queued;
        RawOnly                      = $_.RawOnly;
        SeparatorFile                = $_.SeparatorFile;
        ServerName                   = $_.ServerName;
        Shared                       = $_.Shared;
        ShareName                    = $_.ShareName;
        SpoolEnabled                 = $_.SpoolEnabled;
        StartTime                    = $_.StartTime;
        StatusInfo                   = $_.StatusInfo;
        SystemName                   = $_.SystemName;
        TimeOfLastReset              = $_.TimeOfLastReset;
        UntilTime                    = $_.UntilTime;
        VerticalResolution           = $_.VerticalResolution;
        WorkOffline                  = $_.WorkOffline;
    }
});
