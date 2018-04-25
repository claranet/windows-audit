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
return $(Get-WMIObject -ComputerName $Target -Credential $Credential -Class "Win32_Share" | Select -Property * | %{
    # Return a new PSCustomObject to the pipeline
    New-Object PSCustomObject -Property @{
        MachineIdentifier = $MachineIdentifier;
        Status            = $_.Status;
        Type              = $_.Type;
        Name              = $_.Name;
        AccessMask        = $_.AccessMask;
        AllowMaximum      = $_.AllowMaximum;
        Caption           = $_.Caption;
        Description       = $_.Description;
        InstallDate       = $_.InstallDate;
        MaximumAllowed    = $_.MaximumAllowed;
        Path              = $_.Path;
    };
});
