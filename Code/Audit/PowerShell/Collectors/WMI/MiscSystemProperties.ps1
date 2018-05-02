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

# Inline functions to recursively expand StdRegProv registry paths
Function Get-RegistryPaths {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.ManagementClass]$RegProvider,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$RootPath
    )

    # Get all the key names
    $KeyNames = $RegProvider.EnumKey($([UInt32]"0x80000002"),$RootPath).sNames;
    
    # Enumerate the subkeys in this key
    $KeyNames | %{$K = $_;
        if ($K) {
            $SubKey = "$RootPath\$K";
            Write-Output $SubKey;
            Get-RegistryPaths -RegProvider $RegProvider -RootPath $SubKey;
        }
    }
}

# Inline function to return .NET registry properties
Function Get-RegistryProps {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [System.Management.ManagementClass]$RegProvider,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$KeyPath
    )

    # Lookup map for .NET version strings
    $DotNetLookupMap = @{
        378389 = ".NET Framework 4.5";
        378675 = ".NET Framework 4.5.1 installed with Windows 8.1 or Windows Server 2012 R2";
        378758 = ".NET Framework 4.5.1 installed on Windows 8, Windows 7 SP1, or Windows Vista SP2";
        379893 = ".NET Framework 4.5.2";
        393295 = ".NET Framework 4.6";
        393297 = ".NET Framework 4.6";
        394254 = ".NET Framework 4.6.1";
        394271 = ".NET Framework 4.6.1";
        394802 = ".NET Framework 4.6.2";
        394806 = ".NET Framework 4.6.2";
        460798 = ".NET Framework 4.7";
        460805 = ".NET Framework 4.7";
        461308 = ".NET Framework 4.7.1";
        461310 = ".NET Framework 4.7.1";
        461808 = ".NET Framework 4.7.2";
        461814 = ".NET Framework 4.7.2";
    }

    # Get the type
    $Type = $KeyPath.Split("\")[-1];

    # Switch on the type
    if ("Client","Full" -contains $Type) {
        # Get the properties
        $Version = $RegProvider.GetStringValue($([UInt32]"0x80000002"), $KeyPath, "Version").sValue;  
        $Release = $RegProvider.GetDWORDValue($([UInt32]"0x80000002"), $KeyPath, "Release").uValue;
    
        # If we found the release object return it
        if ($Version -and $Release) {
            [PSCustomObject]@{
                Type    = $Type;
                Version = $Version;
                Release = $DotNetLookupMap[[Int]$Release];
            }
        }
    }
}

# Get our registry provider instance and authenticate against the target
$RegProvider = Get-WmiObject -ComputerName $Target -Credential $Credential -List "StdRegProv" -Namespace "root\default";

# Declare some helper variables
$DotNetKey      = "SOFTWARE\Microsoft\NET Framework Setup\NDP";
$DotNetVersions = @();

# Recursively work out what .NET versions are installed
Get-RegistryPaths -RegProvider $RegProvider -RootPath $DotNetKey | %{
    Get-RegistryProps -RegProvider $RegProvider -KeyPath $_ | %{
        $DotNetVersions += $_;
    }
}

# Variablise some helpers
$HKLM            = [UInt32]"0x80000002";
$IsInstalledPath = "SOFTWARE\Microsoft\PowerShell\1";
$VersionsPath    = "SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine";

# Ok need to check whether PowerShell is installed
$PowerShellInstalled = [Bool]($RegProvider.GetDWORDValue($HKLM,$IsInstalledPath,"Install").uValue);

# Work out what PowerShell versions are installed
if ($PowerShellInstalled) {
    # Get the list of versions
    $PowerShellVersions = $RegProvider.GetStringValue($HKLM,$VersionsPath,"PSCompatibleVersion").sValue;

    # Check if that value is blank
    if (!$PowerShellVersions) {
        $PowerShellVersions = @("1.0");
    } else {
        $PowerShellVersions = $PowerShellVersions.Split(",");
    }
}

# Return the info
return $([PSCustomObject]@{
    MachineIdentifier   = $MachineIdentifier;
    DotNetInstalled     = $($DotNetVersions.Count -gt 0);
    DotNetVersions      = $DotNetVersions;
    PowerShellInstalled = $PowerShellInstalled;
    PowerShellVersions  = $PowerShellVersions;
});