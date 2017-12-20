[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Declare an output var to hold our goodies
[System.Collections.ArrayList]$Applications = @();

# Path to the registry key we want to query
$UninstallKeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

# Init the .NET RegistryKey object
$Reg = [Microsoft.Win32.Registry]::LocalMachine;

# Drill down and get what we're after
$Reg.OpenSubKey($UninstallKeyPath).GetSubKeyNames() | %{

    # Grab the key name from the pipeline
    $Key = $_;

    # Get the application information
    $Application = $Reg.OpenSubKey($($UninstallKeyPath+"\"+$Key));

    # Build a new object to output with
    [Void]($Applications.Add($([PSCustomObject]@{
        MachineIdentifier = $ID;
        DisplayName       = $Application.GetValue("DisplayName");
        DisplayVersion    = $Application.GetValue("DisplayVersion");
        InstallLocation   = $Application.GetValue("InstallLocation");
        Publisher         = $Application.GetValue("Publisher");
        HelpLink          = $Application.GetValue("HelpLink");
    })));
}

# And return
return ,$Applications;