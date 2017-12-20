[CmdletBinding()]
Param(
    # Guid for matching back to the correc machine
    [Parameter(Mandatory=$True)]
    [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
    [String]$ID
)

# Set EAP
$ErrorActionPreference = "Stop";

# Path to the registry keys we want to query
$RootKey = "SYSTEM\CurrentControlSet\Services\W32Time";
$ParamsKey = "$RootKey\Parameters";
$ConfigKey = "$RootKey\Config";
    
# Init the .NET RegistryKey object
$Reg = [Microsoft.Win32.Registry]::LocalMachine;
    
# Ok first we want to get the timeserver and type setting our hash up for later
$TimeProperties = @{
    MachineIdentifier = $ID;
    Server            = ($Reg.OpenSubKey($ParamsKey).GetValue("NtpServer") -split ",")[0];
    Type              = $Reg.OpenSubKey($ParamsKey).GetValue("Type");
}

# Drill down into the config key and get the options dynamically
$Reg.OpenSubKey($ConfigKey).GetValueNames() | %{
    
    # Grab the key from the pipeline and get the value
    $Key = $_;
    $Value = $Reg.OpenSubKey($ConfigKey).GetValue($Key);
    
    # Add to the time properties object
    $TimeProperties.Add($Key,$Value);
}

# And return a PSCustomObject with the combined properties
return $(,@(New-Object PSCustomObject -Property $TimeProperties));