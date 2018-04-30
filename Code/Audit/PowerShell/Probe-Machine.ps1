[Cmdletbinding()]
Param(
    # The target we want to probe
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$Target,

    # Credentials object
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [System.Object[]]$Credentials,

    # Root directory path for where this is running
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$RootDirectory
)

# Set E|P|W prefs and start time
$ErrorActionPreference = "Stop";
$ProgressPreference    = "SilentlyContinue";
$WarningPreference     = "SilentlyContinue";
$StartTime             = Get-Date;

# Rehydrate our errors object
$Target = $Target | Select -Property * -ExcludeProperty Errors;
$Target | Add-Member -MemberType NoteProperty -Name Errors -Value @();

# Import the utils module
try {
    Import-Module "$RootDirectory\PowerShell\Utility.psm1" -Force -DisableNameChecking;
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Init Error] Importing utility module failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
    return $Target;
}

# Add a probe object to our target
try {
    $Target | Add-Member -MemberType NoteProperty -Name Probe -Value $(New-Probe);
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Init Error] Adding new Probe object failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
    return $Target;
}

# Test ICMP
try {
    $Target.Probe.Networking.ICMP = Test-IcmpPing -Endpoint $Target.Endpoint;
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] ICMP test failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
}

# Try and discover the OS
try {
    $Target.Probe.Info.NmapDiscoveredOS = Nmap-TargetOS -Endpoint $Target.Endpoint;
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] Nmap OS discovery failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
}

# Resolve the endpoints for this target and add them to the target probe object
try {
    $ResolvedEndpoints = Resolve-Endpoints -Endpoint $Target.Endpoint;
    $Target.Probe.Networking.HostNames     = $ResolvedEndpoints.HostNames;
    $Target.Probe.Networking.DnsAliases    = $ResolvedEndpoints.DnsAliases;
    $Target.Probe.Networking.IPv4Addresses = $ResolvedEndpoints.IPv4Addresses;
    $Target.Probe.Networking.IPv6Addresses = $ResolvedEndpoints.IPv6Addresses;
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] Recursive target lookup failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
}

# Work out whether what type of connections we should try
if ($Target.OperatingSystem.Contains("Windows") -or $Target.Probe.Info.NmapDiscoveredOS.Contains("Windows")) {
    $WmiTesting = $True;
    $SshTesting = $False;
} elseif ($Target.OperatingSystem.Contains("Linux") -or $Target.Probe.Info.NmapDiscoveredOS.Contains("Linux")) {
    $WmiTesting = $False;
    $SshTesting = $True;
} else {
    $WmiTesting = $True;
    $SshTesting = $True;
}

# Loop while we resolve the possible WMI connection options
While ($WmiTesting) {

    # Ok first we need to resolve which credential we're using
    if (!$Target.Probe.Credentials.Tested) {
        # Not tried anything yet, get the known or default credential
        $C = $(if ($($Credentials | ?{$_.ID -eq $Target.Credential})){
            $Credentials | ?{$_.ID -eq $Target.Credential};
        } else {
            $Credentials | ?{$_.IsDefault -and $_.Type.Contains("Windows")};
        });
    } else {
        $C = $Credentials | ?{
            $Target.Probe.Credentials.Tested -notcontains $_.ID -and
            $_.Type.Contains("Windows")
        } | Select -First 1;
    }

    # Check and see if we're out of credentials
    if (!$C) {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] No supplied WMI credentials valid for this target.";
        $Target.Errors += $E;
        $WmiTesting = $False;
        break;
    }

    # Build a PSCredential from the object
    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
    $Username = "{0}\{1}" -f $C.Domain,$C.Username;
    $PSCredential = New-Object System.Management.Automation.PSCredential($Username,$SecurePassword);

    # Now execute the check and act on the results
    try {
        $WmiResult = Invoke-Wmi `
                        -Target $Target.Endpoint `
                        -Credential $PSCredential `
                        -ScriptPath "$RootDirectory\PowerShell\Collectors\WMI\_ConnectionCheck.ps1" `
                        -MachineIdentifier $Target.ID;
    
        # Ok if we get this far we know the settings on this run were good
        $Target.Probe.Credentials.Successful = $C.ID;
        $Target.Probe.Credentials.Tested += $C.ID;
        $Target.Probe.RemoteConnectivity.Wmi.Authentication = "PSCredential";

        # Store the OS result
        $Target.Probe.Info.RemoteDiscoveredOS = $WmiResult;

        # Set WMI to successful
        $Target.Probe.RemoteConnectivity.Wmi.Successful = $True;

        # Stop the loop
        $WmiTesting = $False;

    } catch {
        # Grab the exception from the pipeline so we can parse it
        $Ex = $_.Exception.Message;

        # Check and see if it's a WSMan XML message
        if ($(try{([Xml]$Ex).DocumentElement.Message}catch{$False})) {
            $Exception = ([Xml]$Ex).DocumentElement.Message;
        } else {
            $Exception = $Ex;
        }

        # Ok check if the connection worked but the credential failed
        if ($Exception.Contains("Access Denied")) {
            # We now know this credential doesn't work
            $Target.Probe.Credentials.Tested += $C.ID;
        } else {
            # Build our output error and add it to the target object
            $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] WMI Remote access failed with exception: $Exception";
            $Target.Errors += $E;
            
            # Set WMI to failed and capture the raw error
            $Target.Probe.RemoteConnectivity.Wmi.Successful = $False;
            $Target.Probe.RemoteConnectivity.Wmi.ErrorMessage = $Ex;

            # Stop the loop
            $WmiTesting = $False;
        }
    }
}

# Loop while we resolve the possible SSH connection options
While ($SshTesting) {

    # Ok first we need to resolve which credential we're using
    if (!$Target.Probe.Credentials.Tested) {
        # Not tried anything yet, get the known or default credential
        $C = $(if ($($Credentials | ?{$_.ID -eq $Target.Credential})){
            $Credentials | ?{$_.ID -eq $Target.Credential};
        } else {
            $Credentials | ?{$_.IsDefault -and $_.Type.Contains("Linux")} | Select -First 1;
        });
    } else {
        # Ok we've tried credentials previously to this, get the next one
        $C = $Credentials | ?{
            $Target.Probe.Credentials.Tested -notcontains $_.ID -and
            $_.Type.Contains("Linux")
        } | Select -First 1;
    }

    # Check and see if we're out of credentials
    if (!$C) {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] No supplied SSH credentials valid for this target.";
        $Target.Errors += $E;
        $SshTesting = $False;
        break;
    }

    # Now we need to work out what sort of credential this is and exec accordingly
    try {
        Switch ($C.Type)
        {
            "Linux/Unix Credentials" {
                # Set some flags we can use later if successful
                $Authentication = "Credentials";

                # And exec to try and get our result
                $SshResult = Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -Password $C.Password `
                                -ScriptPath "$RootDirectory\PowerShell\Collectors\SSH\_ConnectionCheck.sh" `
                                -MachineIdentifier $Target.ID;
            }
            "Linux/Unix Private Key file" {
                # Set some flags we can use later if successful
                $Authentication = "PrivateKey";

                # And exec to try and get our result
                $SshResult = Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -PrivateKeyFilePath $C.PrivateKeyFilePath `
                                -ScriptPath "$RootDirectory\PowerShell\Collectors\SSH\_ConnectionCheck.sh" `
                                -MachineIdentifier $Target.ID;
            }
            "Linux/Unix Private Key file with Passphrase" {
                # Set some flags we can use later if successful
                $Authentication = "PrivateKeyWithPassphrase";

                # And exec to try and get our result
                $SshResult = Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -PrivateKeyFilePath $C.PrivateKeyFilePath `
                                -PrivateKeyPassphrase $C.PrivateKeyPassphrase `
                                -ScriptPath "$RootDirectory\PowerShell\Collectors\SSH\_ConnectionCheck.sh" `
                                -MachineIdentifier $Target.ID;
            }
        }

        # Ok if we get this far we know the settings on this run were good
        $Target.Probe.Credentials.Successful = $C.ID;
        $Target.Probe.Credentials.Tested += $C.ID;
        $Target.Probe.RemoteConnectivity.Authentication = $Authentication;

        # Store the OS result
        $Target.Probe.Info.RemoteDiscoveredOS = $SshResult;

        # Set ssh to successful
        $Target.Probe.RemoteConnectivity.Ssh.Successful = $True;

        # Stop the loop
        $SshTesting = $False;

    } catch {
        # Grab the exception from the pipeline so we can parse it
        $Exception = $_.Exception.Message;

        # Ok check if the connection worked but the credential failed
        if ($Exception.Contains("Access Denied")) {
            # We now know this credential doesn't work
            $Target.Probe.Credentials.Tested += $C.ID;
        } else {
            # Build our output error and add it to the target object
            $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] SSH Remote access failed with exception: $Exception";
            $Target.Errors += $E;

            # Set SSH to failed and capture the raw error
            $Target.Probe.RemoteConnectivity.Ssh.Successful = $False;
            $Target.Probe.RemoteConnectivity.Ssh.ErrorMessage = $Ex;
            
            # Set SSH to failed
            $Target.Probe.RemoteConnectivity.Ssh.Successful = $False;

            # Stop the loop
            $SshTesting = $False;
        }
    }
}

# Set our remote connectivity health property based on what we know now
if ($Target.Probe.RemoteConnectivity.Wmi.Successful -or $Target.Probe.RemoteConnectivity.Ssh.Successful) {
    $Target.Probe.RemoteConnectivity.OK = $True;
} else {
    $Target.Probe.RemoteConnectivity.OK = $False;
}

# Set our scan time for this host
$EndTime = Get-Date;
$Target.Probe.Info.TimeTaken = $(New-TimeSpan $StartTime $EndTime);

# And return the updated target object
return $Target;