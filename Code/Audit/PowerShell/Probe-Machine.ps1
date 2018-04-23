[Cmdletbinding()]
Param(
    # The target we want to probe
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$Target,

    # Credentials object
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [System.Object[]]$Credentials
)

# Set E|P|W prefs and start time
$ErrorActionPreference = "Stop";
$ProgressPreference = "SilentlyContinue";
$WarningPreference = "SilentlyContinue";
$StartTime = Get-Date;

# Import the utils module
try {
    Import-Module "$PSScriptRoot\Utility.psm1" -Force -DisableNameChecking;
} catch {
    throw "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Probe Error] Error importing utility module: $($_.Exception.Message)";
}

# Add a probe object to our target
$Target | Add-Member -MemberType NoteProperty -Name Probe -Value $(New-Probe);

# Get some key:value properties for this target
$Target.Probe.ICMP = Test-IcmpPing -Endpoint $Target.Endpoint;
$Target.Probe.NmapDiscoveredOS = Nmap-TargetOS -Endpoint $Target.Endpoint;

# Resolve the endpoints for this target and add them to the target probe object
$ResolvedEndpoints = Resolve-Endpoints -Endpoint $Target.Endpoint;
$Target.Probe.HostNames = $ResolvedEndpoints.HostNames;
$Target.Probe.DnsAliases = $ResolvedEndpoints.DnsAliases;
$Target.Probe.IPv4Addresses = $ResolvedEndpoints.IPv4Addresses;
$Target.Probe.IPv6Addresses = $ResolvedEndpoints.IPv6Addresses;

# Set ourselves a WinRM loop controller
$WinRmTesting  = $True;

# Loop while we resolve the possible WinRM connection options
While ($WinRmTesting) {

    # Ok first we need to resolve which credential we're using
    if (!$Target.Probe.WinRmCredentialsTested) {
        # Not tried anything yet, get the known or default credential
        $C = $(if ($Target.Credential){
            $Credentials | ?{$_.ID -eq $Target.Credential};
        } else {
            $Credentials | ?{$_.IsDefault -and $_.Type.Contains("Windows")};
        });
    } else {
        # Ok we've tried credentials previously to this, get the next one
        $C = $Credentials | ?{
            $Target.Probe.WinRmCredentialsTested -notcontains $_.ID -and
            $_.Type.Contains("Windows")
        } | Select -First 1;
    }

    # Build a PSCredential from the object
    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
    $PSCredential = New-Object System.Management.Automation.PSCredential($C.Username,$SecurePassword);

    # Splat up the WinRM params for this check
    $WinRmParams = @{
        Target            = $Target.Endpoint;
        Credential        = $PSCredential;
        ScriptPath        = "$PSScriptRoot\Collectors\WinRm\_ConnectionCheck.ps1";
        MachineIdentifier = $([Guid]::NewGuid().Guid);
        UseSsl            = $Target.Probe.WinRmUseTls;
    }

    # Now execute the check and act on the results
    try {
        $WinRmResult = .\Invoke-WinRM.ps1 @WinRmParams;
    
        # Check for null return
        if ($WinRmResult) {
            # Ok if we get this far we know the settings on this run were good
            $Target.Probe.WinRmCredentialsSuccessful += $C.ID;
            $Target.Probe.WinRmCredentialsTested += $C.ID;

            # Store the OS result
            $Target.Probe.RemoteDiscoveredOS = $WinRmResult;

            # Set WinRM to successful
            $Target.Probe.WinRmSuccess = $True;

            # Stop the loop
            $WinRmTesting = $False;
        } else {
            throw "Target returned a null value for the connection check.";
        }

    } catch {
        # Grab the exception from the pipeline so we don't lose it
        $E = $_.Exception.Message

        # Branch for testing TLS
        if ($Target.Probe.WinRmUseTls) {
            # Ok check if the connection worked but the credential failed
            if ($_.Exception.Message.Contains("Access Denied")) {
                # We now know to use TLS going forward but not this credential
                $Target.Probe.WinRmCredentialsTested += $C.ID;
            } else {
                # We know TLS doesn't work but not whether this credential does
                $Target.Probe.WinRmUseTls = $False;
            }
        } 
        # Branch for testing HTTP
        else { 
            # Ok check if the connection worked but the credential failed
            if ($E.Contains("Access Denied")) {
                # We now know this credential doesn't work
                $Target.Probe.WinRmCredentialsTested += $C.ID;
            } else {
                # Ok something else is wrong with WinRM here, try and parse the message
                if (([Xml]$E).DocumentElement.Message) {
                    $Target.Probe.WinRmError = ([Xml]$E).DocumentElement.Message;
                } else {
                    $Target.Probe.WinRmError = $E;
                }
                
                # Set WinRM to failed
                $Target.Probe.WinRmSuccess = $False;

                # Stop the loop
                $WinRmTesting = $False;
            }
        }
    }
}

# Set ourselves a WMI loop controller
$WmiTesting  = $True;

# Loop while we resolve the possible WMI connection options
While ($WmiTesting) {

    # Ok first we need to resolve which credential we're using
    if (!$Target.Probe.WmiCredentialsTested) {
        # Not tried anything yet, get the known or default credential
        $C = $(if ($Target.Credential){
            $Credentials | ?{$_.ID -eq $Target.Credential};
        } else {
            $Credentials | ?{$_.IsDefault -and $_.Type.Contains("Windows")};
        });
    } else {
        $C = $Credentials | ?{
            $Target.Probe.WmiCredentialsTested -notcontains $_.ID -and
            $_.Type.Contains("Windows")
        } | Select -First 1;
    }

    # Build a PSCredential from the object
    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
    $PSCredential = New-Object System.Management.Automation.PSCredential($C.Username,$SecurePassword);

    # Splat up the WMI params for this check
    $WmiParams = @{
        Target            = $Target.Endpoint;
        Credential        = $PSCredential;
        ScriptPath        = "$PSScriptRoot\Collectors\WMI\_ConnectionCheck.ps1";
        MachineIdentifier = $([Guid]::NewGuid().Guid);
    }

    # Now execute the check and act on the results
    try {
        $WmiResult = .\Invoke-Wmi.ps1 @WmiParams;
    
        # Check for null return
        if ($WmiResult) {
            # Ok if we get this far we know the settings on this run were good
            $Target.Probe.WmiCredentialsSuccessful += $C.ID;
            $Target.Probe.WmiCredentialsTested += $C.ID;

            # Store the OS result
            $Target.Probe.RemoteDiscoveredOS = $WmiResult;

            # Set WinRM to successful
            $Target.Probe.WmiSuccess = $True;

            # Stop the loop
            $WmiTesting = $False;
        } else {
            throw "Target returned a null value for the connection check.";
        }

    } catch {
        # Grab the exception from the pipeline so we don't lose it
        $E = $_.Exception.Message

        # Ok check if the connection worked but the credential failed
        if ($E.Contains("Access Denied")) {
            # We now know this credential doesn't work
            $Target.Probe.WmiCredentialsTested += $C.ID;
        } else {
            # Ok something else is wrong with WMI here, try and parse the message
            if (([Xml]$E).DocumentElement.Message) {
                $Target.Probe.WmiError = ([Xml]$E).DocumentElement.Message;
            } else {
                $Target.Probe.WmiError = $E;
            }
            
            # Set WMI to failed
            $Target.Probe.WmiSuccess = $False;

            # Stop the loop
            $WmiTesting = $False;
        }
    }
}

# Set ourselves a SSH loop controller
$SshTesting  = $True;

# Loop while we resolve the possible SSH connection options
While ($SshTesting) {

    # Ok first we need to resolve which credential we're using
    if (!$Target.Probe.SshCredentialsTested) {
        # Not tried anything yet, get the known or default credential
        $C = $(if ($Target.Credential){
            $Credentials | ?{$_.ID -eq $Target.Credential};
        } else {
            $Credentials | ?{$_.IsDefault -and $_.Type.Contains("Linux")} | Select -First 1;
        });
    } else {
        # Ok we've tried credentials previously to this, get the next one
        $C = $Credentials | ?{
            $Target.Probe.SshCredentialsTested -notcontains $_.ID -and
            $_.Type.Contains("Linux")
        } | Select -First 1;
    }

    # Splat up the basic ssh params
    $SshParams = @{
        Target            = $Target.Endpoint;
        Username          = $C.Username;
        ScriptPath        = "$PSScriptRoot\Collectors\SSH\_ConnectionCheck.sh";
        MachineIdentifier = $([Guid]::NewGuid().Guid);
    }

    # Now we need to work out what sort of credential this is and add to the params accordingly
    Switch ($C.Type)
    {
        "Linux/Unix Credentials" {
            $SshParams | Add-Member -MemberType NoteProperty -Name Password -Value $C.Password;
        }
        "Linux/Unix Private Key file" {
            $SshParams | Add-Member -MemberType NoteProperty -Name PrivateKeyFilePath -Value $C.PrivateKeyFilePath;
        }
        "Linux/Unix Private Key file with Passphrase" {
            $SshParams | Add-Member -MemberType NoteProperty -Name PrivateKeyFilePath -Value $C.PrivateKeyFilePath;
            $SshParams | Add-Member -MemberType NoteProperty -Name PrivateKeyPassphrase -Value $C.PrivateKeyPassphrase;
        }
    }

    # Now execute the check and act on the results
    try {
        $SshResult = .\Invoke-Ssh.ps1 @SshParams;
    
        # Check for null return
        if ($SshResult) {
            # Ok if we get this far we know the settings on this run were good
            $Target.Probe.SshCredentialsSuccessful += $C.ID;
            $Target.Probe.SshCredentialsTested += $C.ID;

            # Store the OS result
            $Target.Probe.RemoteDiscoveredOS = $SshResult;

            # Set WinRM to successful
            $Target.Probe.SshSuccess = $True;

            # Stop the loop
            $SshTesting = $False;
        } else {
            throw "Target returned a null value for the connection check.";
        }

    } catch {
        # Grab the exception from the pipeline so we don't lose it
        $E = $_.Exception.Message

        # Ok check if the connection worked but the credential failed
        if ($E.Contains("Access Denied")) {
            # We now know this credential doesn't work
            $Target.Probe.SshCredentialsTested += $C.ID;
        } else {
            # Ok something else is wrong with WMI here, try and parse the message
            $Target.Probe.SshError = $E;

            # Set SSH to failed
            $Target.Probe.SshSuccess = $False;

            # Stop the loop
            $SshTesting = $False;
        }
    }
}

# Set our remote connectivity health property based on what we know now
if ((@($Result.Probe.WinRmSuccess,$Result.Probe.WmiSuccess,$Result.Probe.SshSuccess) -Contains $True)) {
    $Result.Probe.RemoteHealthy = $True;
} else {
    $Result.Probe.RemoteHealthy = $False;
}

# Set our scan time for this host
$EndTime = Get-Date;
$Result.Probe.TimeTaken = $(New-TimeSpan $StartTime $EndTime);

# And return the updated result object
return $Result;