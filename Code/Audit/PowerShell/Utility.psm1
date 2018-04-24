# Writes json status update to stdout
Function Write-StatusUpdate {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Counter
    )

    # Ok we need to get the average time of both probes and audits
    $AverageProbeSeconds = $Counter.ProbeTimeSpans | Measure -Property TotalSeconds -Average | Select -ExpandProperty Average;
    $AverageAuditSeconds = $Counter.AuditTimeSpans | Measure -Property TotalSeconds -Average | Select -ExpandProperty Average;
    
    # Work out how many are left of each (count)
    $ProbeRemainingCount = $Counter.ProbeQueueCount - $($Counter.ProbeSuccessCount + $Counter.ProbeFailedCount);
    $AuditRemainingCount = $Counter.AuditQueueCount - $($Counter.AuditSuccessCount + $Counter.AuditFailedCount);

    # Work out how many are left of each (seconds)
    $ProbeSecondsRemaining = $ProbeRemainingCount * $AverageProbeSeconds;
    $AuditSecondsRemaining = $AuditRemainingCount * $AverageAuditSeconds;

    # Calculate the estimated time remaining
    $EstimatedSecondsRemaining = [Math]::Round($($ProbeSecondsRemaining + $AuditSecondsRemaining));

    # Build the json output
    $JSON = @{
        EstimatedSecondsRemaining = $EstimatedSecondsRemaining;
        ProbeSuccessCount = $Counter.ProbeSuccessCount;
        ProbeFailedCount = $Counter.ProbeFailedCount;
        AuditQueueCount = $Counter.AuditQueueCount;
        AuditSuccessCount = $Counter.AuditSuccessCount;
        AuditFailedCount = $Counter.AuditFailedCount;
    } | ConvertTo-Json -Compress;

    # Build the status string
    $StatusString = "SCANUPDATE:$JSON";

    # And write out
    Write-Output $StatusString;
}

# Writes host update to stdout
Function Write-HostUpdate {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ID,
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Int]$Status,
        [Parameter(Mandatory=$False)]
        [System.Collections.ArrayList]$Errors
    )

    # Build the json output
    $JSON = @{
        ID = $ID;
        Status = $Status;
        Errors = $Errors;
    } | ConvertTo-Json -Compress;

    # Build the status string
    $StatusString = "HOSTUPDATE:$JSON";

    # And write out
    Write-Output $StatusString;
}

# Unrolls an encoded json/base64 string
Function Unroll-EncodedJson {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Path
    )

    # Get the json string
    $Json = Get-Content $Path -Raw;

    # Return the json to an object
    $Object = $Json | ConvertFrom-Json;

    # And return the object
    return $Object;
}

# Returns a bool based on ICMP ping result
Function Test-IcmpPing {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Endpoint
    )

    # Set EAP
    $ErrorActionPreference = "Stop";

    # ICMP ping
    try {
        # Init ping object and hit it
        $Ping       = New-Object System.Net.NetworkInformation.Ping;
        $PingResult = $Ping.Send($Endpoint, 1000, $(New-Object Byte[] 32));

        # Test the result
        if($PingResult.Status -eq "Success") {
            return $True;
        } else {
            return $False;
        }
    }
    catch {
        return $False;
    }
}

# Recursive resolver for ip/dns/hostnames
Function Resolve-Endpoints {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Endpoint
    )

    # Build our output result so we can add properties easily
    $Result = $([PSCustomObject]@{
        Hostnames = $(New-Object System.Collections.ArrayList);
        DnsAliases = $(New-Object System.Collections.ArrayList);
        Ipv4Addresses = $(New-Object System.Collections.ArrayList);
        Ipv6Addresses = $(New-Object System.Collections.ArrayList);
    });

    # Declare an array to hold our resolving targets
    $Targets = New-Object System.Collections.ArrayList;

    # Init a loop controller and seed our resolvers array
    $Resolving = $True;
    [Void]($Targets.Add($([PSCustomObject]@{
        Target   = $Endpoint;
        Resolved = $False;
    })));

    # Recursive resolution until we find all the possible entries
    While($Resolving) {

        # Build some current counters
        $HostNamesCounter     = $Result.Hostnames.Count;
        $DnsAliasesCounter    = $Result.DnsAliases.Count;
        $Ipv4AddressesCounter = $Result.Ipv4Addresses.Count;
        $Ipv6AddressesCounter = $Result.Ipv6Addresses.Count;
        $TargetsCounter       = $Targets.Count;

        # Resolve all the current targets we have
        try {
            $ResolvedTargets = $($Targets.Where({!$_.Resolved}) | %{
                [System.Net.DNS]::GetHostEntry($_.Target);           
            });
        } catch {
            # If we've failed to resolve anything, break
            $Resolving = $False; Break;
        };

        # Update the targets collection now we're not using it
        $Targets | %{$_.Resolved = $True};

        # Process the results we've gathered
        $ResolvedTargets | %{

            # Grab the resolved target from the pipeline
            $ResolvedTarget = $_;
            
            # Add the primary DNS name to the store if !exists
            if (!($Result.DnsAliases.Contains($ResolvedTarget.HostName.ToLower()))) {
                [Void]($Result.DnsAliases.Add($ResolvedTarget.HostName.ToLower()));
            }

            # Add the primary DNS name to the targets if !exists
            if (!($Targets.Where({$_.Target -eq $ResolvedTarget.HostName}))) {
                [Void]($Targets.Add($([PSCustomObject]@{
                    Target   = $ResolvedTarget.HostName;
                    Resolved = $False;
                })));
            }

            # Split out the hostname from the DNS name
            $Hostname = $ResolvedTarget.HostName -split "\." | Select -First 1;

            # Add the hostname to the store if !exists
            if (!($Result.Hostnames.Contains($Hostname.ToUpper()))) {
                [Void]($Result.Hostnames.Add($Hostname.ToUpper()));
            }

            # Add the hostname to the targets if !exists
            if (!($Targets.Where({$_.Target -eq $Hostname}))) {
                [Void]($Targets.Add($([PSCustomObject]@{
                    Target   = $Hostname;
                    Resolved = $False;
                })));
            }

            # For each of the DNS aliases, add to the store/targets if !exists
            $ResolvedTarget.Aliases | %{
                
                # Grab the alias from the pipeline
                $Alias = $_;

                # DNS entries
                if (!($Result.DnsAliases.Contains($Alias.ToLower()))) {
                    [Void]($Result.DnsAliases.Add($Alias.ToLower()));
                }
                
                # Targets
                if (!($Targets.Where({$_.Target -eq $Alias}))) {
                    [Void]($Targets.Add($([PSCustomObject]@{
                        Target   = $Alias;
                        Resolved = $False;
                    })));
                }
            }

            # For each of the IP addresses, add to the store/targets if !exists
            $ResolvedTarget.AddressList | %{
                
                # Grab the IP from the pipeline
                $IP = $_.IPAddressToString;

                # IP Addresses
                if ($IP -match "^\d+.\d+.\d+.\d+$") {
                    if (!($Result.Ipv4Addresses.Contains($IP))) {
                        [Void]($Result.Ipv4Addresses.Add($IP));
                    }
                } else {
                    if (!($Result.Ipv6Addresses.Contains($IP))) {
                        [Void]($Result.Ipv6Addresses.Add($IP));
                    }
                }

                # Targets
                if (!($Targets.Where({$_.Target -eq $IP}))) {
                    [Void]($Targets.Add($([PSCustomObject]@{
                        Target   = $IP;
                        Resolved = $False;
                    })));
                }
            }

        }

        # Check the counts based on what we gathered at the start
        $FoundHostNames     = $Result.Hostnames.Count - $HostNamesCounter;
        $FoundDnsAliases    = $Result.DnsAliases.Count - $DnsAliasesCounter;
        $FoundIpv4Addresses = $Result.Ipv4Addresses.Count - $Ipv4AddressesCounter;
        $FoundIpv6Addresses = $Result.Ipv6Addresses.Count - $Ipv6AddressesCounter;
        $FoundTargets       = $Targets.Count - $TargetsCounter;

        # If none of our counters have incremented, break
        if (($FoundHostNames + $FoundDnsAliases + $FoundIpv4Addresses + $FoundIpv6Addresses + $FoundTargets) -eq 0) {
            $Resolving = $False; Break;
        }
    }

    # And return the result
    return $Result;
}

# Attempts to get remote host OS
Function Nmap-TargetOS {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Endpoint
    )

    # Set EAP
    $ErrorActionPreference = "Stop";

    # Try and get the target's OS
    try {
        # Do the nmap scan
        $Nmap = Invoke-Expression "nmap -oX - --script smb-os-discovery.nse $Endpoint *>&1";
        $OS = [Regex]::Match(([Xml]$Nmap).nmaprun.host.hostscript.script.output,'OS\:\s(.*?)\n').Value.Replace("OS: ","").Trim();
        
        # Check and see if we got a result
        if ($OS) {
            return $OS;
        } else {
            return "Unknown (Nmap)";
        }
        
    } catch {
        return "Unknown (Nmap)";
    }
}

# Returns a probe object
Function New-Probe {

    return $([PSCustomObject][Ordered]@{
        NmapDiscoveredOS = $Null;
        RemoteDiscoveredOS = $Null;
        TimeTaken = $Null;
        WinRmCredentialsTested = $(New-Object System.Collections.ArrayList);
        WinRmCredentialsSuccessful = $Null;
        WmiCredentialsTested = $(New-Object System.Collections.ArrayList);
        WmiCredentialsSuccessful = $Null;
        SshCredentialsTested = $(New-Object System.Collections.ArrayList);
        SshCredentialsSuccessful = $Null;
        ICMP = $Null;
        HostNames = $(New-Object System.Collections.ArrayList);
        DnsAliases = $(New-Object System.Collections.ArrayList);
        IPv4Addresses = $(New-Object System.Collections.ArrayList);
        IPv6Addresses = $(New-Object System.Collections.ArrayList);
        RemoteHealthy = $Null;
        WinRmSuccess = $Null;
        WinRmError = $Null;
        WinRmUseTls = $True;
        WmiSuccess = $Null;
        WmiError = $Null;
        SshSuccess = $Null;
        SshError = $Null;
        SshUseCredentials = $Null;
        SshUsePrivateKey = $Null;
        SshUsePrivateKeyPassphrase = $Null;
    });
}