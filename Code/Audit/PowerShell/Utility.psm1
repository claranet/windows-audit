# Writes json status update to stdout
Function Write-StatusUpdate {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Counter
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
        [Array]$Errors
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
        [Array]$Errors
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

# Writes out a scan termination
Function Terminate-Scan {
    [Cmdletinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateSet("Error","Success")]
        [String]$State,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Message
    )

    # Build the json output
    $JSON = @{
        State = $State;
        Message = $Message;
    } | ConvertTo-Json -Compress;

    # Build the status string
    $TerminationString = "SCANTERMINATE:$JSON";

    # And write out
    Write-Output $TerminationString;
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
        [Array]$Errors
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
        #$Nmap = Invoke-Expression "nmap -oX - --script smb-os-discovery.nse $Endpoint *>&1";
        #$OS = [Regex]::Match(([Xml]$Nmap).nmaprun.host.hostscript.script.output,'OS\:\s(.*?)\n').Value.Replace("OS: ","").Trim();
        
        # Check and see if we got a result
        #if ($OS) {
        #    return $OS;
        #} else {
            return "Unknown (Nmap)";
        #}
        
    } catch {
        return "Unknown (Nmap)";
    }
}

# Returns a probe object
Function New-Probe {

    return $([PSCustomObject][Ordered]@{
        IsDead = $Null;
        Info = [PSCustomObject][Ordered]@{
            TimeTaken          = $Null;
            NmapDiscoveredOS   = $Null;
            RemoteDiscoveredOS = $Null;
        };
        Networking = [PSCustomObject][Ordered]@{
            ICMP          = $Null;
            HostNames     = $Null;
            DnsAliases    = $Null;
            IPv4Addresses = $Null;
            IPv6Addresses = $Null;
        };
        Credentials = [PSCustomObject][Ordered]@{
            Tested     = @();
            Successful = $Null;
        };
        RemoteConnectivity = [PSCustomObject][Ordered]@{
            OK  = $Null;
            Wmi = [PSCustomObject][Ordered]@{
                Successful     = $Null;
                ErrorMessage   = $Null;
                Authentication = $Null;
            };
            Ssh = [PSCustomObject][Ordered]@{
                Successful     = $Null;
                ErrorMessage   = $Null;
                Authentication = $Null;
            };
        };
    });
}

# Returns a new audit object
Function New-Audit {

    return $([PSCustomObject][Ordered]@{
        Info = [PSCustomObject][Ordered]@{
            TimeTaken = $Null;
            Completed = $Null;
        };
        Sections = $Null;
    });
}

# Thin wrapper for Get-WmiObject with additional params
Function Invoke-Wmi {
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
    
        # The script we're executing
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptPath,
    
        # The Machine identifer we'll tag the result with
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
        [String]$MachineIdentifier
    )
    
    # Set EAP
    $ErrorActionPreference = "Stop";
    
    # Invoke the script supplying the params
    $Result = & $ScriptPath $Target $Credential $MachineIdentifier;
    
    # And return
    return $Result;
}

# Async terminating process handler borrowed from elsewhere for now
Function Invoke-Process {
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = 0, Position = 0)]
        [string]$FileName = "PowerShell.exe",

        [Parameter(Mandatory = 0, Position = 1)]
        [string]$Arguments = "",
        
        [Parameter(Mandatory = 0, Position = 2)]
        [string]$WorkingDirectory = ".",

        [Parameter(Mandatory = 0, Position = 3)]
        [int]$TimeoutMS = 20
    )

    end
    {
        try
        {
            # new Process
            $process = NewProcess -FileName $FileName -Arguments $Arguments -WorkingDirectory $WorkingDirectory
                
            # Event Handler for Output
            $stdEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action $scripBlock -MessageData $stdSb
            $errorEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action $scripBlock -MessageData $errorSb

            # execution
            $process.Start() > $null
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()

            # wait for complete
            WaitProcessComplete -Process $process -TimeoutMS $TimeoutMS

            # verbose Event Result
            $stdEvent, $errorEvent | VerboseOutput

            # output
            return GetCommandResult -Process $process -StandardStringBuilder $stdSb -ErrorStringBuilder $errorSb
        }
        finally
        {
            if ($null -ne $process){ $process.Dispose() }
            if ($null -ne $stdEvent)
            {
                Unregister-Event -SourceIdentifier $stdEvent.Name
                $stdEvent.Dispose()
            }
            if ($null -ne $errorEvent)
            {
                Unregister-Event -SourceIdentifier $errorEvent.Name
                $errorEvent.Dispose()
            }
        }
    }

    begin
    {
        # Prerequisites       
        $stdSb = New-Object -TypeName System.Text.StringBuilder
        $errorSb = New-Object -TypeName System.Text.StringBuilder
        $scripBlock = 
        {
            if (-not [String]::IsNullOrEmpty($EventArgs.Data))
            {
                        
                $Event.MessageData.AppendLine($Event.SourceEventArgs.Data)
            }
        }

        function NewProcess ([string]$FileName, [string]$Arguments, [string]$WorkingDirectory)
        {
            "Execute command : '{0} {1}', WorkingSpace '{2}'" -f $FileName, $Arguments, $WorkingDirectory | VerboseOutput
            # ProcessStartInfo
            $psi = New-object System.Diagnostics.ProcessStartInfo 
            $psi.CreateNoWindow = $true
            $psi.LoadUserProfile = $true
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.FileName = $FileName
            $psi.Arguments+= $Arguments
            $psi.WorkingDirectory = $WorkingDirectory

            # Set Process
            $process = New-Object System.Diagnostics.Process 
            $process.StartInfo = $psi
            return $process
        }

        function WaitProcessComplete ([System.Diagnostics.Process]$Process, [int]$TimeoutMS)
        {
            "Waiting for command complete. It will Timeout in {0}ms" -f $TimeoutMS | VerboseOutput
            $isComplete = $Process.WaitForExit($TimeoutMS)
            if (-not $isComplete)
            {
                "Timeout detected for {0}ms. Kill process immediately" -f $timeoutMS | VerboseOutput
                $Process.Kill()
                $Process.CancelOutputRead()
                $Process.CancelErrorRead()
            }
        }

        function GetCommandResult ([System.Diagnostics.Process]$Process, [System.Text.StringBuilder]$StandardStringBuilder, [System.Text.StringBuilder]$ErrorStringBuilder)
        {
            'Get command result string.' | VerboseOutput
            return [PSCustomObject]@{
                StandardOutput = $StandardStringBuilder.ToString()
                ErrorOutput = $ErrorStringBuilder.ToString()
                ExitCode = $process.ExitCode
            }
        }

        filter VerboseOutput
        {
            #$_ | Out-String -Stream | Write-Verbose
        }
    }
}

# Fat horrible wrapper around plink
Function Invoke-Ssh {
    [Cmdletbinding()]
    Param(
        # The server we're targetting
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Target,
    
        # Username we'll use to connect
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Username,
    
        # Password we'll use to connect
        [Parameter(Mandatory=$False)]
        [String]$Password,
    
        # Private key file path 
        [Parameter(Mandatory=$False)]
        [String]$PrivateKeyFilePath,
    
        # Passphrase for the private key
        [Parameter(Mandatory=$False)]
        [String]$PrivateKeyPassphrase,
    
        # The script we're executing
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptPath,
    
        # The Machine identifer we'll tag the result with
        [Parameter(Mandatory=$True)]
        [ValidateScript({$_ -Match "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"})]
        [String]$MachineIdentifier,
        
        # The Root path to the solution
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$RootPath
    )
    
    # Set EAP
    $ErrorActionPreference = "Stop";

    # Build the SshClient root path
    $SshClientPath = [String]::Format("{0}\SshClient\win-ssh-client.exe", $RootPath);

    # Exec the shell
    $SshResult = & $SshClientPath -t $Target -u $Username -p $Password -s $ScriptPath

    # Check the last exit code
    if ($LASTEXITCODE -gt 0) {
        throw $SshResult;
    } else {
        return $SshResult;
    }

}

# Returns an array of audit sections based on params
Function Get-AuditScripts {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$RootDirectory,

        [Parameter(Mandatory=$True)]
        [ValidateSet("SSH","WMI")]
        [String]$ScriptType,

        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$SemanticData
    )

    # Build the root directory to search
    $ScriptDirectory = "$RootDirectory\PowerShell\Collectors\$ScriptType";

    # Work out which script extension we're using
    $Extension = $(Switch($ScriptType){
        "WMI" {"*.ps1"}
        "SSH" {"*.sh"}
    });

    # Get an array to hold our audit sections
    $AuditSections = @();
    
    # Check here if we have semantic data to process
    if ($SemanticData) {
        
        # See if we can find distro:version specific scripting
        $DistroSpecific = Get-ChildItem $ScriptDirectory -Directory | ?{$_.Name.Contains($SemanticData.DISTRIB_ID.ToLower())};

        # Check to see if we found a folder
        if ($DistroSpecific) {
            
            # Let's split up the name and get some properties
            $Properties    = $DistroSpecific.Name.Split("#");
            $TargetVersion = [Version]($Properties[1]);
            $Modifier      = $Properties[2];
            $SourceVersion = [Version]($SemanticData.VERSION_ID);

            # Switch based on our modifier to determine if we should pull these
            if ($(Switch ($Modifier) {
                "-"  {$TargetVersion -lt $SourceVersion}
                "+"  {$TargetVersion -gt $SourceVersion}
                "="  {$TargetVersion -eq $SourceVersion}
                "+=" {$TargetVersion -ge $SourceVersion}
                "-=" {$TargetVersion -le $SourceVersion}
            })) {
                Get-SpecificAuditScripts -Directory $DistroSpecific.FullName -ScriptType $ScriptType | %{$AuditSections += $_};
            }
        } 
    } 
    
    # Switch here based on script type
    if ($ScriptType -eq "SSH") {
        
        # Get the Generic directory in scope
        $GenericFolder = "$ScriptDirectory\Generic";
        
        # Enumerate the generic scripts
        Get-SpecificAuditScripts -Directory $GenericFolder -ScriptType $ScriptType | %{

            # Grab the script segment from the pipeline
            $ScriptSegment = $_;

            # Make sure we don't overwrite semantic scripting here
            if (($AuditSections | ?{$_.Name -eq $ScriptSegment.Name}).Count -eq 0) {
                $AuditSections += $ScriptSegment;
            }
        }
    } else {
        # Return Windows PowerShell scripting
        $AuditSections = Get-SpecificAuditScripts -Directory $ScriptDirectory -ScriptType $ScriptType
    }

    # And return the data
    return $AuditSections;  
}

# Helper function to return an array of audit sections
Function Get-SpecificAuditScripts {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({Test-Path $_})]
        [String]$Directory,

        [Parameter(Mandatory=$True)]
        [ValidateSet("SSH","WMI")]
        [String]$ScriptType
    )

    # Work out which script extension we're using
    $Extension = $(Switch($ScriptType){
        "WMI" {"*.ps1"}
        "SSH" {"*.sh"}
    });

    # Return the scripts we need
    return @($(Get-ChildItem $Directory -Recurse $Extension | %{
        # Exclude the connection check script
        if (!$_.Name.Contains("_ConnectionCheck")) {
            [PSCustomObject]@{
                Name        = $_.BaseName;
                Script      = $_.FullName;
                Completed   = $False;
                RetryCount  = 0;
                Errors      = @();
                Data        = $Null;
            }
        }
    }));
}