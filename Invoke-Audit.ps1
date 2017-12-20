[Cmdletbinding()]
Param(
    # The PSCredential to be used
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential,

    # The path to the node hints text file
    [Parameter(Mandatory=$True)]
    [ValidateScript({Test-Path $_})]
    [String]$NodeHintsFile,

    # The thread count for runspace pools
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [Int]$ThreadCount = 64
)

# Grab the start time so we can measure how long this took
$StartTime = Get-Date;

# Bring in our functions library
try {
    Write-Host "Importing functions library: " -ForegroundColor Yellow -NoNewline;
    Import-Module ".\Lib\Audit\Audit-Functions.psm1" -DisableNameChecking -Force;
    Write-Host "Succeeded." -ForegroundColor Green;
}
catch {
    # Can't use Write-ShellMessage here
    $Message = "There was a problem attempting to import the functions library: $($_.Exception.Message)";
    Write-Host $Message -ForegroundColor Red;
    Exit(1);
}

# Ok now to import the node hints file
try {
    # FQ the filepath for good measure and write out
    $NodeHintsFilePath = (Resolve-Path $NodeHintsFile).Path;
    Write-ShellMessage -Message "Importing node hints list from '$NodeHintsFilePath'" -Type Info;

    # Ignore everything that doesn't start with an operand
    $NodeHints = Get-Content $NodeHintsFilePath | ?{">","<" -contains $_.ToCharArray()[0]};
}
catch {
    Write-ShellMessage -Message "There was a problem attempting to import the node hints file" -Type Error -ErrorRecord $Error[0];
    Exit(1);
}

# Now we need to process the node hints and generate a hosts list
try {  
    # Write out so the user knows what we're doing
    Write-ShellMessage -Message "Processing $($NodeHints.Count) node hints" -Type Info;

    # Get an intermediate array to hold our nodes list
    [System.Collections.ArrayList]$iNodes = @();

    $NodeHints.ForEach({
            
        # Get the node hint info from the pipeline
        $Operand = $_.Substring(0,1);
        $Node    = $_.Substring(1,$_.Length - 1);

        Write-ShellMessage -Message "Processing node '$Node' with operand '$Operand'" -Type Debug;

        # Swiffy and work out whether CIDR block or single host
        if ($Node.Contains("/")) {

            Write-ShellMessage -Message "Node '$Node is a CIDR block, expanding address space" -Type Debug;

            # Split out the IP/CIDR
            $IPAddress = $Node.Split("/")[0];
            $CIDR      = $Node.Split("/")[1];

            # Create new subnet with the hint details
            $Subnet = Get-IPv4Subnet -IPv4Address $IPAddress -CIDR $CIDR;

            # Get subnet boundaries
            $StartIPv4Address = $Subnet.NetworkID;
            $EndIPv4Address = $Subnet.Broadcast;

            # Convert boundaries to Int64
            $StartIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $StartIPv4Address.ToString()).Int64;
            $EndIPv4Address_Int64 = (Convert-IPv4Address -IPv4Address $EndIPv4Address.ToString()).Int64;

            # Create an array to hold our IPs
            [System.Collections.ArrayList]$IPAddresses = @();

            # Add nodes for each IP in the range
            For ($I = $StartIPv4Address_Int64; $I -le $EndIPv4Address_Int64; $I++) 
            {
                # Gather the IP first so we can write out let the user know what's happening
                $IP = ((Convert-IPv4Address -Int64 $I).IPv4Address).IPAddressToString;
                
                # Write-progress as this might be huge
                Write-Progress `
                    -Activity "Expanding CIDR block '$CIDR'" `
                    -Status "Adding IP address '$IP' to nodes list" `
                    -PercentComplete $(($I/$EndIPv4Address_Int64)*100);
                
                # Add to the iNodes collection
                [Void]($iNodes.Add($([PSCustomObject]@{
                    Operand = $Operand;
                    Node    = $IP;
                })));
            }
        }
        else {
            # Ok just ordinary host, add to the iNodes collection
            [Void]($iNodes.Add($([PSCustomObject]@{
                Operand = $Operand;
                Node    = $Node;
            })));
        }
    });

    # Process node exclusions
    Write-ShellMessage -Message "Processing node exclusions" -Type Debug;

    $iNodes.Where({$_.Operand -eq "<"}).ForEach({
        
        # Ok get the node
        $Node = $_;

        # Let's see if any dupes exist from expanded cidr blocks
        $iNodes.Where({$_.Node -eq $Node.Node}).ForEach({
            # And remove them
            [Void]($iNodes.Remove($_));
        });

    });

    # Build the full nodes list
    Write-ShellMessage -Message "Building node runtime collection" -Type Debug;
    [System.Collections.ArrayList]$NodeCollection = @();
    
    $iNodes.ForEach({

        # Grab the node from the pipeline
        $Node = $_;

        # Regex switch to work out if we're adding a hostname or ip
        Switch -Regex ($Node.Node) {
            '^\d+.\d+.\d+.\d+' {
                # IP - create the node and add to the collection
                [Void]($NodeCollection.Add($([PSCustomObject]@{
                    ID           = [Guid]::NewGuid().Guid;
                    Status       = "Unprocessed";
                    IPAddress    = $Node.Node;
                    Hostname     = $Null;
                    ICMPStatus   = $Null;
                    MACAddress   = $Null;
                    BufferSize   = $Null;
                    ResponseTime = $Null;
                    TTL          = $Null;
                    WinRMStatus  = $Null;
                    Audited      = $False;
                    AuditErrors  = $Null;
                    Completed    = $False;
                })));
            }
            default {
                # Hostname - create the node and add to the collection
                [Void]($NodeCollection.Add($([PSCustomObject]@{
                    ID           = [Guid]::NewGuid().Guid;
                    Status       = "Unprocessed";
                    IPAddress    = $Null;
                    Hostname     = $Node.Node;
                    ICMPStatus   = $Null;
                    MACAddress   = $Null;
                    BufferSize   = $Null;
                    ResponseTime = $Null;
                    TTL          = $Null;
                    WinRMStatus  = $Null;
                    Audited      = $False;
                    AuditErrors  = $Null;
                    Completed    = $False;
                })));
            }
        }
    });

    # Write inital node list to disk
    $NodeCSVFilePath = ".\Audit-Results.csv";
    $NodeCollection | Export-CSV -Path $NodeCSVFilePath -Force -NoTypeInformation;

    # And success
    Write-ShellMessage -Message "Successfully parsed $($iNodes.Count) nodes from hints file" -Type Success;
}
catch {
    Write-ShellMessage -Message "There was a problem attempting to process the node hints file" -Type Error -ErrorRecord $Error[0];
    Exit(1);
}

# Get our scriptblocks in for runspace jobs
try {
    # Network probe
    $ProbeScriptPath = (Resolve-Path ".\Lib\Audit\Probe-Machine.ps1").Path;
    Write-ShellMessage -Message "Importing machine probe script from '$ProbeScriptPath'" -Type Debug;
    $ProbeScriptContent = Get-Content $ProbeScriptPath | Out-String;
    $ProbeScriptBlock = [ScriptBlock]::Create($ProbeScriptContent);

    # Audit scan
    $AuditScriptPath = (Resolve-Path ".\Lib\Audit\Audit-Machine.ps1").Path;
    Write-ShellMessage -Message "Importing machine audit script from '$AuditScriptPath'" -Type Debug;
    $AuditScriptContent = Get-Content $AuditScriptPath | Out-String;
    $AuditScriptBlock = [ScriptBlock]::Create($AuditScriptContent);
}
catch {
    Write-ShellMessage -Message "There was a problem importing runspace job scripts" -Type Error -ErrorRecord $Error[0];
    Exit(1);
}

# Create our runspace pools and job lists
try {
    # Network probe
    Write-ShellMessage -Message "Creating network probe runspace pool and job collection" -Type Debug;
    $ProbeRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThreadCount, $Host);
    $ProbeRunspacePool.Open();
    [System.Collections.ArrayList]$ProbeJobs = @();

    # Audit
    Write-ShellMessage -Message "Creating audit runspace pool and job collection" -Type Debug;
    $AuditRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThreadCount, $Host);
    $AuditRunspacePool.Open();
    [System.Collections.ArrayList]$AuditJobs = @();
}
catch {
    Write-ShellMessage -Message "There was a problem creating the runspace pools" -Type Error -ErrorRecord $Error[0];
    Exit(1);
}

# Add all the network probe jobs to the runspace pool
try {
    Write-ShellMessage -Message "Creating runspace jobs for network probe" -Type Info;
    
    # Enumerate the nodes list, create the jobs and add them to the queue
    $NodeCollection.ForEach({

        # Grab the node from the pipeline
        $Node = $_;

        # Write debug
        $Message = "Creating probe job for node with ID '$($Node.ID)' ($(. ({"$($Node.IPAddress)"},{"$($Node.Hostname)"})[$Node.IPAddress -eq $Null]))";
        Write-ShellMessage -Message $Message -Type Debug;

        # Create hashtable to pass parameters to the probe job
        $ProbeJobParams = @{
            Node         = $Node;
            PSCredential = $PSCredential;
        };
                
        # Create new job
        $ProbeJob = [System.Management.Automation.PowerShell]::Create().AddScript($ProbeScriptBlock).AddParameters($ProbeJobParams);
        $ProbeJob.RunspacePool = $ProbeRunspacePool;

        # Add it to the job queue and spark it up
        [Void]$ProbeJobs.Add($([PSCustomObject]@{
            ID       = $Node.ID;
            Pipeline = $ProbeJob;
            Result   = $ProbeJob.BeginInvoke();
        }));
    });
}
catch {
    Write-ShellMessage -Message "There was a problem creating the runspace jobs for the network probe" -Type Error -ErrorRecord $Error[0];
    Exit(1);
}

# Job queue processing
try {
    # Job Exit
    $JobExitCode = 0;
    
    # Grab the total number of probe jobs as we remove them when they are done
    $ProbeJobCount = $ProbeJobs.Count;
    $ProbeJobCompletedCount = 0;

    # Init a counter for the Audit jobs
    $AuditCompletedJobCount = 0;
    $AuditScanTotalJobCount = 0;

    # Loop to process all queues until empty
    While ($ProbeJobs.Count -gt 0 -or $AuditJobs.Count -gt 0) {
        
        # If there are any probe jobs completed, process them
        $CompletedProbeJobs = @($ProbeJobs | ?{$_.Result.IsCompleted});

        # Add to the totals
        $ProbeJobCompletedCount += $CompletedProbeJobs.Count;

        # Enumerate the completed jobs
        $CompletedProbeJobs.ForEach({
           
            # Get the job from the pipeline
            $CompletedJob = $_;
               
            # Now we need to trap here as the result may be an unwrapped ErrorRecord
            try {
                # Grab the result  
                $Result = $CompletedJob.Pipeline.EndInvoke($CompletedJob.Result);

                # Check the error stream and update the node object
                if ($CompletedJob.Pipeline.HadErrors) {
                    # Enumerate the errors
                    $CompletedJob.Pipeline.Streams.Error | %{
                        # Update the node with these
                        $NodeCollection.Where({$_.ID -eq $CompletedJob.ID}).ForEach({
                            $_.Status += "[$(Get-Date -f "dd/MM/yy HH:mm:ss")][Network Probe Runspace Error]: $($Error[0].Exception.Message)`r`n";
                        });
                    }
                }

                # Update the node in the collection
                $NodeCollection.Where({$_.ID -eq $CompletedJob.ID},'First').ForEach({
                    $_.IPAddress    = $Result.IPAddress;
                    $_.Hostname     = $Result.HostName;
                    $_.ICMPStatus   = $Result.ICMPStatus;
                    $_.MACAddress   = $Result.MACAddress;
                    $_.BufferSize   = $Result.BufferSize;
                    $_.ResponseTime = $Result.ResponseTime;
                    $_.TTL          = $Result.TTL;
                    $_.WinRMStatus  = $Result.WinRMStatus;
                });

                # Now, if it's accessible over WinRM add a job to the audit queue
                if ($Result.WinRMStatus -eq "OK") {
                    
                    # Create hashtable to pass parameters to the Audit job
                    $AuditParams = @{
                        PSCredential     = $PSCredential;
                        Node             = ($NodeCollection.Where({$_.ID -eq $CompletedJob.ID},'First'))[0]; # Indexed to escape enumerable
                        WorkingDirectory = $PSScriptRoot;
                    };
                            
                    # Create new Audit job
                    $AuditJob = [System.Management.Automation.PowerShell]::Create().AddScript($AuditScriptBlock).AddParameters($AuditParams);
                    $AuditJob.RunspacePool = $AuditRunspacePool;

                    # And add it to the collection
                    [Void]($AuditJobs.Add($([PSCustomObject]@{
                        ID       = $CompletedJob.ID;
                        Pipeline = $AuditJob;
                        Result   = $AuditJob.BeginInvoke();
                    })));

                    # Increment the Audit Scan total count
                    $AuditScanTotalJobCount++;
                }
                else { # Otherwise generate an error so we know this didn't go ok
                    $NodeCollection.Where({$_.ID -eq $CompletedJob.ID}).ForEach({
                        $_.Status += "[$(Get-Date -f "dd/MM/yy HH:mm:ss")][Access Exception]: $($_.WinRMStatus)`r`n";
                    });
                }
            }
            catch {
                # Update the node to say it's broken instead
                $NodeCollection.Where({$_.ID -eq $CompletedJob.ID}).ForEach({
                    $_.Status += "[$(Get-Date -f "dd/MM/yy HH:mm:ss")][Network Probe Runspace Error]: $($Error[0].Exception.Message)`r`n";
                });
            }
            
            # Dispose of the pipeline
            $CompletedJob.Pipeline.Dispose();
   
            # Remove job from the collection
            $ProbeJobs.Remove($CompletedJob);
        });
          
        # If there are any audit jobs completed, process them
        $CompletedAuditJobs = @($AuditJobs | ?{$_.Result.IsCompleted});

        # Add to the job totals
        $AuditCompletedJobCount += $CompletedAuditJobs.Count;

        # Enumerate the completed ones
        $CompletedAuditJobs.ForEach({
           
            # Get the completed job from the pipeline
            $CompletedAuditJob = $_;
            
            # Now we need to trap here as the result may be an unwrapped ErrorRecord
            try {
                $AuditResult = $CompletedAuditJob.Pipeline.EndInvoke($CompletedAuditJob.Result);

                # Check the error stream and update the node object
                if ($CompletedJob.Pipeline.HadErrors) {
                    # Enumerate the errors
                    $CompletedJob.Pipeline.Streams.Error | %{
                        # Update the node with these
                        $NodeCollection.Where({$_.ID -eq $CompletedJob.ID}).ForEach({
                            $_.Status += "[$(Get-Date -f "dd/MM/yy HH:mm:ss")][Audit Runspace Error]: $($Error[0].Exception.Message)`r`n";
                        });
                    }
                }

                # Update the collection with the new info
                $NodeCollection.Where({$_.ID -eq $CompletedAuditJob.ID}).ForEach({
                    $_.Audited     = $AuditResult.Audited;
                    $_.Completed   = $AuditResult.Completed;
                    $_.AuditErrors += $AuditResult.AuditErrors;
                });
            }
            catch {
                # Update the collection to say the audit broke instead
                $NodeCollection.Where({$_.ID -eq $CompletedAuditJob.ID}).ForEach({
                    $_.Audited     = $True;
                    $_.AuditErrors += "[$(Get-Date -f "dd/MM/yy HH:mm:ss")][Audit Runspace Error]: $($Error[0].Exception.Message)`r`n";
                    $_.Completed   = $False;
                });
            }

           # Dispose of the pipeline
           $CompletedAuditJob.Pipeline.Dispose();
   
           # Remove job from collection
           $AuditJobs.Remove($CompletedAuditJob);
        });
     
        # Write out Network Scan progress (percent complete caught for dividebyzero)
        try   {$NetworkProbeQueuePercent = ($ProbeJobCompletedCount / $ProbeJobCount) * 100}
        catch {$NetworkProbeQueuePercent = 0}
        Write-Progress `
            -ID 1 `
            -Activity "Network Probe Queue" `
            -Status "Processed $ProbeJobCompletedCount nodes out of a possible $ProbeJobCount nodes" `
            -PercentComplete $NetworkProbeQueuePercent;

        # Write out Audit status (percent complete caught for dividebyzero)
        try   {$AuditPercent = ($AuditCompletedJobCount / $AuditScanTotalJobCount) * 100}
        catch {$AuditPercent = 0}
        Write-Progress `
            -ID 2 `
            -Activity "Audit Queue" `
            -Status "Out of $AuditScanTotalJobCount nodes to audit, $AuditCompletedJobCount have completed" `
            -PercentComplete $AuditPercent;

        # Quick sleep to avoid excessive loop burn
        Start-Sleep -Milliseconds 500;
    }
}
catch {
    Write-ShellMessage -Message "There was a problem with the runspace queues" -Type Error -ErrorRecord $Error[0];
    $JobExitCode = 1;
}
finally {
    # Make sure to dispose of the pools prior to exit
    $AuditRunspacePool.Close();
    $AuditRunspacePool.Dispose();
    $ProbeRunspacePool.Close();
    $ProbeRunspacePool.Dispose();

    # Export the node collection so we don't lose any data
    $NodeCollection | Export-CSV -Path $NodeCSVFilePath -Force -NoTypeInformation;
}

# Write out to say we're done
$EndTime = Get-Date;
$TS = New-TimeSpan $StartTime $EndTime;

# Status message
if ($JobExitCode -eq 0) {
    Write-ShellMessage -Message "Network Audit completed" -Type SUCCESS;
}
else {
    Write-ShellMessage -Message "Network Audit completed with errors" -Type WARNING;
}

Write-FinalStatus $NodeCollection $TS $ProbeJobCount;

# Fin
Exit;