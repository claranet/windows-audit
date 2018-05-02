[Cmdletbinding()]
Param(
    # Json encoded string of credentials
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$EncodedCredentialsPath,

    # Json encoded string of hosts
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$EncodedHostsPath,

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

# Main() Trapped so we can gracefully exit
try {     
    # Import the utils module
    try {
        Import-Module "$RootDirectory\PowerShell\Utility.psm1" -Force -DisableNameChecking;
    } catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Importing utility module failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        Exit(2);
    }

    # Unroll the credentials
    try {
        $Credentials = Unroll-EncodedJson -Path $EncodedCredentialsPath;
    } catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Decoding credentials failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # Unroll the hosts
    try {
        $Hosts = Unroll-EncodedJson -Path $EncodedHostsPath;
    } catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Decoding hosts failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # Bring in the audit/probe scripts
    try {
        # Network probe
        $ProbeScriptPath = (Resolve-Path "$RootDirectory\PowerShell\Probe-Machine.ps1").Path;
        $ProbeScriptContent = Get-Content $ProbeScriptPath -Raw;
        $ProbeScriptBlock = [ScriptBlock]::Create($ProbeScriptContent);

        # Audit scan
        $AuditScriptPath = (Resolve-Path "$RootDirectory\PowerShell\Audit-Machine.ps1").Path;
        $AuditScriptContent = Get-Content $AuditScriptPath -Raw;
        $AuditScriptBlock = [ScriptBlock]::Create($AuditScriptContent);
    }
    catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Building script cache failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # Create the runspace pools and queues
    try {
        # Network probe
        $ProbeRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 16, $Host);
        $ProbeRunspacePool.Open();
        [System.Collections.ArrayList]$Probes = @();

        # Audit
        $AuditRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 16, $Host);
        $AuditRunspacePool.Open();
        [System.Collections.ArrayList]$Audits = @();
    }
    catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Creating RunSpace pools and Job Queues failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # Add all the network probe jobs to the runspace pool
    try {
        @($Hosts).ForEach({

            # Grab the host from the pipeline
            $Hostref = $_;

            # Create hashtable to pass parameters to the probe job
            $ProbeParams = @{
                Target      = $HostRef;
                Credentials = $Credentials;
                RootDirectory = $RootDirectory;
            };
                    
            # Create new probe
            $Probe = [System.Management.Automation.PowerShell]::Create().AddScript($ProbeScriptBlock).AddParameters($ProbeParams);
            $Probe.RunspacePool = $ProbeRunspacePool;

            # Write a status update before we light up the job
            Write-HostUpdate -ID $HostRef.ID -Status 1;

            # Add it to the job queue and spark it up
            [Void]($Probes.Add($([PSCustomObject]@{
                ID       = $Hostref.ID;
                Pipeline = $Probe;
                Result   = $Probe.BeginInvoke();
            })));
        });
    }
    catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Init Error] Adding Probes to RunSpace queue failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # Start streaming the results from the runspace pool following up as required
    try{   
        # Init a counter value object so we can easily write to stdout
        $Counter = $([PSCustomObject]@{
            ProbeTimeSpans    = @();
            AuditTimeSpans    = @();
            ProbeQueueCount   = $Probes.Count;
            ProbeSuccessCount = 0;
            ProbeFailedCount  = 0;
            AuditQueueCount   = 0;
            AuditSuccessCount = 0;
            AuditFailedCount  = 0;
        });

        # Loop processing until we're done
        While ($Probes.Count -gt 0 -or $Audits.Count -gt 0) {
            
            # Grab the completed probes and enumerate them
            $CompletedProbes = @($Probes | ?{$_.Result.IsCompleted});
            $CompletedProbes.ForEach({

                # Grab the completed probe and result from the pipeline
                $CompletedProbe = $_;
                $Result = $CompletedProbe.Pipeline.EndInvoke($CompletedProbe.Result);

                # Add our time taken to the probe averages
                if ($Result.Probe.Info.TimeTaken) {
                    $Counter.ProbeTimeSpans += $Result.Probe.Info.TimeTaken;
                }

                # Check and see whether remote access is available
                if ($Result.Probe.RemoteConnectivity.OK) {

                    # Ok we have access, create audit params
                    $AuditParams = @{
                        Target        = $Result;
                        Credentials   = $Credentials;
                        RootDirectory = $RootDirectory;
                    };

                    # Create new audit
                    $Audit = [System.Management.Automation.PowerShell]::Create().AddScript($AuditScriptBlock).AddParameters($AuditParams);
                    $Audit.RunspacePool = $AuditRunspacePool;

                    # Write a status update before we light up the job
                    Write-HostUpdate -ID $CompletedProbe.ID -Status 2 -Errors $Result.Errors;

                    # Add it to the audit queue and spark it up
                    [Void]($Audits.Add($([PSCustomObject]@{
                        ID       = $ProbeID;
                        Pipeline = $Audit;
                        Result   = $Audit.BeginInvoke();
                    })));

                    # Increment the counters
                    $Counter.ProbeSuccessCount++;
                    $Counter.AuditQueueCount++;

                } else {

                    # Ok first lets increment the probe failed counters
                    $Counter.ProbeFailedCount++;
                    $Counter.AuditQueueCount++;
                    $Counter.AuditFailedCount++;

                    # Post the host update
                    Write-HostUpdate -ID $CompletedProbe.ID -Status 101 -Errors $Result.Errors;
                }

                # And remove the probe from the queue
                [Void]($Probes.Remove($CompletedProbe));
            });

            # Grab the completed audits and enumerate them
            $CompletedAudits = @($Audits | ?{$_.Result.IsCompleted});
            $CompletedAudits.ForEach({

                # Grab the completed audit and result from the pipeline
                $CompletedAudit = $_;
                $Result = $CompletedAudit.Pipeline.EndInvoke($CompletedAudit.Result);

                # Add our time taken to the audit averages
                if ($Result.Audit.Info.TimeTaken) {
                    $Counter.AuditTimeSpans += $Result.Audit.Info.TimeTaken;
                }

                # Check and see whether we got to the end of the run
                if ($Result.Audit.Info.Completed) {
                    
                    # Check if we had errors
                    if ($Result.Errors) {
                        # We completed with issues
                        $Status = 202;
                        $Counter.AuditFailedCount++;
                    } else {
                        # Everything went well
                        $Status = 3;
                        $Counter.AuditSuccessCount++;
                    }

                    # Write our status update
                    Write-HostUpdate -ID $Result.ID -Status 3 -Errors $Result.Errors;

                    # Export our file so we can track what we have so far
                    $ExportPath = "{0}\Results\{1}.xml" -f $RootDirectory,$Result.ID;
                    $Result | Export-Clixml -Path $ExportPath -Force;

                } else {
                    # We didn't manage to finish the run, increment the audit failed counter
                    $Counter.AuditFailedCount++;

                    # And write the host status update
                    Write-HostUpdate -ID $Result.ID -Status 201 -Errors $Result.Errors;
                }

                # And remove the audit from the queue
                [Void]($Audits.Remove($CompletedAudit));
            });

            # And write our global status update
            Write-StatusUpdate -Counter $Counter;

            # Dynamic throttle to prevent loop burn
            if ($CompletedProbes.Count -gt 0 -or $CompletedAudits.Count -gt 0) {
                Start-Sleep -Milliseconds 50;
            } else {
                Start-Sleep -Seconds 2;
            }

        }
        
    } catch {
        $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Service Error] Streaming RunSpace queue failed with exception: $($_.Exception.Message)";
        [Console]::Error.WriteLine($E);
        [Environment]::Exit(2);
    }

    # And we're done
    [Environment]::Exit(1);
}
finally {
    # Check if we have still have runspace resources and dispose of them
    if ($ProbeRunspacePool) {
        $ProbeRunspacePool.Close();
        $ProbeRunspacePool.Dispose();
    }

    if ($AuditRunspacePool) {
        $AuditRunspacePool.Close();
        $AuditRunspacePool.Dispose();
    }
}