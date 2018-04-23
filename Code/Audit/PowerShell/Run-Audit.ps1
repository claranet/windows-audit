[Cmdletbinding()]
Param(
    # Json encoded string of credentials
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$EncodedCredentialsPath,

    # Json encoded string of hosts
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]$EncodedHostsPath
)

# Set E|W|P prefs
$ErrorActionPreference = "Stop";
$WarningPreference = "SilentlyContinue";
$ProgressPreference = "SilentlyContinue";

# Import the utils module
try {
    Import-Module "$PSScriptRoot\Utility.psm1" -Force -DisableNameChecking;
} catch {
    [Console]::Error.WriteLine("Error importing utility module: $($_.Exception.Message)");
    Exit(1);
}

# Unroll the credentials
try {
    $Credentials = Unroll-EncodedJson -Path $EncodedCredentialsPath;
} catch {
    [Console]::Error.WriteLine("Error decoding credentials: $($_.Exception.Message)");
    Exit(1);
}

# Unroll the hosts
try {
    $Hosts = Unroll-EncodedJson -Path $EncodedHostsPath;
} catch {
    [Console]::Error.WriteLine("Error decoding hosts: $($_.Exception.Message)");
    Exit(1);
}

# Bring in the audit/probe scripts
try {
    # Network probe
    $ProbeScriptPath = (Resolve-Path "$PSScriptRoot\Probe-Machine.ps1").Path;
    $ProbeScriptContent = Get-Content $ProbeScriptPath -Raw;
    $ProbeScriptBlock = [ScriptBlock]::Create($ProbeScriptContent);

    # Audit scan
    $AuditScriptPath = (Resolve-Path "$PSScriptRoot\Audit-Machine.ps1").Path;
    $AuditScriptContent = Get-Content $AuditScriptPath -Raw;
    $AuditScriptBlock = [ScriptBlock]::Create($AuditScriptContent);
}
catch {
    [Console]::Error.WriteLine("Error importing audit/probe scripting: $($_.Exception.Message)");
    Exit(1);
}

# Create the runspace pools and queues
try {
    # Network probe
    $ProbeRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, 64, $Host);
    $ProbeRunspacePool.Open();
    [System.Collections.ArrayList]$Probes = @();

    # Audit
    $AuditRunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThreadCount, $Host);
    $AuditRunspacePool.Open();
    [System.Collections.ArrayList]$Audits = @();
}
catch {
    [Console]::Error.WriteLine("Error creating runspace pools/job queues: $($_.Exception.Message)");
    Exit(1);
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
        };
                
        # Create new probe
        $Probe = [System.Management.Automation.PowerShell]::Create().AddScript($ProbeScriptBlock).AddParameters($ProbeParams);
        $Probe.RunspacePool = $ProbeRunspacePool;

        # Write a status update before we light up the job
        Write-HostUpdate -ID $HostRef.ID -Status 1;

        # Add it to the job queue and spark it up
        [Void]($ProbeJobs.Add($([PSCustomObject]@{
            ID       = $Hostref.ID;
            Pipeline = $Probe;
            Result   = $Probe.BeginInvoke();
        })));
    });
}
catch {
    [Console]::Error.WriteLine("Error adding probes to runspace queue: $($_.Exception.Message)");
    Exit(1);
}
finally {
    # Close out the runspace pools and dispose if we have an issue
    $AuditRunspacePool.Close();
    $AuditRunspacePool.Dispose();
    $ProbeRunspacePool.Close();
    $ProbeRunspacePool.Dispose();
}

# Start streaming the results from the runspace pool following up as required
try{   
    # Init a counter value object so we can easily write to stdout
    $Counter = $([PSCustomObject]@{
        ProbeTimeSpans    = $(New-Object System.Collections.Arraylist);
        AuditTimeSpans    = $(New-Object System.Collections.Arraylist);
        ProbeQueueCount   = $Probes.Count;
        ProbeSuccessCount = 0;
        ProbeFailedCount  = 0;
        AuditQueueCount   = 0;
        AuditSuccessCount = 0;
        AuditFailedCount  = 0;
    });

    # Loop processing until we're done
    While ($Probes.Count -gt 0 -or $Audits.Count -gt 0) {
        
        # Get a list of completed probes
        $CompletedProbes = @($Probes | ?{$_.Result.IsCompleted});

        # Enumerate the completed probes
        $CompletedProbes.ForEach({

            # Grab the completed probe from the pipeline and create some stdout properties
            $CompletedProbe = $_;
            $ProbeID        = $CompletedProbe.ID;
            $ProbeErrors    = New-Object System.Collections.ArrayList;

            # Need to trap here in case we get an unwrapped ErrorRecord
            try {
                # Grab the result
                $Result = $CompletedProbe.Pipeline.EndInvoke($CompletedProbe.Result);

                # Check the error stream for this job
                if ($CompletedProbe.Pipeline.HadErrors) {
                    # Ok first lets increment the probe failed counters
                    $Counter.ProbeFailedCount++;
                    $Counter.AuditQueueCount++;
                    $Counter.AuditFailedCount++;
                    
                    # Enumerate the errors and push to our collection
                    $CompletedProbe.Pipeline.Streams.Error | %{
                        [Void]($ProbeErrors.Add($_.Exception.Message));
                    }
                    # Post the host update
                    Write-HostUpdate -ID $ProbeID -Status 101 -Errors $ProbeErrors;
                } else {
                    # Ok everything went well, create audit params
                    $AuditParams = @{
                        Target      = $Result;
                        Credentials = $Credentials;
                    };
                            
                    # Create new audit
                    $Audit = [System.Management.Automation.PowerShell]::Create().AddScript($AuditScriptBlock).AddParameters($AuditParams);
                    $Audit.RunspacePool = $AuditRunspacePool;

                    # Write a status update before we light up the job
                    Write-HostUpdate -ID $ProbeID -Status 2;

                    # Add it to the job queue and spark it up
                    [Void]($AuditJobs.Add($([PSCustomObject]@{
                        ID       = $ProbeID;
                        Pipeline = $Audit;
                        Result   = $Audit.BeginInvoke();
                    })));

                    # Increment the counters
                    $Counter.ProbeSuccessCount++;
                    $Counter.AuditQueueCount++;

                    # And finally add our time taken to the probe averages
                    $Counter.ProbeTimeSpans += $Result.Probe.TimeTaken;
                }
            } catch {
                # Ok first lets increment the probe failed counters
                $Counter.ProbeFailedCount++;
                $Counter.AuditQueueCount++;
                $Counter.AuditFailedCount++;

                # We had an unwrapped error here, push it to the array
                [Void]($ProbeErrors.Add($_.Exception.Message));

                # And write the host status update
                Write-HostUpdate -ID $ProbeID -Status 101 -Errors $ProbeErrors;
            }

            # And remove the probe from the queue
            [Void]($Probes.Remove($CompletedProbe));
        });

        # Get a list of completed audits
        $CompletedAudits = @($Audits | ?{$_.Result.IsCompleted});

        # And enumerate the completed audits
        $CompletedAudits.ForEach({

            # Grab the completed audit from the pipeline and create some stdout properties
            $CompletedAudit = $_;
            $AuditID        = $CompletedAudit.ID;
            $AuditErrors    = New-Object System.Collections.ArrayList;

            # Need to trap here in case we get an unwrapped ErrorRecord
            try {
                # Grab the result
                $Result = $CompletedAudit.Pipeline.EndInvoke($CompletedAudit.Result);

                # Check the error stream for this job
                if ($CompletedAudit.Pipeline.HadErrors) {
                    # Ok first lets increment the audit failed counter
                    $Counter.AuditFailedCount++;
                    
                    # Enumerate the errors and push to our collection
                    $CompletedAudit.Pipeline.Streams.Error | %{
                        [Void]($AuditErrors.Add($_.Exception.Message));
                    }
                    # Post the host update
                    Write-HostUpdate -ID $AuditID -Status 201 -Errors $AuditErrors;
                } else {
                    # Ok everything went well, write out our host update
                    Write-HostUpdate -ID $AuditID -Status 3;

                    # And increment the audit success counter
                    $Counter.AuditSuccessCount++;

                    # And finally add our time taken to the audit averages
                    $Counter.AuditTimeSpans += $Result.Audit.TimeTaken;
                }
                
            } catch {
                # Ok first lets increment the audit failed counter
                $Counter.AuditFailedCount++;

                # We had an unwrapped error here, push it to the array
                [Void]($AuditErrors.Add($_.Exception.Message));

                # And write the host status update
                Write-HostUpdate -ID $AuditID -Status 201 -Errors $AuditErrors;
            }

            # And remove the audit from the queue
            [Void]($Audits.Remove($CompletedAudit));
        });

        # And write our global status update
        Write-StatusUpdate -Counter $Counter;
    }
    
} catch {
    [Console]::Error.WriteLine("Error streaming runspace queues: $($_.Exception.Message)");
    Exit(1);
}
finally {
    # Close out the runspace pools and dispose if we have an issue
    $AuditRunspacePool.Close();
    $AuditRunspacePool.Dispose();
    $ProbeRunspacePool.Close();
    $ProbeRunspacePool.Dispose();
}

# Fin
Exit(0);