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

# If we get as far as an audit we can forgive previous probe sins
$Target = $Target | Select -Property * -ExcludeProperty Errors;
$Target | Add-Member -MemberType NoteProperty -Name Errors -Value @();

# Import the utils module
try {
    Import-Module "$RootDirectory\PowerShell\Utility.psm1" -Force -DisableNameChecking;
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Init Error] Importing utility module failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
    return $Target;
}

# Add an audit object to our target
try {
    $Target | Add-Member -MemberType NoteProperty -Name Audit -Value $(New-Audit);
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Init Error] Adding new Audit object failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
    return $Target;
}

# Switch based on our target connection method
if ($Target.Probe.RemoteConnectivity.Wmi.Successful) {
    $ScriptType = "WMI";
    $Extension  = "*.ps1";
} elseif ($Target.Probe.RemoteConnectivity.Ssh.Successful) {
    $ScriptType = "SSH";
    $Extension  = "*.sh";
} else {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Init Error] No remote protocols are available for this target.";
    $Target.Errors += $E;
    return $Target;
}

# Get all our scripts for auditing
try {
    $ScriptDirectory = "$RootDirectory\PowerShell\Collectors\$ScriptType";
    $AuditSections = @($(Get-ChildItem $ScriptDirectory -Recurse $Extension | %{
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
} catch {
    $E = "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Init Error] Building Audit script cache failed with exception: $($_.Exception.Message)";
    $Target.Errors += $E;
    return $Target;
}

# Loop until we have completed successfully or exhaust retries
while ($AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).Count -gt 0) {

    # Stream the remaining audit sections to the pipeline
    $AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).ForEach({

        # Get the current section
        $CurrentSection = $_;

        # Increment the counter for this section
        $CurrentSection.RetryCount++;

        # Trap up so we don't blow the runspace
        try {
            # Ok we need to switch here on our connection method and act accordingly
            Switch ($ScriptType) {
                "WMI" {

                    # Get the credential we learned from the probe
                    $C = $Credentials | ?{$_.ID -eq $Target.Probe.Credentials.Successful};
                    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
                    $Username = "{0}\{1}" -f $C.Domain,$C.Username;
                    $PSCredential = New-Object System.Management.Automation.PSCredential($Username,$SecurePassword);
                    
                    # Try and get the current data
                    $WmiData = Invoke-Wmi `
                                    -Target $Target.Endpoint `
                                    -Credential $PSCredential `
                                    -ScriptPath $CurrentSection.Script `
                                    -MachineIdentifier $Target.ID;

                    # Check and see if we've been returned a hashtable by older Windows versions
                    if ($WmiData -is [Hashtable]) {
                        # Get a holding array sorted
                        $HoldingArray = @();

                        # Enumerate the current data and spin out PSCustomObjects for each one
                        $WmiData.GetEnumerator() | %{
                            $HoldingArray += $(New-Object PSCustomObject -Property $_);
                        }

                        # Explicitly splat the original variable with the new one to avoid data type confusion
                        $WmiData = $Null;
                        $WmiData = $HoldingArray;
                    }

                    # Add our data to the audit section
                    $CurrentSection.Data = $WmiData;

                    # Set the current section to completed
                    $CurrentSection.Completed = $True;
                }
                "SSH" {
                    # Get the credential we learned from the probe
                    $C = $Credentials | ?{$_.ID -eq $Target.Probe.Credentials.Successful};

                    # Now we need to work out what sort of credential this is and exec accordingly
                    $SshData = $(Switch ($C.Type)
                    {
                        "Linux/Unix Credentials" {
                            Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -Password $C.Password `
                                -ScriptPath $CurrentSection.Script `
                                -MachineIdentifier $Target.ID;
                        }
                        "Linux/Unix Private Key file" {
                            Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -PrivateKeyFilePath $C.PrivateKeyFilePath `
                                -ScriptPath $CurrentSection.Script `
                                -MachineIdentifier $Target.ID;
                        }
                        "Linux/Unix Private Key file with Passphrase" {
                            Invoke-Ssh `
                                -Target $Target.Endpoint `
                                -Username $C.Username `
                                -PrivateKeyFilePath $C.PrivateKeyFilePath `
                                -PrivateKeyPassphrase $C.PrivateKeyPassphrase `
                                -ScriptPath $CurrentSection.Script `
                                -MachineIdentifier $Target.ID;
                        }
                    });

                    # Add our data to the audit section
                    $CurrentSection.Data = $SshData | ConvertFrom-Json -ErrorAction SilentlyContinue;

                    # Set the current section to completed
                    $CurrentSection.Completed = $True;
                }
            }
        } catch {
            # Ok grab the exception from the pipeline
            $E = $_.Exception.Message;

            # Build our error string
            $u_E = "[{0}] [Audit Script Error] Attempt '{1}' of Audit script '{2}' failed with exception: {3}";
            $f_E = $u_E -f $(Get-Date -f "dd/MM/yy-HH:mm:ss"),$CurrentSection.RetryCount,$CurrentSection.Name,$E;
            
            # And add it to the current section
            $CurrentSection.Errors += $f_E;
        }
    });
}

# Add our audit data section to the target object
$Target.Audit.Sections = $AuditSections;

# Ok now we need to make sure the target audit errors are propagated
$AuditSections.Where({$_.Errors}).ForEach({
    @($_.Errors).ForEach({
        $Target.Errors += $_;
    });
});

# Tot up the time taken and add to our output
$EndTime = Get-Date;
$Target.Audit.Info.TimeTaken = $(New-TimeSpan $StartTime $EndTime);

# Set our completed bool and return the updated target object
$Target.Audit.Info.Completed = $True;
return $Target;