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
    throw "[$(Get-Date -f "dd/MM/yy-HH:mm:ss")] [Audit Error] Error importing utility module: $($_.Exception.Message)";
}

# Add an audit object to our target, padded out with an errors and time taken properties
$Target | Add-Member -MemberType NoteProperty -Name Audit -Value $([PSCustomObject]@{
    Errors = $(New-Object System.Collections.ArrayList);
    TimeTaken = $Null
});

# Switch based on our target connection method
if ($Target.Probe.WinRmSuccess) {
    $ScriptType = "WinRM";
    $Extension  = "*.ps1";
} elseif ($Target.Probe.WmiSuccess) {
    $ScriptType = "WMI";
    $Extension  = "*.ps1";
} elseif ($Target.Probe.SshSuccess) {
    $ScriptType = "SSH";
    $Extension  = "*.sh";
} else {
    # Terminating error as we can't connect
    throw "No remote protocols are available for this target.";
}

# Get all our scripts for auditing
$ScriptDirectory = "$PSScriptRoot\Collectors\$ScriptType";
$AuditSections = @($(Get-ChildItem $ScriptDirectory -Recurse $Extension | %{
    # Exclude the connection check script
    if (!$_.Name.Contains("_ConnectionCheck")) {
        [PSCustomObject]@{
            SectionName  = $_.BaseName;
            ScriptPath   = $_.FullName;
            Completed    = $False;
            RetryCount   = 0;
            Errors       = $(New-Object System.Collections.ArrayList);
        }
    }
}));

# Loop until we have completed successfully or exhaust retries
while ($AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).Count -gt 0) {

    # Stream the remaining audit sections to the pipeline
    $AuditSections.Where({$_.RetryCount -le 3 -and $_.Completed -eq $False}).ForEach({

        # Get the current section
        $CurrentSection = $_;

        # Increment the counter for this section
        $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName}).RetryCount++;

        # No. Unhandled. Exceptions.
        try {
            # Ok we need to switch here on our connection method and act accordingly
            Switch ($ScriptType) {
                "WinRM" {

                    # Get the credential we learned from the probe
                    $C = $Credentials | ?{$_.ID -eq $Target.Probe.WinRmCredentialsSuccessful};
                    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
                    $Username = "{0}\{1}" -f $C.Domain,$C.Username;
                    $PSCredential = New-Object System.Management.Automation.PSCredential($Username,$SecurePassword);
                    
                    # Build the WinRM params
                    $WinRmParams = @{
                        Target            = $Target.Endpoint;
                        Credential        = $PSCredential;
                        ScriptPath        = $CurrentSection.ScriptPath;
                        MachineIdentifier = $Target.ID;
                        UseSsl            = $Target.Probe.WinRmUseTls;
                    }

                    # Try and get the current data
                    $CurrentData = $(. "$PSScriptRoot\Invoke-WinRm.ps1" @WinRmParams);

                    # Null check so we dont bomb out with Get-Member
                    if ($CurrentData) {
                        # Ok we want to check and see whether we got a dodgy hashtable back
                        if (($CurrentData | Gm | Select -ExpandProperty TypeName -First 1).Contains("Hashtable")) {
                            # Get a holding array sorted
                            [System.Collections.ArrayList]$HoldingArray = @();

                            # Enumerate the current data and spin out PSCustomObjects for each one
                            $CurrentData.GetEnumerator() | %{
                                [Void]($HoldingArray.Add($(New-Object PSCustomObject -Property $_)));
                            }

                            # Explicitly splat the original variable with the new one to avoid data type confusion
                            $CurrentData = $Null;
                            $CurrentData = $HoldingArray;
                        }
                    } else {
                        # Throw here as sometimes WinRM returns $Null if the target is broken
                        throw "Null result returned.";
                    }

                    # Add the result to the audit object
                    $Target.Audit | Add-Member -MemberType NoteProperty -Name $CurrentSection.SectionName -Value $CurrentData;

                    # Set the current section to completed
                    $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName}).Completed = $True;
                }
                "WMI" {

                    # Get the credential we learned from the probe
                    $C = $Credentials | ?{$_.ID -eq $Target.Probe.WmiCredentialsSuccessful};
                    $SecurePassword = $C.Password | ConvertTo-SecureString -AsPlainText -Force;
                    $Username = "{0}\{1}" -f $C.Domain,$C.Username;
                    $PSCredential = New-Object System.Management.Automation.PSCredential($Username,$SecurePassword);
                    
                    # Build the WMI params
                    $WmiParams = @{
                        Target            = $Target.Endpoint;
                        Credential        = $PSCredential;
                        ScriptPath        = $CurrentSection.ScriptPath;
                        MachineIdentifier = $Target.ID;
                    }

                    # Try and get the current data
                    $CurrentData = $(. "$PSScriptRoot\Invoke-Wmi.ps1" @WmiParams);

                    # Null check so we dont bomb out with Get-Member
                    if ($CurrentData) {
                        # Ok we want to check and see whether we got a dodgy hashtable back
                        if (($CurrentData | Gm | Select -ExpandProperty TypeName -First 1).Contains("Hashtable")) {
                            # Get a holding array sorted
                            [System.Collections.ArrayList]$HoldingArray = @();

                            # Enumerate the current data and spin out PSCustomObjects for each one
                            $CurrentData.GetEnumerator() | %{
                                [Void]($HoldingArray.Add($(New-Object PSCustomObject -Property $_)));
                            }

                            # Explicitly splat the original variable with the new one to avoid data type confusion
                            $CurrentData = $Null;
                            $CurrentData = $HoldingArray;
                        }
                    } else {
                        # Throw here if we have a null result
                        throw "Null result returned.";
                    }

                    # Add the result to the audit object
                    $Target.Audit | Add-Member -MemberType NoteProperty -Name $CurrentSection.SectionName -Value $CurrentData;

                    # Set the current section to completed
                    $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName}).Completed = $True;
                }
                "SSH" {
                    # Get the credential we learned from the probe
                    $C = $Credentials | ?{$_.ID -eq $Target.Probe.SshCredentialsSuccessful};

                    # Splat up the basic ssh params
                    $SshParams = @{
                        Target            = $Target.Endpoint;
                        Username          = $C.Username;
                        ScriptPath        = $CurrentSection.ScriptPath;
                        MachineIdentifier = $Target.ID;
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

                    # Try and get the current data
                    $CurrentData = $(. "$PSScriptRoot\Invoke-Ssh.ps1" @SshParams);

                    # Null check so we can throw if required
                    if ($CurrentData) {
                        # Ok, the result _should_ be plain Json so we'll try a cast here
                        try {
                            # Try the cast
                            $HoldingObject = $CurrentData | ConvertFrom-Json;

                            # Ok if we get this far we're good, splat the current data object and reassign
                            $CurrentData = $Null;
                            $CurrentData = $HoldingObject;

                        } catch {
                            throw "Error converting data from Json to Object: $($_.Exception.Message)";
                        }
                        
                    } else {
                        # Throw here if we have a null result
                        throw "Null result returned.";
                    }

                    # Add the result to the audit object
                    $Target.Audit | Add-Member -MemberType NoteProperty -Name $CurrentSection.SectionName -Value $CurrentData;

                    # Set the current section to completed
                    $AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName}).Completed = $True;
                }
            }
        } catch {
            # Ok grab the exception from the pipeline
            $E = $_.Exception.Message;

            # Build our client facing error
            $u_ErrorMessage = "[{0}] [Audit Error] There was an exception processing audit section '{1}' with connection method '{2}: {3}";
            $f_ErrorMessage = $u_ErrorMessage -f $(Get-Date -f "dd/MM/yy-HH:mm:ss"),$CurrentSection.SectionName,$ScriptType,$E;

            # Add the exception to the auditsections object so we can track multiple different failures
            [Void]($AuditSections.Where({$_.SectionName -eq $CurrentSection.SectionName}).Errors.Add($f_ErrorMessage))
        }
    });
}

# Ok now we need to make sure the target audit errors are captures
$AuditSections.Where({$_.Errors}).ForEach({
    $_.Errors.CopyTo($Target.Audit.Errors);
});

# Tot up the time taken and add to our output
$EndTime = Get-Date;
$Result.Audit.TimeTaken = $(New-TimeSpan $StartTime $EndTime);

# And return the updated target object
return $Target;