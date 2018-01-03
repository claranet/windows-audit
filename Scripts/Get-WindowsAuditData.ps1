#requires -version 2
<#
    .SYNOPSIS
    Name: Get-WindowsAuditData.ps1
    Gathers information about a Windows Server instance
    
    .DESCRIPTION
    This script will gather a variety of information from a Windows Server instance,
    returning it in a format that can be manipulated to produce an output report
    indicating the machine's current Application/Hardware/Configuration status.
    
    .EXAMPLE
    This script is not designed for standalone usage, please see the Invoke-WindowsAudit.ps1
    file in the root of this solution.
#>

[CmdletBinding()]
Param(
    # Path to a file containing the computer list to execute this script on
    [Parameter(Mandatory=$False)]
    [String]$InputFile,

    # Alternate input source, String[] of computers to execute this script on
    [Parameter(Mandatory=$False)]
    [String[]]$Computers,

    # PSCredential that will be used to connect to the target machines
    [Parameter(Mandatory=$True)]
    [PSCredential]$PSCredential
)

#---------[ Global Declarations ]---------

# Get the execution policy value and set to unrestructed
$ExecutionPolicy = Get-ExecutionPolicy;
Set-ExecutionPolicy Unrestricted -Force;

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Trigger so we know something went wrong during the process
$WarningTrigger = $False;

#---------[ Imports ]---------

# Import our functions from the lib module
try {
    Import-Module ".\Scripts\Audit-Functions.psm1" -DisableNameChecking -Force;
}
catch {
    # Can't use Write-ShellMessage here as the module didn't import
    $Msg = "There was a problem importing the functions library: $($_.Exception.Message)";
    Write-Host "[$(Get-Date -f "dd/MM/yy HH:mm:ss")] [ERROR]: $Msg"
    Exit(1);
}

# Scriptblock to execute imported from file
try {
    Write-ShellMessage -Message "Importing audit script" -Type INFO;
    $ScriptBlockPath = ".\Scripts\Audit-Scriptblock.ps1";
    [ScriptBlock]$ScriptBlock = [ScriptBlock]::Create($(Get-Content $ScriptBlockPath | Out-String));
}
catch {
    Write-ShellMessage -Message "There was a problem importing the audit script" -Type ERROR -ErrorRecord $_;
    Exit(1);
}

#---------[ Create the output folder ]---------

# Check if our RawData folder exists
$RawDataFolder = ".\Output\RawData";
if (!(Test-Path $RawDataFolder)) {
    try {
        Write-ShellMessage -Message "XML output folder '$RawDatafolder' does not exist, creating" -Type DEBUG;
        [Void](New-Item $RawDataFolder -ItemType Directory -Force);
    }
    catch {
        Write-ShellMessage -Message "XML output folder could not be created" -Type ERROR -ErrorRecord $_;
        Exit(1);
    }
}

#---------[ Main() ]---------

# Let's work out whether we got a file or string[] as input
if ($InputFile) {
    # Import the content excluding blank entries
    $ComputersToProcess = Get-Content $InputFile | ?{$_};
}
else {
    # Use the shell input instead
    $ComputersToProcess = $Computers;
}

# Loop to execute on targeted computers
$C = 0;
$HostCount = $ComputersToProcess.Count;
ForEach ($Computer in $ComputersToProcess) {
    try {
        # Increment our counter here and write-progress
        $C++;
        Write-Progress -Activity "Gathering audit data" -Status "Processing computer $C of $HostCount" -PercentComplete $(($C/$HostCount)*100);

        # Now we need to get the protocol to use
        $Protocol = Test-RemoteConnection -ComputerName $Computer -PSCredential $PSCredential;

        # Quick status message and execute the command using the protcol we got earlier
        Write-ShellMessage -Message "Connecting to '$Computer' using protocol '$Protocol' with PSCredential for '$($PSCredential.UserName)'" -Type INFO;
        Switch ($Protocol) {
            "WinRM" {               
                $HostInformation = Invoke-Command -ComputerName $Computer -ScriptBlock $ScriptBlock -Credential $PSCredential;
            }
            "PSExec" {
                $HostInformation = Invoke-PSExecCommand -ComputerName $Computer -Script $ScriptBlockPath -PSCredential $PSCredential;
            }
        }

        # Now we want to write to disk inside the loop
        try {
            # Get our filename
            $DNSName = $HostInformation.OS.CSName;
            $OutputFileName = "$RawDataFolder\$DNSName.cli.xml";
    
            # Write to disk
            Write-ShellMessage -Message "Writing '$OutputFileName' to disk" -Type DEBUG;
            Export-Clixml -InputObject $HostInformation -Path $OutputFileName -Force;
        }
        catch {
            # Write out and set our warning trigger
            Write-ShellMessage -Message "There was an error attempting to serialise data for '$Computer' and write it to disk" -Type ERROR -ErrorRecord $_;
            $WarningTrigger = $True;
    
            # Write to error log file
            Write-ErrorLog -HostName $Computer -EventName "WriteToDisk" -Exception $($_.Exception.Message) -Sanitise $PSCredential.GetNetworkCredential().Password;
        }

    }
    catch {
        # Write out and set our warning trigger
        Write-ShellMessage -Message "There was a problem gathering information from computer '$Computer'" -Type WARNING -ErrorRecord $_;
        $WarningTrigger = $True;

        # Write to error log file
        Write-ErrorLog -HostName $Computer -EventName "Gather" -Exception $($_.Exception.Message) -Sanitise $PSCredential.GetNetworkCredential().Password;
    }
}

# Kill our progress bar as we're done
Write-Progress -Activity "Gathering audit data" -Completed;

#---------[ Fin ]---------

if ($WarningTrigger) {
    $FinalMessage = "Audit data gathering for $HostCount computers has completed with issues";
    Write-ShellMessage -Message $FinalMessage -Type WARNING;
}
else {
    $FinalMessage = "Audit data gathering for $HostCount computers has completed successfully";
    Write-ShellMessage -Message $FinalMessage -Type SUCCESS;
}

#---------[ Set the exec policy back to what it was ]---------
Set-ExecutionPolicy $ExecutionPolicy -Force;

Exit;