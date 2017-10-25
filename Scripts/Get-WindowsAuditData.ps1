#requires -version 2
<#
    .SYNOPSIS
    Name: Get-WindowsAuditData.ps1
    Gathers information about a Windows Server instance
    
    .DESCRIPTION
    This script will gather a variety of information from a Windows Server instance,
    returning it in a format that can be manipulated to produce an output report
    indicating the machine's current Application/Hardware/Configuration status.

    .PARAMETER InputFile [String]
    The path to a Pipe Separated Values file which will be parsed for target information
    on what instances to harvest audit data from.
    Per-line format: (hostname|ip):(port)|(protocol) 

    .PARAMETER Computers [String[]]
    String array of computers to run this script on. Defaults to this computer
    if not specified. If the computer value is a [host:port] or [ip:port] combination
    the specified port will be used for WinRM.

    .PARAMETER Protocol [String: WinRM,PSExec]
    The protocol to use for the target computers specified in the $Computers parameter.
    Defaults to WinRM if not specified.

    .PARAMETER PSCredential [PSCredential]
    PSCredential that will be used for WinRM communications. Must be valid on the machines 
    you're trying to connect to.

    .PARAMETER SerialisationDepth [Int: 2..8]
    Override value for the serialisation depth to use when this script is using the 
    System.Management.Automation.PSSerializer class. Defaults to 5, and range is limited
    to 2..8 as anything less than 2 is useless, anything greater than 8 will generate a very
    large (multi-gb) file and probably crash the targeted machine. Tweak if the data you want
    is nested so low it's not being included in the output.
    
    .EXAMPLE
    .\Invoke-WindowsAudit.ps1 -InputFile "C:\path\to\myfile.psv"
    This will execute the script on the list of machines found in the supplied file using the
    current identity.

    .\Invoke-WindowsAudit.ps1 -InputFile "C:\path\to\myfile.psv" -PSCredential $MyPSCredential
    This will execute the script on the list of machines found in the supplied file using the
    supplied PSCredential. Please note the PSCredential will only be used if the protocol in use
    is WinRM.

    .\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","dev-test-02" -PSCredential $MyPSCredential
    This will execute the script on both of the named computers, using the specified
    PSCredential from the $MyPSCredential variable.

    .\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","192.168.0.10:55876","dev-test-06:443"
    This will execute the script on all three of the named computers, using the
    specified ports for WinRM on latter two and the current user's identity.
#>

[CmdletBinding()]
Param(
    # Path to a PSV file containing the list of computers|protocols to connect to
    [Parameter(Mandatory=$False)]
    [String]$InputFile,

    # String[] of computers to execute this script on
    [Parameter(Mandatory=$False)]
    [String[]]$Computers,

    # Protocol to use for connecting to the target machine
    [Parameter(Mandatory=$False)]
    [String]$Protocol = "WinRM",

    # PSCredential that will be used for WinRM to connect to the target machines
    [Parameter(Mandatory=$False)]
    [PSCredential]$PSCredential,

    # Override for the ExportDepth to CLI XML
    [Parameter(Mandatory=$False)]
    [Int]$SerialisationDepth = 5
)

#---------[ Global Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Trigger so we know something went wrong during the process
$WarningTrigger = $False;

# Output object for holding data to write to disk
$Output = @();

#---------[ Imports ]---------

# Import our functions from the lib module
try {
    Import-Module ".\Scripts\Audit-Functions.psm1" -DisableNameChecking;
}
catch {
    Write-ShellMessage -Message "There was a problem importing the functions library" -Type ERROR -ErrorRecord $_;
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

#---------[ Extended Validation ]---------

# Check if we recieved a PSV file with the computers
if ($InputFile) {
    Write-ShellMessage -Message "Parsing supplied input file" -Type INFO;

    # Get an object to hold the data we want
    $Computers = @();

    # Ok so let's parse the file
    $I = 0;
    $(Get-Content $InputFile) | %{ 
        try {
        # Get the pipe object
        $Line = $_;
            Write-ShellMessage -Message "Parsing line: $Line" -Type DEBUG;

            # Check if the line is pipe separated
            if ($Line.Contains("|")) {
                # Get the props we want
                $HostName = $Line.Split("|")[0];
                $Protocol = $Line.Split("|")[1];
            }
            else {
                $HostName = $Line;
                $Protocol = $WinRM;
            }

            # Write out and add the computer object
            Write-ShellMessage -Message "Found computer '$HostName' with protocol '$Protocol'" -Type DEBUG;
            $Computers += "$HostName#$Protocol";
            $I++;
        }
        catch {
            # Write out and set our warning trigger
            Write-ShellMessage -Message "There was a problem parsing line '$Line'" -Type WARNING -ErrorRecord $_;
            $WarningTrigger = $True;
        }
    }

    # And set the host count so we can enumerate on this later
    $HostCount = $I;
}
else {
    Write-ShellMessage -Message "Parsing supplied list of computers" -Type INFO;
    $HostCount = $Computers.Count;
}

#---------[ Main() ]---------

# Loop to execute on targeted computers
$C = 0;
ForEach ($Computer in $Computers) {
    try {
        # Increment our counter here and write-progress
        $C++;
        Write-Progress -Activity "Gathering audit data" -Status "Processing computer $C of $HostCount" -PercentComplete $(($C/$HostCount)*100);

        # Ok we need to check whether we have an InputFile
        if ($InputFile) {
            # Get what we need from the inputfile vars
            $Split    = $Computer.Split("#");
            $Hostname = $Split[0].Split(":")[0];
            $Port     = $Split[0].Split(":")[1];
            $Protocol = $Split[1];
        }
        else {
            # Get what we need from the param input instead
            $Hostname = $Computer.Split(":")[0];
            $Port     = $Computer.Split(":")[1];
        }

        # Next we'll check the protocol and see how we're connecting
        if ($Protocol -eq "PSExec") {
            # Ok let's call PSExec
            Write-ShellMessage -Message "Connecting to '$HostName' using protocol '$Protocol'" -Type INFO;
            $HostInformation = Invoke-PSExecCommand -ComputerName $Hostname -Script $ScriptBlockPath -SerialisationDepth $SerialisationDepth; 
        }
        elseif ($Port) {
            # Ok we're hitting a non standard port over WinRM, check if we're using a PSCredential and hit it
            if ($PSCredential) {
                # Execute the command supplying the credential
                Write-ShellMessage -Message "Connecting to '$HostName' using protocol '$Protocol' on port '$Port' using PSCredential for '$($PSCredential.UserName)'" -Type INFO;
                $HostInformation = Invoke-Command -ComputerName $Hostname -Port $Port -ScriptBlock $ScriptBlock -Credential $PSCredential;
            }
            else {
                # Execute the command using the default credential
                Write-ShellMessage -Message "Connecting to '$HostName' using protocol '$Protocol' on port '$Port'" -Type INFO;
                $HostInformation = Invoke-Command -ComputerName $Hostname -Port $Port -ScriptBlock $ScriptBlock;
            }
        }
        else {
            # Ok we know that we're using WinRM over standard port, check if using PSCredential and hit it
            if ($PSCredential) {
                # Execute the command supplying the credential
                Write-ShellMessage -Message "Connecting to '$HostName' using protocol '$Protocol' using PSCredential for '$($PSCredential.UserName)'" -Type INFO;
                $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock -Credential $PSCredential;
            }
            else {
                # Execute the command using the default credential
                Write-ShellMessage -Message "Connecting to '$HostName' using protocol '$Protocol'" -Type INFO;
                $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock;
            }
        }

        # And add to the output
        Write-ShellMessage -Message "Adding host information for '$HostName' to the output collection" -Type DEBUG;
        $Output += $HostInformation;
    }
    catch {
        # Write out and set our warning trigger
        Write-ShellMessage -Message "There was a problem gathering information from computer '$HostName'" -Type WARNING -ErrorRecord $_;
        $WarningTrigger = $True;
    }
}

# Kill our progress bar as we're done
Write-Progress -Activity "Gathering audit data" -Completed;

# Check if our RawData folder exists
Write-ShellMessage -Message "Begining data write to disk" -Type INFO;
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

# Write XML to disk
$Output | %{
    try {
        # Get the pipe object
        $HostInformation = $_;

        # Get the hostname
        $Hostname = $HostInformation.OS.CSName;

        # Get our filename
        $OutputFileName = "$RawDataFolder\$Hostname.cli.xml";

        # Write to disk
        Write-ShellMessage -Message "Writing '$OutputFileName' to disk" -Type DEBUG;
        Export-Clixml -InputObject $HostInformation -Path $OutputFileName -Depth $SerialisationDepth -Force;
    }
    catch {
        # Write out and set our warning trigger
        Write-ShellMessage -Message "There was an error attempting to serialise data for '$Hostname' and write it to disk" -Type ERROR -ErrorRecord $_;
        $WarningTrigger = $True;
    }
}

#---------[ Fin ]---------

if ($WarningTrigger) {
    $FinalMessage = "Audit data gathering for $HostCount computers has completed with warnings";
    Write-ShellMessage -Message $FinalMessage -Type WARNING;
}
else {
    $FinalMessage = "Audit data gathering for $HostCount computers has completed successfully";
    Write-ShellMessage -Message $FinalMessage -Type SUCCESS;
}

Exit;