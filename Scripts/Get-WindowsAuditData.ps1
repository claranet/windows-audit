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

    .TODO# Need to add error handling and output logging

    #requires -version 2
#>

[CmdletBinding()]
Param(
    # Path to a PSV file containing the list of computers|protocols to connect to
    [Parameter(Mandatory=$False)]
    [ValidateScript({$(Test-Path $_)})]
    [String]$InputFile,

    # String[] of computers to execute this script on
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]$Computers,

    # Protocol to use for connecting to the target machine
    [Parameter(Mandatory=$False)]
    [ValidateSet("WinRM","PSExec")]
    [String]$Protocol = "WinRM",

    # PSCredential that will be used for WinRM to connect to the target machines
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential,

    # Override for the ExportDepth to CLI XML
    [Parameter(Mandatory=$False)]
    [ValidateRange(2,8)]
    [Int]$SerialisationDepth = 5
)

#---------[ Global Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Import our functions from the lib module
Import-Module ".\Lib\Audit-Functions.psm1" -DisableNameChecking;

# Output object for holding data to write to disk
$Output = @();

# Scriptblock to execute imported from file
$ScriptBlockPath = ".\Lib\Audit-Scriptblock.ps1";
[ScriptBlock]$ScriptBlock = [ScriptBlock]::Create($(Get-Content $ScriptBlockPath | Out-String));

# Check if we recieved a PSV file with the computers
if ($InputFile) {

    # Get an object to hold the data we want
    $Computers = @();

    # Ok so let's parse the file
    $InputFile | %{
        
        # Get the pipe object
        $Line = $_;

        # Check if the line is pipe separated
        if ($Line.Contains("|")) {
            $Computers += [PSCustomObject]@{
                Computer = $Line.Split("|")[0];
                Protocol     = $Line.Split("|")[1];
            }
        }
        else {
            $Computers += [PSCustomObject]@{
                Computer = $Line;
                Protocol     = "WinRM";
            }
        }
    }
}

# Loop to execute on targeted computers
ForEach ($Computer in $Computers) {
    
    # Ok first we need to check whether we have an InputFile
    if ($InputFile) {
        # Get what we need from the PSCustomObject
        $Hostname = $_.Computer.Split(":")[0];
        $Port     = $_.Computer.Split(":")[1];
        $Protocol = $_.Protocol;
    }
    else {
        # Get what we need from the param input instead
        $Hostname = $Computer.Split(":")[0];
        $Port     = $Computer.Split(":")[1];
    }

    # Next we'll check the protocol and see how we're connecting
    if ($Protocol -eq "PSExec") {
        # Ok let's call PSExec
        $HostInformation = Invoke-PSExecCommand -ComputerName $Hostname -Script $ScriptBlockPath -SerialisationDepth $SerialisationDepth; 
    }
    elseif ($Port) {
        # Ok we're hitting a non standard port over WinRM, check if we're using a PSCredential and hit it
        if ($PSCredential) {
            # Execute the command supplying the credential
            $HostInformation = Invoke-Command -ComputerName $Hostname -Port $Port -ScriptBlock $ScriptBlock -Credential $PSCredential;
        }
        else {
            # Execute the command using the default credential
            $HostInformation = Invoke-Command -ComputerName $Hostname -Port $Port -ScriptBlock $ScriptBlock;
        }
    }
    else {
        # Ok we know that we're using WinRM over standard port, check if using PSCredential and hit it
        if ($PSCredential) {
            # Execute the command supplying the credential 
            $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock -Credential $PSCredential;
        }
        else {
            # Execute the command using the default credential
            $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock;
        }
    }

    # And add to the output
    $Output += $HostInformation;
}

# Check if our RawData folder exists
$RawDataFolder = ".\Output\RawData";
if (!(Test-Path $RawDataFolder)) {
    [Void](New-Item $RawDataFolder -ItemType Directory -Force);
}

# Write XML to disk
$Output | %{
    # Get the pipe object
    $HostInformation = $_;

    # Get our filename
    $OutputFileName = "$RawDataFolder\$($HostInformation.OS.CSName).cli.xml";

    # Write to disk
    Export-Clixml -InputObject $HostInformation -Path $OutputFileName -Depth $SerialisationDepth;
}