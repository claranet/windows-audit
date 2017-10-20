<#
    .SYNOPSIS
    Name: Invoke-WindowsAudit.ps1
    Gathers information about a Windows Server instance
    
    .DESCRIPTION
    This script will gather a variety of information from a Windows Server instance,
    returning it in a format that can be manipulated to produce an output report
    indicating the machine's current Application/Hardware/Configuration status.

    .PARAMETER Computers [String[]]
    String array of computers to run this script on. Defaults to this computer
    if not specified. If the computer value is a [host:port] or [ip:port] combination
    the specified port will be used for WinRM.

    .PARAMETER PSCredential [PSCredential]
    PSCredential that will be used for WinRM communications. Must be valid
    on the machines you're trying to connect to.
    
    .EXAMPLE
    .\Invoke-WindowsAudit.ps1
    This will execute the script on the current computer using the current user's
    identity.

    .\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","dev-test-02" -PSCredential $MyPSCredential
    This will execute the script on both of the named computers, using the specified
    PSCredential from the $MyPSCredential variable.

    .\Invoke-WindowsAudit.ps1 -Computers "dev-test-01","192.168.0.10:55876","dev-test-06:443"
    This will execute the script on all three of the named computers, using the
    specified ports for WinRM on latter two and the current user's identity.

    #requires -version 2
#>

[CmdletBinding()]
Param( 
    # List of computers to execute this script on, defaults to this computer if not specified
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]$Computers = $env:COMPUTERNAME,

    # PSCredential that will be used for WinRM to connect to the target machines
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [PSCredential]$PSCredential
)

#---------[ Global Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Output object for return
$Output = @();

# Scriptblock to execute imported from file
[ScriptBlock]$ScriptBlock = [ScriptBlock]::Create($(Get-Content "..\Lib\Audit-Scriptblock.ps1" | Out-String));

# Loop to execute on targeted computers
ForEach ($Computer in $Computers) {
    
    # Ok we need to check if we're using a non-standard port
    if ($Computer.Contains(":")) {
        # Split up for params
        $Hostname = $Computer.Split(":")[0];
        $Port     = $Computer.Split(":")[1];

        # We need to check and see if the user supplied credentials and act accordingly
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
        # We need to check and see if the user supplied credentials and act accordingly
        if ($PSCredential) {
            # Execute the command supplying the credential 
            $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock -Credential $PSCredential;
        }
        else {
            # Execute the command using the default credential
            $HostInformation = Invoke-Command -ComputerName $Hostname -ScriptBlock $ScriptBlock;
        }
    }

    # And add the output
    $Output += $HostInformation;
}

# Check if our RawData folder exists
$RawDataFolder = "..\Output\RawData";
if (!(Test-Path $RawDataFolder)) {
    [Void](New-Item $RawDataFolder -ItemType Directory);
}

# Write XML to disk
$Output | %{
    # Get the pipe object
    $HostInformation = $_;

    # Get our filename
    $OutputFileName = "$RawDataFolder\$($HostInformation.OS.CSName).cli.xml";

    # Write to disk
    Export-Clixml -InputObject $HostInformation -Path $OutputFileName;
}