<#
    .SYNOPSIS
    Name: Parse-WindowsAudit.ps1
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