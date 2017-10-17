<#
    .SYNOPSIS
    Name: Invoke-WindowsAudit.ps1
    Gathers information about a Windows Server instance
    
    .DESCRIPTION
    This script will gather a variety of information from a Windows Server instance,
    returning it in a format that can be manipulated to produce an output report
    indicating the machine's current Application/Hardware/Configuration status.

    .PARAMETER NoneForNow
    (Paramdescription)
    
    .EXAMPLE
    (Example)

    #requires -version 2
#>

[CmdletBinding()]
Param( 
    
)

#---------[ Declarations ]---------
# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

#---------[ Functions ]---------
#Functions

#---------[ Main() ]---------
#Main()