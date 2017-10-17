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
    #
)

#---------[ Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Get our return object sorted out
$HostInformation = New-Object PSCustomObject;

#---------[ Functions ]---------

# Easy add-member function
Function Add-HostInformation {
    [Cmdletbinding()]
    Param(
        # The name of the property we're adding
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        # The value of the property we're adding
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Object]$Value
    )

    # Add the property to HostInformation
    $HostInformation | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;

}

#---------[ Main() ]---------

# Compute
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor");

# Memory
Add-HostInformation -Name Memory -Value $(Get-WMIObject -Class "Win32_PhysicalMemory");

# Storage
Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
    PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive")
    LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk")
    Volumes       = $(Get-WMIObject -Class "Win32_Volume")
    SharedFolders = "TODO"
    MountedDrives = $(Get-WMIObject -Class "Win32_MountPoint")
});

# Networking

# Peripherals

# Applications and features

# System information

#---------[ Return ]---------
return $HostInformation;