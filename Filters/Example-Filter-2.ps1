[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Functions module
Import-Module "..\Lib\Filter-Functions.ps1" -DisableNameChecking;

# Host Information
#Hostname	Domain Name	IPv4	OS Version	Uptime	Last Restart	Region/Locale	Timezone	System Type	Location	CPU	CPU in use	Memory	Memory in use	PS Version	.NET Version

# Network
#Hostname	Adapter Index	IPv4	IPv6	Domain Name	Subnet	Gateway	DNS Servers	Firewall Rule Names	TLS Certifcate Names	TLS Certifcate Expiry	WSUS Server

# Storage
#Hostname	Disk Caption	Mount	Type	Size	Usage

# Mounts and Folders
#Hostname	Shared Folder Path	Mounted Drive Path

# Applications
#Hostname	DisplayName	Version	Windows Roles	Windows Features	Schedules Tasks
