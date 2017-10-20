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

$Information = [PSCustomObject]@{
    "HostName"                  = $HostInformation.OS.CSName;
    "Domain Name"               = $HostInformation.SystemInfo.SystemInfo.Domain;
    "IPv4 Address"              = $((($HostInformation.Networking.AdapterInformation | ?{$_.IPAddress} | select IPAddress).IPAddress|?{$_| Is-Ipv4Address}) -Join ", ");
    "OS"                        = $HostInformation.OS.Caption;
    "Uptime"                    = $(Get-DateTimeDifference -CompareDateTime $([Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime)));
    "Region/Locale"             = $(Get-LocaleFromWMICode -WMILocaleCode $HostInformation.OS.Locale);
    "Timezone"                  = $(Get-TimeZoneDisplayName -UTCOffsetMinutes $HostInformation.OS.CurrentTimeZone);
    "System Type"               = $(if($HostInformation.SystemInfo.IsVirtualMachine){"Virtual Machine"}else{"Physical Machine"});
    "Location"                  = $(Locate-WindowsMachine);
    "CPU"                       = $(($HostInformation.Compute.Name | Select -First 1) + " x$($HostInformation.Compute.Name.Count)");
    "PowerShell Version"        = $HostInformation.Management.PowerShellVersion;
    ".NET Version"              = $HostInformation.Management.DotNetVersion;
    "CPU Use % (Total)"         = $HostInformation.SystemInfo.CPUPercentInUse;
    "Total Physical Memory"     = $HostInformation.Memory.WindowsMemory.TotalPhysicalMemory;
    "Available Physical Memory" = $HostInformation.Memory.WindowsMemory.AvailablePhysicalMemory;
    "Virtual Memory Max Size"   = $HostInformation.Memory.WindowsMemory.VirtualMemoryMaxSize;
    "Virtual Memory Available"  = $HostInformation.Memory.WindowsMemory.VirtualMemoryAvailable;
    "Virtual Memory InUse"      = $HostInformation.Memory.WindowsMemory.VirtualMemoryInUse;    
}

# Network
#Hostname	Adapter Index	IPv4	IPv6	Domain Name	Subnet	Gateway	DNS Servers	Firewall Rule Names	TLS Certifcate Names	TLS Certifcate Expiry	WSUS Server

# Storage
#Hostname	Disk Caption	Mount	Type	Size	Usage

# Mounts and Folders
#Hostname	Shared Folder Path	Mounted Drive Path

# Applications
#Hostname	DisplayName	Version	Windows Roles	Windows Features	Schedules Tasks
