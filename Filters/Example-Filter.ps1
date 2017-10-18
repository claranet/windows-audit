[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Let's declare a new object to return
$Output = New-Object PSObject -Property @{

# System Information	
    # Hostname
    Hostname = ""

	# Uptime/Last rebooted
    Uptime       = ""
    LastRebooted = ""

	# Region/Locale
    Region = ""

	# Timezone
    TimeZone = ""

	# System type
    SystemType = ""

	# Hypervisor
    Hypervisor = ""

	# Location
    Location = ""

	# Operating system version
    OSVersion = ""
	
# Compute	
    # CPU
    Status = ""
    MaxClockSpeed = ""
    CurrentClockSpeed = ""
    Caption = ""
    Name = ""
    Manufacturer = ""
    Cores = ""
    LogicalProcessors = ""
    HyperThreadingEnabled = ""

# Memory	
    # RAM
	
# Storage	
    # Physical Disks
	# Logical Disks
	# Volumes
	# Shared Folders
	# Mounted Drives
	
# Networking	
    # Ipv4 address(es)
	# Ipv6 address(es)
	# Subnet info
	# DNS/WINS/NetBIOS info
	# Hostname
	# NTP/Time servers
	# NICs
	# Domain name
	# Firewall
	# TLS Certificates
	
# Peripherals	
    # Printers
	# Other Serial/USB devices
	
# Applications & Features	
    # Installed Win32 Applications
	# Web Applications
	# Windows Features
	# Windows Roles
	# Windows Update
	# Scheduled tasks
	# PowerShell version
	# WinRM status
	
# System Information	
    # Uptime/Last rebooted
	# Region/Locale
	# Timezone/Current time vs External
	# System type
	# Hypervisor & Guest tools
	# Location
	# Operating system version

}

# And return it
return $Output;