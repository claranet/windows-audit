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
    Name                  = ""
    Manufacturer          = ""
    Cores                 = ""
    Status                = ""
    MaxClockSpeed         = ""
    CurrentClockSpeed     = ""
    Caption               = ""
    LogicalProcessors     = ""
    HyperThreadingEnabled = ""

# Memory	
    # RAM
    TotalPhysicalMemory     = ""
    AvailablePhysicalMemory = ""
    VirtualMemoryMaxSize    = ""
    VirtualMemoryAvailable  = ""
    VirtualMemoryInUse      = ""
	
# Storage	
    # Physical Disks
    PhysicalDisks = ""

    # Logical Disks
    LogicalDisks = ""
    
    # Volumes
    Volumes = ""
    
    # Shared Folders
    SharedFolders = ""
    
    # Mounted Drives
    MountedDrives = ""
	
# Networking	
    # Ipv4 address(es)
    IPv4Addresses = ""

    # Ipv6 address(es)
    IPv6Addresses = ""

    # Subnet info
    Gateway = ""
    SubnetMask = ""

    # DNS/WINS/NetBIOS info
    DNSSuffixes = ""
    DNSServers  = ""

    # NTP/Time servers
    NTPConfiguration = ""

    # NICs
    NetworkInterfaces = ""

    # Domain name
    DomainName = ""

    # Firewall
    EnabledFirewallZone = ""
    FirewallRules = ""

    # TLS Certificates
    TLSCertificates = ""
	
# Peripherals	
    # Printers
    Printers = ""

    # Other Serial/USB devices
    SerialDevices = ""
    USBDevices    = ""
	
# Applications & Features	
    # Installed Win32 Applications
    InstalledApplications = ""

    # Web Applications
    WebApplications = ""

    # Windows Features
    InstalledRolesAndFeatures = ""

    # Windows Update
    InstalledUpdates = ""

    # Scheduled tasks
    ScheduledTasks = ""

    # PowerShell/.NET version
    PowerShellVersion = ""
    DotNetVersion     = ""

    # WinRM status
    WinRMEnabled  = ""
    WinRMProtocol = ""
	
}

# And return it
return $Output;