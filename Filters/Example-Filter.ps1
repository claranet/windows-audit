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
    Hostname = $HostInformation.OS.CSName

	# Uptime/Last rebooted
    Uptime       = [Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime)
    LastRebooted = $(
        $StartTime = [Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime);
        $EndTime   = Get-Date;
        $TimeSpan  = New-TimeSpan $StartTime $EndTime;
        return "{0} Days, {1} Hours, {2} Minutes ago" -f $TimeSpan.Days, $TimeSpan.Hours, $TimeSpan.Minutes;
    )

	# Region/Locale
    Locale = $(
        $HexNumber  = [System.Globalization.NumberStyles]::HexNumber;
        $InvarInfo  = [System.Globalization.NumberFormatInfo]::InvariantInfo;
        $LocaleCode = 0;
        [Void]([Int]::TryParse($HostInformation.OS.Locale, $HexNumber, $InvarInfo, [Ref]$LocaleCode));
        return [CultureInfo]::GetCultureInfo($LocaleCode).Name;
    )

	# Timezone
    TimeZone = $(
        $UTCOffsetHours = "{0:D2}:00:00" -F $($HostInformation.OS.CurrentTimeZone / 60);
        $Zones = [System.TimeZoneInfo]::GetSystemTimeZones() | ?{$_.BaseUtcOffset -eq $UTCOffsetHours};
        return $Zones.DisplayName -join " | ";
    )

	# System type
    SystemType = $(if($HostInformation.SystemInfo.IsVirtualMachine){"Virtual Machine"}else{"Physical Machine"})

	# Hypervisor
    Hypervisor = $(if($HostInformation.SystemInfo.IsVirtualMachine){$HostInformation.SystemInfo.MachineType}else{"None"})

	# Location
    Location = "" # Needs work

	# Operating system version
    OSVersion = $HostInformation.OS.Name.Split("|")[0].Trim()
	
# Compute
    # CPU
    Name                  = $HostInformation.Compute.Name
    Manufacturer          = $HostInformation.Compute.Manufacturer
    Cores                 = $HostInformation.Compute.NumberOfCores
    Status                = $HostInformation.Compute.Status
    MaxClockSpeed         = $HostInformation.Compute.MaxClockSpeed
    CurrentClockSpeed     = $HostInformation.Compute.CurrentClockSpeed
    Caption               = $HostInformation.Compute.Caption
    LogicalProcessors     = $HostInformation.Compute.NumberOfLogicalProcessors
    HyperThreadingEnabled = $(
        $PhysicalCores = $HostInformation.Compute.NumberOfCores;
        $LogicalCores  = $HostInformation.Compute.NumberOfLogicalProcessors
        if ($LogicalCores -eq (2*$PhysicalCores)) {
            return $True;
        }
        else {
            return $False;
        }
    )

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