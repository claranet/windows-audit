[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Functions

# Converts a Win32_LogicalDisk MediaType enum to a description string
Function ConvertTo-DiskMediaTypeString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateRange(0, 22)]
        [Int]$MediaTypeEnum
    )

    Switch($MediaTypeEnum) {
        0  {"Unknown media type"}
        1  {"5¼ Inch Floppy Disk - 1.2 MB - 512 bytes/sector"}
        2  {"3½ Inch Floppy Disk - 1.44 MB - 512 bytes/sector"}
        3  {"3½ Inch Floppy Disk - 2.88 MB - 512 bytes/sector"}
        4  {"3½ Inch Floppy Disk - 20.8 MB - 512 bytes/sector"}
        5  {"3½ Inch Floppy Disk - 720 KB - 512 bytes/sector"}
        6  {"5¼ Inch Floppy Disk - 360 KB - 512 bytes/sector"}
        7  {"5¼ Inch Floppy Disk - 320 KB - 512 bytes/sector"}
        8  {"5¼ Inch Floppy Disk - 320 KB - 1024 bytes/sector"}
        9  {"5¼ Inch Floppy Disk - 180 KB - 512 bytes/sector"}
        10 {"5¼ Inch Floppy Disk - 160 KB - 512 bytes/sector"}
        11 {"Removable media other than floppy"}
        12 {"Fixed hard disk media"}
        13 {"3½ Inch Floppy Disk - 120 MB - 512 bytes/sector"}
        14 {"3½ Inch Floppy Disk - 640 KB - 512 bytes/sector"}
        15 {"5¼ -Inch Floppy Disk - 640 KB - 512 bytes/sector"}
        16 {"5¼ -Inch Floppy Disk - 720 KB - 512 bytes/sector"}
        17 {"3½ Inch Floppy Disk - 1.2 MB - 512 bytes/sector"}
        18 {"3½ Inch Floppy Disk - 1.23 MB - 1024 bytes/sector"}
        19 {"5¼ Inch Floppy Disk - 1.23 MB - 1024 bytes/sector"}
        20 {"3½ Inch Floppy Disk - 128 MB - 512 bytes/sector"}
        21 {"3½ Inch Floppy Disk - 230 MB - 512 bytes/sector"}
        22 {"8 Inch Floppy Disk - 256 KB - 128 bytes/sector"}
    }
}

# Converts a Win32_LogicalDisk DriveType enum to a description string
Function ConvertTo-DiskDriveTypeString {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [ValidateRange(0, 6)]
        [Int]$DriveTypeEnum
    )

    Switch($DriveTypeEnum) {
        0 {"Unknown media type"}
        1 {"No Root Directory"}
        2 {"Removable Disk"}
        3 {"Local Disk"}
        4 {"Network Drive"}
        5 {"Compact Disc"}
        6 {"RAM Disk"}
    }
}

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
    TotalPhysicalMemory     = $HostInformation.Memory.WindowsMemory.TotalPhysicalMemory
    AvailablePhysicalMemory = $HostInformation.Memory.WindowsMemory.AvailablePhysicalMemory
    VirtualMemoryMaxSize    = $HostInformation.Memory.WindowsMemory.VirtualMemoryMaxSize
    VirtualMemoryAvailable  = $HostInformation.Memory.WindowsMemory.VirtualMemoryAvailable
    VirtualMemoryInUse      = $HostInformation.Memory.WindowsMemory.VirtualMemoryInUse
	
# Storage	
    # Physical Disks
    PhysicalDisks = $(
        $I = 0;
        $HostInformation.Storage.PhysicalDisks | %{
            $I++;
            "Physical Disk  : $I"
            "Interface Type : " + $_.InterfaceType
            "Size           : " + $_.Size
            "Features       : " + $($_.CapabilityDescriptions -Join ", ")
            "Caption        : " + $_.Caption
            "Manufacturer   : " + $_.Manufacturer
            "Model          : " + $_.Model
            "Disk Type      : " + $_.MediaType
            "Serial Number  : " + $_.SerialNumber
            if ($_.SCSIBus) {
            "SCSI Information"
                "Bus          : " + $_.SCSIBus
                "Logical Unit : " + $_.SCSILogicalUnit
                "Port         : " + $_.SCSIPort
                "Target ID    : " + $_.SCSITargetID
            }
            "-----------------"
        }
    )

    # Logical Disks
    LogicalDisks = $(
        $I = 0;
        $HostInformation.Storage.LogicalDisks | %{
            $I++;
            "Logical Disk     : $I"
            "Name             : " + $_.Name
            "Mount Point      : " + $_.DeviceID
            "Caption          : " + $_.Caption
            "Compressed       : " + $_.Compressed
            "Description      : " + $_.Description
            "Drive Type       : " + $(ConvertTo-DiskDriveTypeString -DriveTypeEnum $_.DriveType)
            "Media Type       : " + $(ConvertTo-DiskMediaTypeString -MediaTypeEnum $_.MediaType)
            "File System      : " + $_.FileSystem
            "Free Space       : " + [Math]::Round(($_.FreeSpace / 1GB),2)+" GB"
            "Used Space       : " + [Math]::Round((($_.Size - $_.Freespace) / 1GB),2)+" GB"
            "Total Size       : " + [Math]::Round(($_.Size / 1GB),2)+" GB"
            "Is Dirty Volume  : " + $_.VolumeDirty
            "Volume Name      : " + $_.VolumeName
            "Volume Serial No : " + $_.VolumeSerialNumber
            "-----------------"
        }
    )
    
    # Volumes
    Volumes = $(
        $I = 0;
        $HostInformation.Storage.Volumes | %{
            $I++;
            "Volume                    : $I"
            "Name                      : " + $_.Name
            "Mount Point               : " + $_.DeviceID
            "Auto Mount                : " + $_.AutoMount
            "Block Size                : " + $_.BlockSize
            "Boot Volume               : " + $_.BootVolume
            "System Volume             : " + $_.SystemVolume
            "Indexing Enabled          : " + $_.IndexingEnabled
            "Page file present         : " + $_.PageFilePresent
            "Max Filename Length       : " + $_.MaximumFileNameLength
            "Supports Disk Quotas      : " + $_.SupportDiskQuotas
            "Quotas Enabled            : " + $_.QuotasEnabled
            "Quotas Incomplete         : " + $_.QuotasIncomplete
            "Quotas Rebuilding         : " + $_.QuotasRebuilding
            "Caption                   : " + $_.Caption
            "Supports File Compression : " + $_.SupportsFileBasedCompression
            "Compressed                : " + $_.Compressed
            "Description               : " + $_.Description
            "Drive Type                : " + $(ConvertTo-DiskDriveTypeString -DriveTypeEnum $_.DriveType)
            "File System               : " + $_.FileSystem
            "Free Space                : " + [Math]::Round(($_.FreeSpace / 1GB),2)+" GB"
            "Used Space                : " + [Math]::Round((($_.Capacity - $_.Freespace) / 1GB),2)+" GB"
            "Total Size                : " + [Math]::Round(($_.Capacity / 1GB),2)+" GB"
            "Is Dirty Volume           : " + $_.DirtyBitSet
            "-----------------"
        }
    )
    
    # Shared Folders
    SharedFolders = $(
        $HostInformation.Storage.SharedFolders | %{
            "Name                      : " + $_.Name
            "Type                      : " + $_.Type
            "Status                    : " + $_.Status
            "Access Mask               : " + $_.AccessMask
            "Allow Maximum Connections : " + $_.AllowMaximum
            "Caption                   : " + $_.Caption
            "Description               : " + $_.Description
            "Local File Path           : " + $_.Path
            "-----------------"
        }
    )
    
    # Mounted Drives
    MountedDrives = $(
        $HostInformation.Storage.MountedDrives | %{
            "Directory : " + $_.Directory
            "Volume    : " + $_.Volume
            "Path      : " + $_.Path
            "-----------------"
        }
    )
	
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