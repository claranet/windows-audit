[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Functions module
Import-Module "..\Lib\Filter-Functions.ps1" -DisableNameChecking;

# Systeminfo hashtable
$SystemInfo = @{
    
    # System Info
    HostName     = $HostInformation.OS.CSName;
    Uptime       = [Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime);
    LastRebooted = $(Get-DateTimeDifference -CompareDateTime $([Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime)));
    Locale       = $(Get-LocaleFromWMICode -WMILocaleCode $HostInformation.OS.Locale);
    Timezone     = $(Get-TimeZoneDisplayName -UTCOffsetMinutes $HostInformation.OS.CurrentTimeZone);
    SystemType   = $(if($HostInformation.SystemInfo.IsVirtualMachine){"Virtual Machine"}else{"Physical Machine"});
    HyperVisor   = $(if($HostInformation.SystemInfo.IsVirtualMachine){$HostInformation.SystemInfo.MachineType}else{"None"});
    Location     = $(Locate-WindowsMachine);
    OSVersion    = $($HostInformation.OS.Name.Split("|")[0].Trim());
    ServerRoles  = $(($HostInformation.RolesAndFeatures | ?{$_.Installed -and $_.FeatureType -eq "Role"} | Select Name).Name -Join ", ");

    # Memory
    TotalPhysicalMemory     = $HostInformation.Memory.WindowsMemory.TotalPhysicalMemory;
    AvailablePhysicalMemory = $HostInformation.Memory.WindowsMemory.AvailablePhysicalMemory;
    VirtualMemoryMaxSize    = $HostInformation.Memory.WindowsMemory.VirtualMemoryMaxSize;
    VirtualMemoryAvailable  = $HostInformation.Memory.WindowsMemory.VirtualMemoryAvailable;
    VirtualMemoryInUse      = $HostInformation.Memory.WindowsMemory.VirtualMemoryInUse;

    # Networking
    EnabledFirewallZone = $HostInformation.Networking.FirewallZone;

    # PowerShell/.NET version
    PowerShellVersion   = $HostInformation.Management.PowerShellVersion;
    DotNetVersion       = $HostInformation.Management.DotNetVersion

    # WinRM status
    WinRMEnabled        = $HostInformation.Management.WinRMEnabled
    #WinRMProtocols     = $HostInformation.Management.WinRMProtocols not available due to security feature :(
}

# Network Adapters
$NetworkAdapters = $HostInformation.Networking.AdapterInformation | %{
    [PSCustomObject]@{  
        "HostName"                        = $HostInformation.OS.CSName
        "Adapter Index"                   = $_.Index
        "Model/Type"                      = $_.Description
        "Caption"                         = $_.Caption
        "IPv4 Addresses"                  = $(($_.IPAddress | ?{Is-Ipv4Address $_}) -Join  ", ")
        "IPv6 Addresses"                  = $(($_.IPAddress | ?{Is-Ipv6Address $_}) -Join  ", ")
        "Subnet Mask"                     = $($_.IPSubnet | Select -First 1)
        "MAC Address"                     = $_.MACAddress
        "Service Name"                    = $_.ServiceName
        "Using DHCP"                      = $_.DHCPEnabled
        "DHCP Lease Obtained"             = $(if($_.DHCPLeaseObtained){[Management.ManagementDateTimeConverter]::ToDateTime($_.DHCPLeaseObtained)})
        "DHCP Lease Expires"              = $(if($_.DHCPLeaseExpires){[Management.ManagementDateTimeConverter]::ToDateTime($_.DHCPLeaseExpires)})
        "DHCP Server"                     = $_.DHCPServer
        "DNS Domain"                      = $_.DNSDomain
        "DNS Suffix Order"                = $($_.DNSDomainSuffixSearchOrder -join ", ")
        "DNS Hostname"                    = $_.DNSHostName
        "DNS Server Order"                = $($_.DNSServerSearchOrder -join ", ")
        "Domain DNS Registration"         = $_.DomainDNSRegistrationEnabled
        "Full DNS Registration"           = $_.FullDNSRegistrationEnabled
        "Using WINS"                      = $_.DNSEnabledForWINSResolution
        "WINS Enable LMHost Lookup"       = $_.WINSEnableLMHostsLookup
        "WINS Host Lookup File"           = $_.WINSHostLookupFile
        "WINS Primary Server"             = $_.WINSPrimaryServer
        "WINS Secondary Server"           = $_.WINSSecondaryServer
        "WINS Scope ID"                   = $_.WINSScopeID
        "IP Connection Metric"            = $_.IPConnectionMetric
        "IP Enabled"                      = $_.IPEnabled
        "IP Filter Security Enabled"      = $_.IPFilterSecurityEnabled
        "ARP Always Source Route"         = $_.ARPAlwaysSourceRoute
        "ARP Use Ethernet SNAP"           = $_.ArpUseEtherSNAP
        "Database Path"                   = $_.DatabasePath
        "Dead Gateway Detection"          = $_.DeadGWDetectEnabled
        "Default Gateway"                 = $($_.DefaultIPGateway -join ", ")
        "Default TOS"                     = $_.DefaultTOS
        "Default TTL"                     = $_.DefaultTTL
        "Gateway Cost Metric"             = $($_.GatewayCostMetric -join ", ")
        "IGMP Level"                      = $_.IGMPLevel
        "IP Port Security Enabled"        = $_.IPPortSecurityEnabled
        "IP Use Zero Broadcast"           = $_.UseIPZeroBroadcast 
        "IPSec Permit IP Protocols"       = $($_.IPSecPermitIPProtocols -join ", ")
        "IPSec Permit TCP Ports"          = $($_.IPSecPermitTCPPorts -join ", ")
        "IPSec Permit UDP Ports"          = $($_.IPSecPermitUDPPorts -join ", ")
        "IPX Enabled"                     = $_.IPXEnabled
        "IPX Address"                     = $_.IPXAddress
        "IPX Frame Type"                  = $_.IPXFrameType
        "IPX Media Type"                  = $_.IPXMediaType
        "IPX Network Number"              = $_.IPXNetworkNumber
        "IPX Virtual Network Number"      = $_.IPXVirtualNetworkNumber
        "Keep Alive Interval"             = $_.KeepAliveInterval
        "Keep Alive Time"                 = $_.KeepAliveTime
        "Packet MTU"                      = $_.MTU
        "Number of Forward Packets"       = $_.NumForwardPackets
        "PMTUBH Detection Enabled"        = $_.PMTUBHDetectEnabled
        "PMTUBH Discovery Enabled"        = $_.PMTUBHDiscoveryEnabled
        "TCP NetBIOS Options"             = $_.TcpipNetBIOSOptions
        "TCP Max Connect Retransmissions" = $_.TcpMaxRecconectTransmissions
        "TCP Max Data Retransmissions"    = $_.TcpMaxDataRetransmissions
        "TCP Number of Connections"       = $_.TcpNumConnections
        "TCP Use RFC1122 Urgent Pointer"  = $_.TcpUseRFC1122UrgentPointer
        "TCP Window Size"                 = $_.TCPWindowSize
    }
}

# CPU
$CPUs = $HostInformation.Compute | %{
    [PSCustomObject]@{
        "HostName"                   = $HostInformation.OS.CSName
        "CPU Name"                   = $HostInformation.Compute.Name
        "CPU Manufacturer"           = $HostInformation.Compute.Manufacturer
        "CPU Cores"                  = $HostInformation.Compute.NumberOfCores
        "CPU Status"                 = $HostInformation.Compute.Status
        "CPU MaxClockSpeed"          = $HostInformation.Compute.MaxClockSpeed
        "CPU CurrentClockSpeed"      = $HostInformation.Compute.CurrentClockSpeed
        "CPU Caption"                = $HostInformation.Compute.Caption
        "CPU LogicalProcessors"      = $HostInformation.Compute.NumberOfLogicalProcessors
        "CPU HyperThreading Enabled" = $(Is-HyperThreadingEnabled -PhysicalCores $HostInformation.Compute.NumberOfCores -LogicalCores $HostInformation.Compute.NumberOfLogicalProcessors) 
    }
}

# Physical Disks
$PhysicalDisks = $HostInformation.Storage.PhysicalDisks | %{
    [PSCustomObject]@{
        "HostName"          = $HostInformation.OS.CSName
        "Interface Type"    = $_.InterfaceType
        "Size"              = $_.Size
        "Features"          = $($_.CapabilityDescriptions -Join ", ")
        "Caption"           = $_.Caption
        "Manufacturer"      = $_.Manufacturer
        "Model"             = $_.Model
        "Disk Type"         = $_.MediaType
        "Serial Number"     = $_.SerialNumber
        "SCSI Bus"          = $_.SCSIBus
        "SCSI Logical Unit" = $_.SCSILogicalUnit
        "SCSI Port"         = $_.SCSIPort
        "SCSI Target ID"    = $_.SCSITargetID
    }
}

# Logical Disks
$LogicalDisks = $HostInformation.Storage.LogicalDisks | %{
    [PSCustomObject]@{
        "HostName"    = $HostInformation.OS.CSName
        "Name"        = $_.Name
        "Mount Point" = $_.DeviceID
        "Caption"     = $_.Caption
        "Compressed"  = $_.Compressed
        "Description" = $_.Description
        "Drive Type"  = $(ConvertTo-DiskDriveTypeString -DriveTypeEnum $_.DriveType)
        "Media Type"  = $(ConvertTo-DiskMediaTypeString -MediaTypeEnum $_.MediaType)
        "File System" = $_.FileSystem
        "Free Space"  = [Math]::Round(($_.FreeSpace / 1GB),2)+" GB"
        "Used Space"  = [Math]::Round((($_.Size - $_.Freespace) / 1GB),2)+" GB"
        "Total Size"  = [Math]::Round(($_.Size / 1GB),2)+" GB"
        "Is Dirty"    = $_.VolumeDirty
        "Vol Name"    = $_.VolumeName
        "Serial No"   = $_.VolumeSerialNumber
    }
}

# Volumes
$Volumes = $HostInformation.Storage.Volumes | %{
    [PSCustomObject]@{
        "HostName"                  = $HostInformation.OS.CSName
        "Volume"                    = $I
        "Name"                      = $_.Name
        "Mount Point"               = $_.DeviceID
        "Auto Mount"                = $_.AutoMount
        "Block Size"                = $_.BlockSize
        "Boot Volume"               = $_.BootVolume
        "System Volume"             = $_.SystemVolume
        "Indexing Enabled"          = $_.IndexingEnabled
        "Page file present"         = $_.PageFilePresent
        "Max Filename Length"       = $_.MaximumFileNameLength
        "Supports Disk Quotas"      = $_.SupportDiskQuotas
        "Quotas Enabled"            = $_.QuotasEnabled
        "Quotas Incomplete"         = $_.QuotasIncomplete
        "Quotas Rebuilding"         = $_.QuotasRebuilding
        "Caption"                   = $_.Caption
        "Supports File Compression" = $_.SupportsFileBasedCompression
        "Compressed"                = $_.Compressed
        "Description"               = $_.Description
        "Drive Type"                = $(ConvertTo-DiskDriveTypeString -DriveTypeEnum $_.DriveType)
        "File System"               = $_.FileSystem
        "Free Space"                = [Math]::Round(($_.FreeSpace / 1GB),2)+" GB"
        "Used Space"                = [Math]::Round((($_.Capacity - $_.Freespace) / 1GB),2)+" GB"
        "Total Size"                = [Math]::Round(($_.Capacity / 1GB),2)+" GB"
        "Is Dirty Volume"           = $_.DirtyBitSet
    }
}

# Shared Folders
$SharedFolders = $HostInformation.Storage.SharedFolders | %{
    [PSCustomObject]@{
        "HostName"                  = $HostInformation.OS.CSName
        "Name"                      = $_.Name
        "Type"                      = $_.Type
        "Status"                    = $_.Status
        "Access Mask"               = $_.AccessMask
        "Allow Maximum Connections" = $_.AllowMaximum
        "Caption"                   = $_.Caption
        "Description"               = $_.Description
        "Local File Path"           = $_.Path
    }
}

# Mounted Drives
$MountedDrives = $HostInformation.Storage.MountedDrives | %{
    [PSCustomObject]@{
        "HostName"  = $HostInformation.OS.CSName
        "Directory" = $_.Directory
        "Volume"    = $_.Volume
        "Path"      = $_.Path
    }
}

# Firewall rules
#$HostInformation.Networking.FirewallRules

# TLS Certificates
$TLSCertificates = $HostInformation.TLSCertificates | ?{!$_.PSIsContainer} | %{
    [PSCustomObject]@{
        "HostName"            = $HostInformation.OS.CSName
        "Friendly Name"       = $_.FriendlyName
        "Path"                = $_.PSParentPath
        "Thumbprint"          = $_.Thumbprint
        "Archived"            = $_.Archived
        "Extensions"          = $(($_.Extensions | %{$_}) -join ", ")
        "Issuer"              = $_.Issuer
        "Subject"             = $_.Subject
        "Not After"           = $_.NotAfter
        "Not Before"          = $_.NotBefore
        "Has Private Key"     = $_.HasPrivateKey
        "Public Key"          = $($_.PublicKey)
        "Raw Data"            = $($_.RawData -Join ", ")
        "Serial Number"       = $_.SerialNumber
        "Subject Name"        = $($_.SubjectName)
        "Signature Algorithm" = $($_.SignatureAlgorithm)
        "Version"             = $_.Version
        "Handle"              = $_.Handle
    }
}

# Printers
$Printers = $HostInformation.Peripherals.Printers | %{
    [PSCustomObject]@{
        "HostName"            = $HostInformation.OS.CSName
        "Name"                = $_.Name
        "Status"              = $_.Status
        "Attributes"          = $_.Attributes
        "Availability"        = $_.Availability
        "Capabilities"        = $($_.CapabilityDescriptions -join ", ")
        "Caption"             = $_.Caption
        "Comment"             = $_.Comment
        "Description"         = $_.Description
        "Is Default Printer"  = $_.Default
        "Device ID"           = $_.DeviceID
        "Direct Connection"   = $_.Direct
        "Driver Name"         = $_.DriverName
        "Is Local Printer"    = $_.Local
        "Location"            = $_.Location
        "Network Printer"     = $_.Network
        "Port Name"           = $_.PortName
        "Printer State"       = $_.PrinterState
        "Printer Status"      = $_.PrinterStatus
        "Print Job Data Type" = $_.PrintJobDataType
        "Print Processor"     = $_.PrintProcessor
        "Priority"            = $_.Priority
        "Published"           = $_.Published
        "Server Name"         = $_.ServerName
        "Status Info"         = $_.StatusInfo
        "System Name"         = $_.SystemName
        "Last Reset Time"     = $_.TimeOfLastReset 
    }
}

# Serial Devices
$SerialDevices = $HostInformation.Peripherals.SerialDevices %{
    [PSCustomObject]@{
        "HostName"                    = $HostInformation.OS.CSName
        "Name"                        = $_.Name
        "Availability"                = $_.Availability
        "Status"                      = $_.Status
        "Binary"                      = $_.Binary
        "Features"                    = $($_.CapabilityDescriptions -Join ", ")
        "Caption"                     = $_.Caption
        "Config Manager Error Code"   = $_.ConfigManagerErrorCode
        "Config Manager User Config"  = $_.ConfigManagerUserConfig
        "Creation Class Name"         = $_.CreationClassName
        "Description"                 = $_.Description
        "Device ID"                   = $_.DeviceID
        "Error Cleared"               = $_.ErrorCleared
        "Error Description"           = $_.ErrorDescription
        "Install Date"                = $_.InstallDate
        "Last Error Code"             = $_.LastErrorCode
        "Max BAUD Rate"               = $_.MaxBaudRate
        "Max Input Buffer Size"       = $_.MaximumInputBufferSize
        "Max Output Buffer Size"      = $_.MaximumOutputBufferSize
        "Max Number Controlled"       = $_.MaxNumberControlled
        "OS Auto Discovered"          = $_.OSAutoDiscovered
        "PNP Device ID"               = $_.PNPDeviceID
        "Power Management Supported"  = $_.PowerManagementSupported
        "Power Management Features"   = $($_.PowerManagementCapabilities -Join ", ")
        "Protocol Supported"          = $_.ProtocolSupported
        "Provider Type"               = $_.ProviderType
        "Settable BAUD Rate"          = $_.SettableBaudRate
        "Settable Data Bits"          = $_.SettableDataBits
        "Settable Flow Control"       = $_.SettableFlowControl
        "Settable Parity"             = $_.SettableParity
        "Settable Parity Check"       = $_.SettableParityCheck
        "Settable RLSD"               = $_.SettableRLSD
        "Settable Stop Bits"          = $_.SettableStopBits
        "Status Info"                 = $_.StatusInfo
        "Supports 16 Bit Mode"        = $_.Supports16BitMode
        "Supports DTRDSR"             = $_.SupportsDTRDSR
        "Supports Elapsed Timeouts"   = $_.SupportsElapsedTimeouts
        "Supports Int Timeouts"       = $_.SupportsIntTimeouts
        "Supports Parity Check"       = $_.SupportsParityCheck
        "Supports RLSD"               = $_.SupportsRLSD
        "Supports RTSCTS"             = $_.SupportsRTSCTS
        "Supports Special Characters" = $_.SupportsSpecialCharacters
        "Supports XOn and XOff"       = $_.SupportsXOnXOff
        "Supports XOn and XOff Set"   = $_.SupportsXOnXOffSet
        "Time of Last Reset"          = $_.TimeOfLastReset
        "Path"                        = $_.Path
    }
}

# USB Devices
$USBDevices = $HostInformation.Peripherals.USBDevices | %{
    [PSCustomObject]@{
        "HostName"= $HostInformation.OS.CSName 
        "Device Name" = $_.Name
        "Description" = $_.Description
        "Manufacturer" = $_.Manufacturer
        "Caption" = $_.Caption
        "PNP Class" = $_.PNPClass
        "Availability" = $_.Availability
        "Class GUID" = $_.ClassGuid
        "Compatible ID" = $_.CompatibleID
        "Config Manager Error Code" = $_.ConfigManagerErrorCode
        "Config Manager User Config" = $_.ConfigManagerUserConfig
        "Creation Class Name" = $_.CreationClassName
        "Device ID" = $_.DeviceID
        "Error Cleared" = $_.ErrorCleared
        "Error Description" = $_.ErrorDescription
        "Hardware ID" = $_.HardwareID
        "Install Date" = $_.InstallDate
        "Last Error Code" = $_.LastErrorCode
        "PNP Device ID" = $_.PNPDeviceID
    }
}

# x32 Applications
#$HostInformation.Applications.x32

# x64 Applications
#$HostInformation.Applications.x64

# Installed roles and features
$InstalledRolesAndFeatures = $HostInformation.Applications.InstalledRolesAndFeatures | %{
    [PSCustomObject]@{
        "HostName"     = $HostInformation.OS.CSName
        "Display Name" = $_.DisplayName
        "Name"         = $_.Name
        "Feature Type" = $_.FeatureType
        "Path"         = $_.Path
        "Sub Features" = $($_.Subfeatures -join ", ")
    }
}

# Windows Updates
#$HostInformation.WindowsUpdates

# Scheduled Tasks
#$HostInformation.ScheduledTasks


$Output = @"
System Information	
    NTP Configuration : $($HostInformation.Networking.NTPConfiguration)
	
# Applications & Features	

    # Web
    IISWebApplications = $( # needs re-engineering in the Audit-ScriptBlock as this is terrible
        $HostInformation.IISConfiguration.Sites | gm | ?{$_.MemberType -eq "NoteProperty"} | %{
            "Site Name     : " + $_.Name
            "Configuration : " + $_.Definition.Replace("string ","").Split(",").Replace("$($_.Name)=","")
            "-----------------"
        }
    )
    IISWebApplicationPools = $( # needs re-engineering in the Audit-ScriptBlock as this is terrible
        $HostInformation.IISConfiguration.ApplicationPools | gm | ?{$_.MemberType -eq "NoteProperty"} | %{
            "App Pool Name : " + $_.Name
            "Configuration : " + $_.Definition.Replace("string ","").Split(",").Replace("$($_.Name)=","")
            "-----------------"
        }
    )
    IISVirtualDirectories = $( # needs re-engineering in the Audit-ScriptBlock as this is terrible
        $HostInformation.IISConfiguration.VirtualDirectories | gm | ?{$_.MemberType -eq "NoteProperty"} | %{
            "Virtual Directory Name : " + $_.Name
            "Configuration          : " + $_.Definition.Replace("string ","").Split(",").Replace("$($_.Name)=","")
            "-----------------"
        }
    )

"@

# And return it
return $Output;