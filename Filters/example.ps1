[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Functions module
Import-Module "..\Lib\Audit-Functions.ps1" -DisableNameChecking;

# Make a new dir to export to if not exists
$ExportFolder = ".\Export\$($HostInformation.OS.CSName)";
if (!(Test-Path $ExportFolder)) {
    [Void](New-Item $ExportFolder -ItemType Directory);
}

# Host Information
$Information = [PSCustomObject]@{
    "HostName"                  = $HostInformation.OS.CSName;
    "Domain Name"               = $HostInformation.SystemInfo.SystemInfo.Domain;
    "IPv4 Address"              = $((($HostInformation.Networking.AdapterInformation | ?{$_.IPAddress} | select IPAddress).IPAddress|?{$_| Is-Ipv4Address}) -Join ", ");
    "OS"                        = $HostInformation.OS.Caption;
    "Uptime"                    = $(Get-DateTimeDifference -CompareDateTime $([Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.OS.LastBootUpTime)));
    "Region/Locale"             = $(Get-LocaleFromWMICode -WMILocaleCode $HostInformation.OS.Locale);
    "Timezone"                  = $(Get-TimeZoneDisplayName -UTCOffsetMinutes $HostInformation.OS.CurrentTimeZone);
    "System Type"               = $(if($HostInformation.SystemInfo.IsVirtualMachine){"Virtual Machine"}else{"Physical Machine"});
    "Location"                  = $HostInformation.SystemInfo.Location;
    "WSUS Server"               = $();
    "PowerShell Version"        = $HostInformation.Management.PowerShellVersion;
    ".NET Version"              = $HostInformation.Management.DotNetVersion;
    "CPU"                       = $(($HostInformation.Compute.Name | Select -First 1) + " x$($HostInformation.Compute.Name.Count)");
    "CPU Use % (Total)"         = $HostInformation.SystemInfo.CPUPercentInUse;
    "Total Physical Memory"     = $HostInformation.Memory.WindowsMemory.TotalPhysicalMemory;
    "Available Physical Memory" = $HostInformation.Memory.WindowsMemory.AvailablePhysicalMemory;
    "Virtual Memory Max Size"   = $HostInformation.Memory.WindowsMemory.VirtualMemoryMaxSize;
    "Virtual Memory Available"  = $HostInformation.Memory.WindowsMemory.VirtualMemoryAvailable;
    "Virtual Memory InUse"      = $HostInformation.Memory.WindowsMemory.VirtualMemoryInUse;    
}

# Network
$NetworkInterfaces = $HostInformation.Networking.AdapterInformation | %{
    [PSCustomObject]@{
        "HostName"      = $HostInformation.OS.CSName;
        "Description"   = $_.Description
        "Adapter Index" = $_.Index;
        "IPv4 Address"  = $(($_.IPAddress | ?{Is-Ipv4Address $_}) -Join  ", ");
        "IPv6 Address"  = $(($_.IPAddress | ?{Is-Ipv6Address $_}) -Join  ", ");
        "Domain Name"   = $_.DNSDomain;
        "Subnet Mask"   = $($_.IPSubnet | Select -First 1);
        "Gateway"       = $($_.DefaultIPGateway -join ", ");
        "DNS Servers"   = $($_.DNSServerSearchOrder -join ", ");
    }
}

# Firewall rules
$FirewallRules = $HostInformation.Networking.FirewallRules | %{
    [PSCustomObject]@{
        "HostName"      = $HostInformation.OS.CSName;
        "Name" = $_.Name
        "Description" = $_.Description
        "Local Ports" = $_.LocalPorts
        "Remote Ports" = $_.RemotePorts
        "Local Addresses" = $_.LocalAddresses
        "Remote Addresses" = $_.RemoteAddresses
        "Direction" = $(Switch($_.Direction){1{"Inbound"};2{"Outbound"};default{$_.Direction}});
    }
}

# TLS Certificates
$TLSCertificates = $HostInformation.TLSCertificates | ?{!$_.PSIsContainer} | %{
    [PSCustomObject]@{
        "HostName"        = $HostInformation.OS.CSName;
        "Friendly Name"   = $_.FriendlyName;
        "Expires"         = $_.NotAfter;
        "Thumbprint"      = $_.Thumbprint;
        "Has Private Key" = $_.HasPrivateKey;
        "Issuer"          = $_.Issuer;
    }
}

# Storage
$StorageDisks = $HostInformation.Storage.PhysicalDisks | %{
    [PSCustomObject]@{
        "HostName"       = $HostInformation.OS.CSName;
        "Disk Type"      = $_.Caption;
        "Interface Type" = $_.InterfaceType;
        "Media Type"     = $_.MediaType;
        "Size"           = $([Math]::Round(($_.Size / 1GB)).ToString() + " GB");
    }
}
$StorageVolumes = $HostInformation.Storage.Volumes | %{
    [PSCustomObject]@{
        "HostName"          = $HostInformation.OS.CSName;
        "Caption"           = $_.Caption;
        "Mount Point"       = $_.DriveLetter;
        "Type"              = $(ConvertTo-DiskDriveTypeString -DriveTypeEnum $_.DriveType);
        "Filesystem"        = $_.FileSystem;
        "Boot Volume"       = $_.BootVolume;
        "System Volume"     = $_.SystemVolume;
        "Indexing Enabled"  = $_.IndexingEnabled;
        "Page file present" = $_.PageFilePresent;
        "Compressed"        = $_.Compressed;
        "Free Space"        = $([Math]::Round(($_.FreeSpace / 1GB),2).ToString() +" GB");
        "Used Space"        = $([Math]::Round((($_.Capacity - $_.Freespace) / 1GB),2).ToString() +" GB");
        "Total Size"        = $([Math]::Round(($_.Capacity / 1GB),2).ToString() +" GB");
    }
}

# Mounts and Folders
$SharedFolders = $(
    # Shared folders
    $HostInformation.Storage.SharedFolders | %{
        [PSCustomObject]@{
            "HostName"                  = $HostInformation.OS.CSName;
            "Shared Folder Path"        = $_.Path;
            "Shared Folder Name"        = $_.Name;
            "Shared Folder Description" = $_.Description;
            "Mounted Drive Path"        = "N/A";
            "Mounted Drive Letter"      = "N/A";
        }
    };
    # Mounted drives
    $HostInformation.Storage.MountedDrives | %{
        [PSCustomObject]@{
            "HostName"                  = $HostInformation.OS.CSName;
            "Shared Folder Path"        = "N/A";
            "Shared Folder Name"        = "N/A";
            "Shared Folder Description" = "N/A";
            "Mounted Drive Path"        = $_.ProviderName;
            "Mounted Drive Letter"      = $_.Name;
        }
    };
)

# Applications
$Applications = $(
    # 32 Bit
    $HostInformation.Applications.x32 | %{
        [PSCustomObject]@{
            "HostName"        = $HostInformation.OS.CSName;
            "Display Name"    = $_.DisplayName;
            "Display Version" = $_.DisplayVersion;
            "Publisher"       = $_.Publisher;
            "Install Date"    = $_.InstallDate;
            "Install Type"    = "32-Bit";
        }
    };
    # 64 Bit
    $HostInformation.Applications.x64 | %{
        [PSCustomObject]@{
            "HostName"        = $HostInformation.OS.CSName;
            "Display Name"    = $_.DisplayName;
            "Display Version" = $_.DisplayVersion;
            "Publisher"       = $_.Publisher;
            "Install Date"    = $_.InstallDate;
            "Install Type"    = "64-Bit";
        }
    };
)

# Windows Features
$WindowsFeatures = $HostInformation.RolesAndFeatures | ?{$_.Installed} | Sort -Property Path | %{
    [PSCustomObject]@{
        "HostName"     = $HostInformation.OS.CSName;
        "Display Name" = $_.DisplayName;
        "Name"         = $_.Name;
        "Feature Type" = $_.FeatureType;
        "Path"         = $_.Path;
        "Subfeatures"  = $_.Subfeatures;
    }
}


# Scheduled Tasks
$ScheduledTasks = $HostInformation.ScheduledTasks | %{
    [PSCustomObject]@{
        "HostName"      = $HostInformation.OS.CSName;
        "Name"          = $_.Name;
        "Enabled"       = $_.Enabled;
        "Actions"       = $_.Actions;
        "Last Run Time" = $_.LastRunTime;
        "Last Result"   = $_.LastResult;
    }
}

# Export
$Information  | Export-CSV -Path "$ExportFolder\00_HostInformation.csv" -NoTypeInformation;
$NetworkInterfaces  | Export-CSV -Path "$ExportFolder\01_NetworkInterfaces.csv" -NoTypeInformation;
$FirewallRules  | Export-CSV -Path "$ExportFolder\02_FirewallRules.csv" -NoTypeInformation;
$TLSCertificates  | Export-CSV -Path "$ExportFolder\03_TLSCertificates.csv" -NoTypeInformation;
$StorageDisks  | Export-CSV -Path "$ExportFolder\04_StorageDisks.csv" -NoTypeInformation;
$StorageVolumes  | Export-CSV -Path "$ExportFolder\05_StorageVolumes.csv" -NoTypeInformation;
$SharedFolders  | Export-CSV -Path "$ExportFolder\06_SharedFolders.csv" -NoTypeInformation;
$Applications  | Export-CSV -Path "$ExportFolder\07_Applications.csv" -NoTypeInformation;
$WindowsFeatures  | Export-CSV -Path "$ExportFolder\08_WindowsFeatures.csv" -NoTypeInformation;
$ScheduledTasks | Export-CSV -Path "$ExportFolder\09_ScheduledTasks.csv" -NoTypeInformation;