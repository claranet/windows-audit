[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

# Import the functions module
Import-Module ".\Lib\Audit-Functions.psm1" -DisableNameChecking;

<# 
    The filter needs to be defined as a single PSCustomObject, with named key/value
    pairs indicating the name (key) of the section you wish to create, along with the
    actual content (value) of that section. Each section will become a worksheet in
    the final output file.
#> 
$Output = New-Object PSCustomObject -Property @{
    "00_System Information" = $([PSCustomObject]@{
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
    });
    "01_Network Interfaces" = $($HostInformation.Networking.AdapterInformation | %{
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
    });
    "02_Firewall Rules" = $($HostInformation.Networking.FirewallRules | %{
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
    });
    "03_TLS Certificates" = $($HostInformation.TLSCertificates | ?{!$_.PSIsContainer} | %{
        [PSCustomObject]@{
            "HostName"        = $HostInformation.OS.CSName;
            "Friendly Name"   = $_.FriendlyName;
            "Expires"         = $_.NotAfter;
            "Thumbprint"      = $_.Thumbprint;
            "Has Private Key" = $_.HasPrivateKey;
            "Issuer"          = $_.Issuer;
        }
    });
    "04_Storage Disks" = $($HostInformation.Storage.PhysicalDisks | %{
        [PSCustomObject]@{
            "HostName"       = $HostInformation.OS.CSName;
            "Disk Type"      = $_.Caption;
            "Interface Type" = $_.InterfaceType;
            "Media Type"     = $_.MediaType;
            "Size"           = $([Math]::Round(($_.Size / 1GB)).ToString() + " GB");
        }
    });
    "05_Storage Volumes" = $($HostInformation.Storage.Volumes | %{
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
    });
    "06_Shared Folders and Drives" = $(
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
    );
    "07_Applications" = $(
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
    );
    "08_Windows Features" = $($HostInformation.RolesAndFeatures | ?{$_.Installed} | Sort -Property Path | %{
        [PSCustomObject]@{
            "HostName"     = $HostInformation.OS.CSName;
            "Display Name" = $_.DisplayName;
            "Name"         = $_.Name;
            "Feature Type" = $_.FeatureType;
            "Path"         = $_.Path;
            "Subfeatures"  = $_.Subfeatures;
        }
    });
    "09_Scheduled Tasks" = $($HostInformation.ScheduledTasks | %{
        [PSCustomObject]@{
            "HostName"      = $HostInformation.OS.CSName;
            "Name"          = $_.Name;
            "Enabled"       = $_.Enabled;
            "Actions"       = $_.Actions;
            "Last Run Time" = $_.LastRunTime;
            "Last Result"   = $_.LastResult;
        }
    });
}

# Let's get our destination output folder created
$ExportFolder = ".\Output\Processed";
if (!(Test-Path $ExportFolder)) {
    [Void](New-Item $ExportFolder -ItemType Directory -Force);
}

# Now we need to eumerate the $Output object's properties and write out
$Output.PSObject.Properties | Sort -Property Name | %{
    
    # Get the section name and value
    $SectionName = $_.Name;
    $SectionValue = $_.Value | Select -Property *;

    # Work out the export file path
    $FilePath = "$ExportFolder\$($HostInformation.OS.CSName).xlsx";

    # Export to File
    if ($SectionValue) {
        $SectionValue | .\Lib\Export-XLSX.ps1 -Path $FilePath -WorksheetName $SectionName -Append;
    }
    else {
        "(None)" | .\Lib\Export-XLSX.ps1 -Path ".\Windows-Audit-Output.csv" -WorksheetName $SectionName -Append;
    }
}