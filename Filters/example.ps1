[Cmdletbinding()]
Param(
    [Parameter(Mandatory=$True,ValueFromPipeline=$True)]
    [ValidateNotNullOrEmpty()]
    [PSCustomObject]$HostInformation
)

#---------[ Global Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Trigger so we know something went wrong during the process
$WarningTrigger = $False;

#---------[ Imports ]---------

# Import our functions from the lib module
try {
    Write-Host "Importing functions library: " -ForegroundColor Yellow -NoNewline;
    Import-Module ".\Lib\Audit\Audit-Functions.psm1" -DisableNameChecking;
    Write-Host "Succeeded." -ForegroundColor Green;
}
catch {
    # Can't use Write-ShellMessage here
    $Message = "There was a problem attempting to import the functions library: $($_.Exception.Message)";
    Write-Host $Message -ForegroundColor Red;
    Exit(1);
}

# Import the ImportExcel module
try {
    Write-Host "Importing ImportExcel library: " -ForegroundColor Yellow -NoNewline;
    Import-Module ImportExcel;
    Write-Host "Succeeded." -ForegroundColor Green;
}
catch {
    # Failed
    $Message = "There was a problem attempting to import the ImportExcel module: $($_.Exception.Message) ";
    $Message += "Please make sure this module is installed prior to filtering your Audit data (https://github.com/dfinke/ImportExcel).";
    Write-Host $Message -ForegroundColor Red;
    Exit(1);
}

#---------[ Main() ]---------

# Build the filter object
try {
    Write-ShellMessage -Message "Building output object" -Type INFO;
    $Filter = New-Object PSCustomObject -Property @{
        "00_SystemInformation" = $([PSCustomObject]@{
            "HostName"                  = $HostInformation.Win32_OperatingSystem.Hostname;
            "Domain Name"               = $HostInformation.Win32_ComputerSystem.Domain;
            "IPv4 Address"              = $((($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.IPAddress} | select IPAddress).IPAddress|?{$_| Is-Ipv4Address}) -Join ",");
            "OS"                        = $HostInformation.Win32_OperatingSystem.Caption;
            "Uptime"                    = $(Get-DateTimeDifference -CompareDateTime $([Management.ManagementDateTimeConverter]::ToDateTime($HostInformation.Win32_OperatingSystem.LastBootUpTime)));
            "Region/Locale"             = $(Get-LocaleFromWMICode -WMILocaleCode $HostInformation.Win32_OperatingSystem.Locale);
            "Timezone"                  = $(Get-TimeZoneDisplayName -UTCOffsetMinutes $HostInformation.Win32_OperatingSystem.CurrentTimeZone);
            "System Type"               = $(Switch ($HostInformation.Win32_ComputerSystem.Model) {
                                            "Virtual Machine" {"Hyper-V Virtual Machine"; $V = $True}
                                            "VMware Virtual Platform" {"VMWare Virtual Machine"; $V = $True}
                                            "VirtualBox" {"Oracle VM VirtualBox"; $V = $True}
                                            "HVM domU" {"Xen Hypervisor"; $V = $True}
                                            default {$HostInformation.Win32_ComputerSystem.Model; $V = $False}
                                          });
            "Make"                      = $HostInformation.Win32_ComputerSystem.Manufacturer;
            "Model"                     = $HostInformation.Win32_ComputerSystem.Model;
            "Service Tag"               = $HostInformation.Win32_BIOS.SerialNumber;
			"BIOS Info"                 = $HostInformation.Win32_BIOS.Name;
            "Asset Tag"                 = $HostInformation.cim_chassis.SMBIOSAssetTag;
            "PowerShell Version"        = $HostInformation.SystemProperties.PowerShellVersion;
            ".NET Version"              = $HostInformation.SystemProperties.DotNetVersion;
            "CPU"                       = $(($HostInformation.Win32_Processor.Name | Select -First 1) + " x$($HostInformation.Win32_Processor.Name.Count)");
            "Total Physical Memory"     = [Math]::Round($HostInformation.Win32_ComputerSystem.TotalPhysicalMemory / 1MB,2).ToString() + " MB";
            "Available Physical Memory" = [Math]::Round($HostInformation.Win32_OperatingSystem.FreePhysicalMemory / 1MB,2).ToString() + " MB";
            "Virtual Memory Max Size"   = [Math]::Round($HostInformation.Win32_OperatingSystem.TotalVirtualMemorySize / 1MB,2).ToString() + " MB";
            "Virtual Memory Available"  = [Math]::Round($HostInformation.Win32_OperatingSystem.FreeVirtualMemory / 1MB,2).ToString() + " MB";;
            "Virtual Memory InUse"      = [Math]::Round($($HostInformation.Win32_OperatingSystem.TotalVirtualMemorySize - $HostInformation.OperatingSystem.FreeVirtualMemory) / 1MB,2).ToString() + " MB";
            "Is Virtual Machine"        = $V
        });
        "01_NetworkInterfaces" = $($HostInformation.Win32_NetworkAdapter | %{
            $Index = $_.Index;
            [PSCustomObject]@{
                "HostName"      = $HostInformation.Win32_OperatingSystem.Hostname;
                "Description"   = $_.Description
                "Adapter Index" = $Index;
                "IPv4 Address"  = $((($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index}).IPAddress | ?{Is-Ipv4Address $_}) -Join  ", ");
                "IPv6 Address"  = $((($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index}).IPAddress | ?{Is-Ipv6Address $_}) -Join  ", ");
                "Domain Name"   = $($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index} | Select -ExpandProperty DnsDomain);
                "Subnet Mask"   = $(($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index}).IpSubnet | Select -First 1);
                "Gateway"       = $(($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index}).DefaultIPGateway -Join ", ");
                "DNS Servers"   = $(($HostInformation.Win32_NetworkAdapterConfiguration | ?{$_.MachineIdentifier -eq $HostInformation.Win32_OperatingSystem.MachineIdentifier -and $_.Index -eq $Index}).DNSServerSearchOrder -Join ", ");
            }
        });
        "02_FirewallRules" = $($HostInformation.FirewallRules | %{
            [PSCustomObject]@{
                "HostName"      = $HostInformation.Win32_OperatingSystem.Hostname;
                "Name" = $_.Name
                "Local Ports" = $_.LocalPorts
                "Remote Ports" = $_.RemotePorts
                "Local Addresses" = $_.LocalAddresses
                "Remote Addresses" = $_.RemoteAddresses
                "Direction" = $_.Direction;
            }
        });
        "03_TLSCertificates" = $($HostInformation.TLSCertificates | ?{!$_.PSIsContainer} | %{
            [PSCustomObject]@{
                "HostName"        = $HostInformation.Win32_OperatingSystem.Hostname;
                "Friendly Name"   = $_.FriendlyName;
                "Expires"         = $_.NotAfter;
                "Thumbprint"      = $_.Thumbprint;
                "Has Private Key" = $_.HasPrivateKey;
                "Issuer"          = $_.Issuer;
            }
        });
        "04_StorageDisks" = $($HostInformation.Win32_DiskDrive | %{
            [PSCustomObject]@{
                "HostName"       = $HostInformation.Win32_OperatingSystem.Hostname;
                "Disk Type"      = $_.Caption;
                "Interface Type" = $_.InterfaceType;
                "Media Type"     = $_.MediaType;
                "Size"           = $([Math]::Round(($_.Size / 1GB)).ToString() + " GB");
            }
        });
        "05_StorageVolumes" = $($HostInformation.Win32_Volume | %{
            [PSCustomObject]@{
                "HostName"          = $HostInformation.Win32_OperatingSystem.Hostname;
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
        "06_SharedFoldersandDrives" = $(
            # Shared folders
            $HostInformation.Win32_Share | %{
                $ShareName = $_.Name;
                [PSCustomObject]@{
                    "HostName"                  = $HostInformation.Win32_OperatingSystem.Hostname;
                    "Shared Folder Path"        = $_.Path;
                    "Shared Folder Name"        = $_.Name;
                    "Shared Folder Description" = $_.Description;
                    "Shared Folder Permissions" = $(($HostInformation.Win32_LogicalShareSecuritySetting | ?{$_.ShareName -eq $ShareName} | Select @{Name="SharePermissions";Expression={"$($_.IdentityReference) - $($_.FileSystemRights) - $($_.AccessControlType)"}}).SharePermissions -join ", ");
                    "Mounted Drive Path"        = "N/A";
                    "Mounted Drive Letter"      = "N/A";
                }
            };
            # Mounted drives
            $HostInformation.Win32_MappedLogicalDisk | %{
                [PSCustomObject]@{
                    "HostName"                  = $HostInformation.Win32_OperatingSystem.Hostname;
                    "Shared Folder Path"        = "N/A";
                    "Shared Folder Name"        = "N/A";
                    "Shared Folder Description" = "N/A";
                    "Shared Folder Permissions" = "N/A";
                    "Mounted Drive Path"        = $_.ProviderName;
                    "Mounted Drive Letter"      = $_.Name;
                }
            };
        );
        "07_Applications" = $($HostInformation.Applications | %{
            [PSCustomObject]@{
                "HostName"        = $HostInformation.Win32_OperatingSystem.Hostname;
                "Display Name"    = $_.DisplayName;
                "Display Version" = $_.DisplayVersion;
                "Publisher"       = $_.Publisher;
                "Install Date"    = $_.InstallDate;
                "Help Link"       = $_.HelpLink;
            }
        });
        "08_WindowsFeatures" = $($HostInformation.RolesAndFeatures | ?{$_.Installed} | Sort -Property Path | %{
            [PSCustomObject]@{
                "HostName"     = $HostInformation.Win32_OperatingSystem.Hostname;
                "Display Name" = $_.DisplayName;
                "Name"         = $_.Name;
                "Feature Type" = $_.FeatureType;
                "Path"         = $_.Path;
                "Subfeatures"  = $($_.Subfeatures -join ", ");
            }
        });
        "09_ScheduledTasks" = $($HostInformation.ScheduledTasks | %{
            [PSCustomObject]@{
                "HostName"      = $HostInformation.Win32_OperatingSystem.Hostname;
                "Name"          = $_.Name;
                "Enabled"       = $_.Enabled;
                "Actions"       = $_.TaskToRun;
                "Last Run Time" = $_.LastRunTime;
                "Last Result"   = $_.LastResult;
            }
        });
        "10_USBdevices" = $($HostInformation.Win32_USBControllerDevice | %{
            [PSCustomObject]@{
                "HostName"     = $HostInformation.Win32_OperatingSystem.Hostname;
                "Name"         = $_.Name;
                "Caption"      = $_.Caption;
                "Description"  = $_.Description;
                "Manufacturer" = $_.Manufacturer;
                "Service"      = $_.Service;
                "Status"       = $_.Status;
            }
        });
        "11_Serialdevices" = $($HostInformation.Win32_PNPEntity | ?{$_.ClassGuid -eq "{4d36e978-e325-11ce-bfc1-08002be10318}"} | %{
            [PSCustomObject]@{
                "HostName"     = $HostInformation.Win32_OperatingSystem.Hostname;
                "Caption"      = $_.Caption;
                "Name"         = $_.Name;
                "PNP Device ID" = $_.PNPDeviceID;
                "Status"       = $_.Status;
            }
        });
        "12_IISInformation" = $($HostInformation.IISSites | %{
            $SiteName = $_.Name;
            if ($_) {
                [PSCustomObject]@{
                    "HostName"         = $HostInformation.Win32_OperatingSystem.Hostname;
                    "Site Name"        = $_.Name;
                    "Bindings"         = $((($_.Bindings -Replace "P=","Protocol=") -Replace "B=","Ports=") -Replace "S=","SSL=");
                    "Physical Path"    = $_.PhysicalPath;
                    "Folder Dependencies" = $(($HostInformation.IISSitesConfiguration | ?{$_.Name -eq $SiteName} | %{
                        if ($_){
                            $Content = $_.ConfigurationFileContent.Split("`r`n");
                            $Content | ?{$_ -match "^((\\\\[a-zA-Z0-9-]+\\[a-zA-Z0-9`~!@#$%^&(){}'._-]+([ ]+[a-zA-Z0-9`~!@#$%^&(){}'._-]+)*)|([a-zA-Z]:))(\\[^ \\/:*?""<>|]+([ ]+[^ \\/:*?""<>|]+)*)*\\?$"};
                        }
                    }) -join ", ");
                    "SQL Dependencies" = $($HostInformation.IISSitesConfiguration | ?{$_.Name -eq $SiteName} | %{
                        $Content = $_.ConfigurationFileContent;
                        (Select-String '<([^>]*)>' -Input $Content -AllMatches | %{
                            $_.matches | ?{`
                                $_.Value.Contains(";") -and `
                                $_.Value -notlike "*<!--*" -and `
                                $(($_.Value.ToCharArray() | ?{$_ -eq ";"}).Length -gt 1) -and `
                                $_.Value -match "Data\ Source|Database|Initial\ Catalog" `
                        } | Select Value}).Value | %{
                            ($_ -split "=""") -split """" | ?{$_.Contains(";")} | %{
                                $R = New-Object PSCustomObject;
                                $SB = New-Object System.Data.Common.DbConnectionStringBuilder;
                                $SB.set_ConnectionString($_);
                                $SB.Keys | %{
                                    $P = $_;
                                    $R | Add-Member -MemberType NoteProperty -Name $P -Value $($SB."$($P)");
                                }
                                $R;
                            }
                        }
                    });
                    "Web Dependencies" = $(($HostInformation.IISSitesConfiguration | ?{$_.Name -eq $SiteName} | %{
                        if ($_){
                            $Content = $_.ConfigurationFileContent.Split("`r`n");
                            $Content | ?{$_ -match "http\://" -and $_ -notmatch "go\.microsoft\.com"};
                        }
                    }) -join ", ");
                }
            }
        });
        "13_DatabaseInformation" = $($HostInformation.SQLServerInstances | %{
            $Instance = $_;
            $Databases = $HostInformation.SQLServerDatabases.Where({$_.ConnectionIdentifier -eq $Instance.ConnectionIdentifier});
            $Databases | ?{$_.DBID} | %{
                $DBStatus = ($_.Status -split ", ");
                [PSCustomObject]@{
                    "HostName"                  = $HostInformation.Win32_OperatingSystem.Hostname;
                    "Instance Name"             = $Instance.InstanceName;
                    "Connection Identifier"     = $Instance.ConnectionIdentifier;
                    "SQL Version"               = $Instance.InstanceVersion;
                    "Is Accessible"             = $Instance.Accessible;
                    "DB Name"                   = $_.Name;
                    "DB Owner"                  = $_.Owner;
                    "DB Created Date"           = $_.CreatedDate;
                    "DB Compatibility Level"    = $_.CompatibilityLevel;
                    "DB ID"                     = $_.DBID;
                    "DB Size"                   = $_.Size;
                    "DB Status"                 = ($DBStatus.Where({$_ -like "status*"}) -Split "=")[1]
                    "DB Updateability"          = ($DBStatus.Where({$_ -like "Updateability*"}) -Split "=")[1];
                    "DB User Access"            = ($DBStatus.Where({$_ -like "UserAccess*"}) -Split "=")[1];
                    "DB Recovery Mode"          = ($DBStatus.Where({$_ -like "Recovery*"}) -Split "=")[1];
                    "DB Version"                = ($DBStatus.Where({$_ -like "Version*"}) -Split "=")[1];
                    "DB Collation"              = ($DBStatus.Where({$_ -like "Collation*"}) -Split "=")[1];
                    "DB Sort Order"             = ($DBStatus.Where({$_ -like "SQLSortOrder*"}) -Split "=")[1];
                    "DB Auto Create Statistics" = ($DBStatus.Where({$_ -like "IsAutoCreateStatistics*"}) -Split "=")[0] -eq "IsAutoCreateStatistics";
                    "DB Auto Update Statistics" = ($DBStatus.Where({$_ -like "IsAutoUpdateStatistics*"}) -Split "=")[0] -eq "IsAutoUpdateStatistics";
                }
            }
        });
        "14_WindowsUpdates" = $($HostInformation.WindowsUpdates | %{
            [PSCustomObject]@{
                "HostName"    = $HostInformation.Win32_OperatingSystem.Hostname;
                Description = $_.Description
                ServicePackInEffect = $_.ServicePackInEffect;
                FixComments = $_.FixComments;
                InstalledOn = $_.InstalledOn;
                Caption = $_.Caption;
                Name = $_.Name;
                HotFixID = $_.HotFixID;
                Status = $_.Status;
                InstallDate = $_.InstallDate;
                InstalledBy = $_.InstalledBy;
            }
        });
        "15_NetworkTopology" = $($HostInformation.NetworkConnections | %{
            [PSCustomObject]@{
                HostName           = $HostInformation.Win32_OperatingSystem.Hostname;
                Protocol           = $_.Protocol;
                LocalAddress       = $_.LocalAddress;
                LocalPort          = $_.LocalPort;
                RemoteAddress      = $_.RemoteAddress;
                RemotePort         = $_.RemotePort;
                State              = $_.State;
                ProcessID          = $_.ProcessID;
                ProcessName        = $_.ProcessName;
                ProcessDescription = $_.ProcessDescription;
                ProcessProduct     = $_.ProcessProduct;
                ProcessFileVersion = $_.ProcessFileVersion;
                ProcessExePath     = $_.ProcessExePath;
                ProcessCompany     = $_.ProcessCompany;
            }
        });
    }
}
catch {
    Write-ShellMessage -Message "There was a problem building the output object" -Type ERROR -ErrorRecord $_;
    Exit(1);
}

# Now we need to eumerate the $Filter object's properties and write out
Write-ShellMessage -Message "Begining data write to disk" -Type INFO;
$Filter.PSObject.Properties | Sort -Property Name | %{
    
    try {
        # Get the section name and value
        $SectionName = $_.Name;
        $SectionValue = $_.Value | Select -Property *;

        # Get the hostname for error writing and define the output file
        $HostName = $HostInformation.Win32_OperatingSystem.Hostname
        $FilePath = (Resolve-Path $($MyInvocation.PSScriptRoot + "\..\")).Path + "Filtered-Windows-Audit-Data.xlsx";

        # Export to File
        if ($SectionValue) {
            Write-ShellMessage -Message "Exporting '$SectionName' to '$FilePath' for host '$HostName'" -Type INFO;
            Export-Excel -Path $FilePath -WorkSheetname $SectionName -TargetData $SectionValue -Append;
        }
        else {
            Write-ShellMessage -Message "Section '$SectionName' for host '$HostName' is null; skipping" -Type WARNING;
        }
    }
    catch {
        # Write out and set our warning trigger
        Write-ShellMessage -Message "There was an error attempting to compile data for '$Hostname' and write it to disk" -Type ERROR -ErrorRecord $_;
        $WarningTrigger = $True;
    }
}

#---------[ Fin ]---------

if ($WarningTrigger) {
    $FinalMessage = "Audit data compilation has completed with warnings";
    Write-ShellMessage -Message $FinalMessage -Type WARNING;
}
else {
    $FinalMessage = "Audit data compilation has completed successfully";
    Write-ShellMessage -Message $FinalMessage -Type SUCCESS;
}

Exit;