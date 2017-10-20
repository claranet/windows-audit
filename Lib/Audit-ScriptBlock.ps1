#---------[ Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Get our return object sorted out
$HostInformation = New-Object PSCustomObject;

#---------[ Functions ]---------

# Easy add-member function
Function Add-HostInformation {
    [Cmdletbinding()]
    Param(
        # The name of the property we're adding
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,

        # The value of the property we're adding
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [Object]$Value
    )

    # Add the property to HostInformation
    $HostInformation | Add-Member -MemberType NoteProperty -Name $Name -Value $Value;

};

# Returns a PSCustomObject with parsed Scheduled Tasks for this system
Function Get-ScheduledTasksList {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]$Path = "\"
    )

    # Ok get our scheduled task COM object established and connected
    $Schedule = New-Object -ComObject "Schedule.Service";
    $Schedule.Connect();

    # Prepare an output array
    $ScheduledTasksListOutput = @();

    # Get root tasks
    $Schedule.GetFolder($Path).GetTasks(0) | % {    
        try {
            # Ok get the XML definition
            $XML = [XML]$_.Xml;

            # And add a PSCustomObject with the goodies to the output array
            $ScheduledTasksListOutput += $(New-Object PSCustomObject -Property @{
                "Name"        = $_.Name
                "Path"        = $_.Path
                "State"       = $_.State
                "Enabled"     = $_.Enabled
                "LastResult"  = $_.LastTaskResult
                "MissedRuns"  = $_.NumberOfMissedRuns
                "LastRunTime" = $_.LastRunTime
                "NextRunTime" = $_.NextRunTime
                "Actions"     = ($XML.Task.Actions.Exec | %{"$($_.Command) $($_.Arguments)"}) -join ", "
            })
        }
        catch {
            Write-Warning $Error[0].Exception.Message;
        }
    }

    # Get tasks from subfolders
    $Schedule.GetFolder($Path).GetFolders(0) | % {
        $ScheduledTasksListOutput += Get-ScheduledTasksList -Path $_.Path;
    }

    # Cleanup the trash before we go
    [Void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($Schedule));
    Remove-Variable Schedule;

    # And return
    return ,$ScheduledTasksListOutput;
}

# Returns a string indicating whether the machine is running on Azure or On-Prem
Function Locate-WindowsMachine {

    # Enumerate all the network adapters that have DHCP enabled
    Get-WmiObject -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled = 'True' AND DHCPEnabled ='True'" | Select SettingID | %{
        # Get the reg path into a variable for legibility
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\$($_.SettingID)";

        # Get the DHCP options set
        $DHCP = Get-ItemProperty -Path $RegPath -Name DhcpInterfaceOptions;

        # Check for the magic Azure only DHCP option
        if ($DHCP.DHCPInterfaceOptions -contains 245) {
            return "Azure";
        }
    }

    # If we get this far we're on prem
    return "On-Prem";
}

#---------[ OS ]---------
try {
    Write-Host "Gathering OS information" -ForegroundColor Cyan;
    Add-HostInformation -Name OS -Value $(Get-WMIObject -Class "Win32_OperatingSystem" | Select -Property *);
}
catch {
    Write-Host "Error gathering OS information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ System ]---------
try {
    Write-Host "Gathering system information" -ForegroundColor Cyan;

    # Get our system info object
    $SystemInfo = Get-WMIObject -Class "Win32_ComputerSystem" | Select -Property *;

    # Check to see what type of machine we're running
    Switch ($SystemInfo.Model) {
        "Virtual Machine" {
            $IsVirtualMachine = $True;
            $MachineType      = "Hyper-V Virtual Machine";
        }
        "VMware Virtual Platform" {
            $IsVirtualMachine = $True;
            $MachineType      = "VMWare Virtual Machine";
        }
        "VirtualBox" {
            $IsVirtualMachine = $True;
            $MachineType      = "Oracle VM VirtualBox";
        }
        "HVM domU" {
            $IsVirtualMachine = $True;
            $MachineType      = "Xen Hypervisor";
        }
        default {
            $IsVirtualMachine = $False;
            $MachineType      = $SystemInfo.Model;
        }
    };

    # And add to the collection
    Add-HostInformation -Name SystemInfo -Value $(New-Object PSCustomObject -Property @{
        Hostname         = $env:COMPUTERNAME;
        IsVirtualMachine = $IsVirtualMachine;
        MachineType      = $MachineType;
        SystemInfo       = $SystemInfo;
        Location         = $(Locate-WindowsMachine);
        CPUPercentInUse  = $([Math]::Round(((Get-Counter "\\$env:COMPUTERNAME\processor(_total)\% processor time" | Select CounterSamples).CounterSamples | Select CookedValue).CookedValue,2).ToString() + "%");
    });
}
catch {
    Write-Host "Error gathering system information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Compute ]---------
try {
    Write-Host "Gathering compute information" -ForegroundColor Cyan;
    Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor" | Select -Property *);
}
catch {
    Write-Host "Error gathering compute information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Memory ]---------
try {
    Write-Host "Gathering memory information" -ForegroundColor Cyan;
    
    # Get our output object initialised
    $WindowsMemory = New-Object PSCustomObject;

    # Enumerate the output of systeminfo and get what we want
    Invoke-Expression "systeminfo" | ?{$_ -like "*memory*"} | %{
        # Let's split out the spaces
        $String = $_.Replace(" ","");

        # And replace the first : when there are more than one
        if (($String.ToCharArray() | ?{$_ -eq ":"}).Count -gt 1) {
            $String = ([Regex]":").Replace($String,"",1);
        };

        # Add the k:v to the object we created earlier
        $WindowsMemory | Add-Member -MemberType NoteProperty -Name $String.Split(":")[0] -Value $String.Split(":")[1];   
    };

    # Note; Win32_PhysicalMemory is $Null on virtual machines
    Add-HostInformation -Name Memory -Value $(New-Object PSCustomObject -Property @{
        PhysicalMemory = $(Get-WMIObject -Class "Win32_PhysicalMemory" | Select -Property *);
        WindowsMemory  = $WindowsMemory;
    });
}
catch {
    Write-Host "Error gathering memory information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Storage ]---------
try {
    Write-Host "Gathering storage information" -ForegroundColor Cyan;
    Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
        PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive" | Select -Property *);
        LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk" | Select -Property *);
        Volumes       = $(Get-WMIObject -Class "Win32_Volume" | Select -Property *);
        SharedFolders = $(Get-WMIObject -Class "Win32_Share" | Select -Property *);
        MountedDrives = $(Get-WMIObject -Class "Win32_MappedLogicalDisk" | Select -Property *);
    });
}
catch {
    Write-Host "Error gathering storage information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Networking ]---------
try {
    Write-Host "Gathering networking information" -ForegroundColor Cyan;

    # Let's get the Com object established for the firewall rules, outvar to null to avoid ps misinterpretation
    $Firewall = New-Object -Com "HNetCfg.FwPolicy2" -OutVariable null;

    # And add to the hostinformation collection
    Add-HostInformation -Name Networking -Value $(New-Object PSCustomObject -Property @{
        AdapterInformation = $(Get-WMIObject -Class "Win32_NetworkAdapterConfiguration" | Select -Property *);
        Hostname           = $env:COMPUTERNAME;
        NTPConfiguration   = $(Invoke-Expression "w32tm /query /configuration");
        FirewallZone       = $(switch ($Firewall.CurrentProfileTypes) {1 {"Domain"};2 {"Private"};4 {"Public"}});
        FirewallRules      = $Firewall.Rules;
    });
}
catch {
    Write-Host "Error gathering networking information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Peripherals ]---------
try {
    Write-Host "Gathering peripherals information" -ForegroundColor Cyan;
    Add-HostInformation -Name Peripherals -Value $(New-Object PSCustomObject -Property @{
        USBDevices    = $(Get-WMIObject -Class "Win32_USBControllerDevice" | %{[Wmi]$_.Dependent} | Select -Property *);
        SerialDevices = $(Get-WMIObject -Class "Win32_SerialPort" | Select -Property *);
        Printers      = $(Get-WMIObject -Class "Win32_Printer" | Select -Property *);
    });
}
catch {
    Write-Host "Error gathering peripherals information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Applications ]---------
try {
    Write-Host "Gathering application information" -ForegroundColor Cyan;

    # Var up our regkeys and select criteria for legibility
    $x32Reg = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*";
    $x64Reg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*";
    $SelectCriteria = @("DisplayName","DisplayVersion","Publisher","InstallDate");

    # And add to the collection
    Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
        x32 = $(Get-ItemProperty $x32Reg | ?{![String]::IsNullOrEmpty($_.DisplayName)} | Select $SelectCriteria);
        x64 = $(Get-ItemProperty $x64Reg | ?{![String]::IsNullOrEmpty($_.DisplayName)} | Select $SelectCriteria);
    });
}
catch {
    Write-Host "Error gathering applications information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Roles & Features ]---------
try {
    # Check if Server or Workstation here as ServerManager isn't available on workstations
    if ($HostInformation.OS.Caption.ToLower().Contains("server")) {
        Write-Host "Gathering roles and features information" -ForegroundColor Cyan;

        # Import the servermanager module for the Get-WindowsFeature cmdlet
        Import-Module ServerManager;
        Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature | Select -Property *);
    };
}
catch {
    Write-Host "Error gathering roles and features information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ IIS ]---------
try {
    if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "Web-Server"}).Installed) {
        Write-Host "Gathering IIS information" -ForegroundColor Cyan;

        # Get the WebAdministration module imported
        Import-Module WebAdministration;

        # Now, we need to explicitly cast the outputs of the following
        # to PSCustomObjects as the IISConfigurationElement and other
        # types don't serialise properly.

        # Get the WebSites
        $WebSites = Get-WebSite | %{
            New-Object PSCustomObject -Property @{
                Name         = $_.Name;
                ID           = $_.ID;
                State        = $_.State;
                PhysicalPath = $_.PhysicalPath;
                Bindings     = @(,$($_.Bindings | %{$_.Collection}));
            }
        }

        # Get the Application Pools
        $ApplicationPools = gci "IIS:\AppPools" | Select -Property * | %{
            $Name = $_.Name;
            New-Object PSCustomObject -Property @{
                Name                  = $Name;
                State                 = $_.State;
                ManagedPipelineMode   = $_.ManagedPipelineMode;
                ManagedRuntimeVersion = $_.ManagedRuntimeVersion;
                StartMode             = $_.StartMode;
                AutoStart             = $_.AutoStart;
                Applications          = @(,$((Get-WebSite | ?{$_.applicationPool -eq $Name} | Select Name).Name));
            }
        }

        # Get the Bindings
        $WebBindings = Get-WebBinding | %{
            New-Object PSCustomObject -Property @{
                Protocol           = $_.protocol;
                BindingInformation = $_.bindingInformation;
            }
        }

        # Get the Virtual Directories
        $VirtualDirectories = Get-WebVirtualDirectory | %{
            New-Object PSObject -Property @{
                Name         = $_.Path.Split("/")[($_.Path.Split("/").Length)-1];
                Path         = $_.Path;
                PhysicalPath = $_.PhysicalPath;
            }
        }

        # Get a list .config files for each application so we can work out dependency chains
        $ConfigFiles = Get-ChildItem "IIS:\" -Recurse | ?{$_.Name -like "*.config"} | Select FullName;
        $ConfigFileContent = @();
        
        # If any are found, enumerate the collection and get the content
        $ConfigFiles | %{
            
            # Get the pipeline object
            $ConfigFile = $_;

            # Work out what website it belongs to
            $WebSite = (Get-WebSite | ?{$_.PhysicalPath -like "*$($ConfigFile.Directory.FullName)*"}).Name;

            # Add to the collection
            $ConfigFileContent += $(New-Object PSCustomObject -Property @{
                Site    = $WebSite;
                Path    = $ConfigFile.FullName;
                Content = $(Get-Content $ConfigFile.FullName | Out-String);
            });
        }

        # Add a collection containing our IIS trees to the hostinfo object
        Add-HostInformation -Name IISConfiguration -Value $(New-Object PSCustomObject -Property @{
            WebSites            = $WebSites;
            ApplicationPools    = $ApplicationPools;
            WebBindings         = $WebBindings;
            VirtualDirectories  = $VirtualDirectories;
            ConfigurationFiles  = $ConfigFileContent;
        });
    };
}
catch {
    Write-Host "Error gathering IIS information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ TLS Certificates ]---------
try {
    Write-Host "Gathering TLS Certificate information" -ForegroundColor Cyan;
        
    # Add a collection containing our certificate tree
    $TLSCertificates = $(Get-ChildItem "Cert:\LocalMachine" -Recurse | ?{!$_.PSIsContainer} | Select -Property *);
    Add-HostInformation -Name TLSCertificates -Value $TLSCertificates;
}
catch {
    Write-Host "Error gathering TLS Certificate information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Windows Updates ]---------
try {
    Write-Host "Gathering Windows Update information" -ForegroundColor Cyan;
        
    # Ok let's get our Microsoft Update com object established
    $Session = New-Object -ComObject "Microsoft.Update.Session";

    # Create an update searcher
    $Searcher = $Session.CreateUpdateSearcher();

    # Query the history count
    $HistoryCount = $Searcher.GetTotalHistoryCount();

    # RTM level if zero index, act accordingly
    if ($HistoryCount -gt 0) {
        $UpdateHistory = $Searcher.QueryHistory(0, $HistoryCount) | ?{![String]::IsNullOrEmpty($_.Title)} | Select Title, Description, Date,@{
            Name="Operation";Expression={Switch($_.operation){1 {"Installation"}; 2 {"Uninstallation"}; 3 {"Other"}}}
        };
    }
    else {
        # RTM; Set to false here so we can parse later
        $UpdateHistory = $False;
    }

    # Get the WSUS Server information, trapped as the key may not exist
    $RegKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\";
    try {
        $WSUSServer = (Get-ItemProperty -Path $RegKey -Name "WUServer").WUServer;
    }
    catch {
        $WSUSServer = "(None)";
    }

    # Add add our windows updates to the HostInformation object 
    Add-HostInformation -Name WindowsUpdates -Value $(New-Object PSCustomObject -Property @{
        UpdateHistory = $UpdateHistory;
        WSUSConfiguration = $WSUSServer;
    });
}
catch {
    Write-Host "Error gathering Windows Update information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ PowerShell, WinRM & .NET ]---------
try {
    Write-Host "Gathering management information" -ForegroundColor Cyan;
        
    # Get WinRM enabled state as we can use the bool to check/skip the protocol
    $WinRMEnabled = $((Test-WSMan -ErrorAction SilentlyContinue) -ne $Null); 

    # Add add our management info to the HostInformation object 
    Add-HostInformation -Name Management -Value $(New-Object PSCustomObject -Property @{
        PowerShellVersion = $($PSVersionTable.PSVersion.ToString());
        DotNetVersion     = $([System.Runtime.InteropServices.RuntimeEnvironment]::GetSystemVersion());
        WinRMEnabled      = $WinRMEnabled;
    });
}
catch {
    Write-Host "Error gathering management information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Scheduled Tasks ]---------
try {
    Write-Host "Gathering scheduled tasks information" -ForegroundColor Cyan;
    Add-HostInformation -Name ScheduledTasks -Value $(Get-ScheduledTasksList);
}
catch {
    Write-Host "Error gathering scheduled tasks information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Domain Controller ]---------
try {
    if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "AD-Domain-Services"}).Installed) {
        
        Write-Host "Gathering Active Directory Domain Controller information" -ForegroundColor Cyan;

        # Get the ActiveDirectory module imported
        Import-Module ActiveDirectory;

        # Add a collection containing our IIS trees to the hostinfo object
        Add-HostInformation -Name ActiveDirectoryDomainController -Value $(New-Object PSCustomObject -Property @{
            DomainController = $(Get-ADDomainController | Select -Property *);
            Domain           = $(Get-ADDomain | Select -Property *);
            Forest           = $(Get-ADForest | Select -Property *);
            DSE              = $(Get-ADRootDSE | Select -Property *);
            DCDiag           = $(Invoke-Expression "dcdiag");
        });
    };
}
catch {
    Write-Host "Error gathering Active Directory Domain Controller information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Database ]---------
try {
    if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        
        Write-Host "Gathering SQL Server information" -ForegroundColor Cyan;

        # Get the SQLPS module imported, trap just in case it's not installed properly
        try {
            [Void](Import-Module SQLPS -DisableNameChecking -WarningAction SilentlyContinue);
        }
        catch {
            # Let's get the latest version of SQL from whichever directory SQL is installed in
            if (Test-Path "C:\Program Files\Microsoft SQL Server") {
                $V = ((gci "C:\Program Files\Microsoft SQL Server" | ?{$_.Name -match "^\d+$"}).Name | Measure -Maximum).Maximum;
            }
            else {
                $V = ((gci "C:\Program Files (x86)\Microsoft SQL Server" | ?{$_.Name -match "^\d+$"}).Name | Measure -Maximum).Maximum;
            }

            # Add snapin method, this will throw into the outer catch if it fails
            Invoke-Expression "Add-PSSnapin SqlServerProviderSnapin$V";
        }

        # Get a list of databases
        $DatabaseList = $((Invoke-SQLCMD -Query "SELECT NAME FROM SYS.DATABASES" -Server $env:computername -Database "Master").Name);
        
        # Get some help information for the databases
        $DatabaseInformation = New-Object PSCustomObject;
        $DatabaseList | %{
            # Get the database name
            $DatabaseName = $_;

            # Add the information object to the collection
            $DatabaseInformation += $(New-Object PSCustomObject -Property @{
                DatabaseName        = $DatabaseName;
                DatabaseInformation = $(Invoke-SQLCMD -Query "EXEC SP_HELPDB '$DatabaseName'" -Server $env:computername -Database "Master");
            })
        };

        # Add a collection containing our IIS trees to the hostinfo object
        Add-HostInformation -Name SQLServer -Value $(New-Object PSCustomObject -Property @{
            DatabaseList        = $Databases;
            DatabaseInformation = $DatabaseInformation;
        });
    };
}
catch {
    Write-Host "Error gathering SQL Server information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Apache Virtual Hosts ]---------
try {
    if (Get-Service | ?{$_.Name -like "*Apache*" -and $_.Name -notlike "*Tomcat*"}) {
        
        Write-Host "Gathering Apache Virtual Host information" -ForegroundColor Cyan;

        # Get the Apache install and httpd.exe paths
        $ApachePath = $((Get-ChildItem "C:\Program Files (x86)\*Apache*").FullName);
        $Httpd      = $((Get-ChildItem $ApachePath "httpd.exe" | Select -First 1).FullName);

        if ($Httpd) {
            # Add a collection containing our Apache tree to the hostinfo object
            Add-HostInformation -Name ApacheVirtualHosts -Value $((Invoke-Expression "$httpd -S").Split("`r`n"));
        }
        else {
            throw "Couldn't locate Apache httpd.exe";
        }
    }
}
catch {
    Write-Host "Error gathering Apache Virtual Host information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Tomcat Web Applications ]---------
try {
    if (Get-Service | ?{$_.Name -like "*Tomcat*"}) {
        Write-Host "Gathering Tomcat application information" -ForegroundColor Cyan;

        # Add a collection containing our Tomcat tree to the hostinfo object
        $TomcatApplications = $((New-Object System.Net.WebClient).DownloadString("http://localhost:8080/manager/text/list").Split("`r`n"));
        Add-HostInformation -Name TomcatApplications -Value $TomcatApplications;
    }
}
catch {
    Write-Host "Error gathering Tomcat application information: " + $Error[0].Exception.Message -ForegroundColor Red;
}

#---------[ Return ]---------
Write-Host "Gathering completed" -ForegroundColor Green;
return $HostInformation;