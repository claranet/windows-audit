Param([Switch]$X)

#---------[ Declarations ]---------

# EAP to stop so we can trap errors in catch blocks
$ErrorActionPreference = "Stop";

# Get our return object sorted out
$HostInformation = New-Object PSCustomObject;

# Get the execution policy value and set to unrestructed
$ExecutionPolicy = Get-ExecutionPolicy;
Set-ExecutionPolicy Unrestricted -Force;

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

    try {
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
    catch {
        # Seems a bit flippant but if this regkey doesn't exist it's < 2008, not Azure.
        return "On-Prem";
    }
}

# Writes pretty log messages
Function Write-ShellMessage {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Message,
        [Parameter(Mandatory=$True)]
        [ValidateSet("DEBUG","INFO","WARNING","SUCCESS","ERROR")]
        [String]$Type,
        [Parameter(Mandatory=$False)]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    # Get a datestamp sorted
    $DateStamp = Get-Date -Format "dd/MM/yy HH:mm:ss";

    # Build our message output
    $Output = [String]::Format("[{0}] [{1}:{2}]: {3}",$DateStamp,$env:COMPUTERNAME,$Type,$Message);
    
    # If we have an ErrorRecord attach the message at the end
    if ($ErrorRecord) {
        $Output += ": $($ErrorRecord.Exception.Message)";
    }

    # Swiffy to determine colour
    Switch ($Type) {
        "DEBUG"   {$C = "Magenta"};
        "INFO"    {$C = "Cyan"};
        "WARNING" {$C = "Yellow"};
        "SUCCESS" {$C = "Green"};
        "ERROR"   {$C = "Red"};
    }

    # And write out
    Write-Host $Output -ForegroundColor $C;
}

# Alternative firewall rule gathering for Server 2003
Function Get-NetshFireWallRule  {
    
    # Get our return array sorted
    $Return = @();

    # Get a new ordered hash in place so we can add values easily
    # Nullify the values we can't get from netsh advfirewall
    $Hash = @{
        Description                 = $Null;
        ApplicationName             = $Null;
        serviceName                 = $Null;
        IcmpTypesAndCodes           = $Null;
        Interfaces                  = $Null;
        InterfaceTypes              = $Null;
        Action                      = $Null;
        EdgeTraversalOptions        = $Null;
        LocalAppPackageId           = $Null;
        LocalUserOwner              = $Null;
        LocalUserAuthorizedList     = $Null;
        RemoteUserAuthorizedList    = $Null;
        RemoteMachineAuthorizedList = $Null;
        SecureFlags                 = $Null;
    };
        
    # Enumerate the output from netsh advfirewall
    ForEach ($Rule in $(netsh advfirewall firewall show rule name="all")) {

        # If the line isn't a separator, parse and add
        if ($Rule -notmatch "----------------------------------------------------------------------"){
            switch -Regex ($Rule){
                '^Rule Name:\s+(?<RuleName>.*$)'   {$Hash.Name            = $Matches.RuleName;Break}
                '^Enabled:\s+(?<Enabled>.*$)'      {$Hash.Enabled         = $Matches.Enabled;Break}
                '^Direction:\s+(?<Direction>.*$)'  {$Hash.Direction       = $Matches.Direction;Break}
                '^Profiles:\s+(?<Profiles>.*$)'    {$Hash.Profiles        = $Matches.Profiles;Break}
                '^Grouping:\s+(?<Grouping>.*$)'    {$Hash.Grouping        = $Matches.Grouping;Break}
                '^LocalIP:\s+(?<LocalIP>.*$)'      {$Hash.LocalAddresses  = $Matches.LocalIP;Break}
                '^RemoteIP:\s+(?<RemoteIP>.*$)'    {$Hash.RemoteAddresses = $Matches.RemoteIP;Break}
                '^Protocol:\s+(?<Protocol>.*$)'    {$Hash.Protocol        = $Matches.Protocol;Break}
                '^LocalPort:\s+(?<LocalPort>.*$)'  {$Hash.LocalPorts      = $Matches.LocalPort;Break}
                '^RemotePort:\s+(?<RemotePort>.*$)'{$Hash.RemotePorts     = $Matches.RemotePort;Break}
                '^Edge traversal:\s+(?<Edge_traversal>.*$)' {
                    $Hash.EdgeTraversal = $Matches.Edge_traversal;
                    $Return += $(New-Object psobject -Property $Hash);
                    Break;
                }
            }
        }
    }
    
    # And return our array
    return $return
}

# Gets enabled firewall zones from netsh
Function Get-NetshFireWallProfile {

    # Get our netsh command and return object
    $NETSH    = netsh advfirewall show allprofiles;
    $Profiles = @();

    # Work out which are enabled
    if ($Domain = $NETSH | Select-String "Domain Profile" -Context 2 | Out-String) {
        if (($Domain.Substring($Domain.Length-9).Trim() -eq "ON")) {
            $Profiles += "Domain";
        }
    }
    if ($Private = $NETSH | Select-String "Private Profile" -Context 2 | Out-String) {
        if (($Private.Substring($Private.Length-9).Trim() -eq "ON")) {
            $Profiles += "Private";
        }
    }
    if ($Public = $NETSH | Select-String "Public Profile" -Context 2 | Out-String) {
        if (($Public.Substring($Public.Length-9).Trim() -eq "ON")) {
            $Profiles += "Public";
        }
    }

    # Work out if any of them are enabled and return
    if ($Profiles) {
        return $Profiles -Join ",";
    }
    else {
        return "None";
    }
}

# Custom SQl query function to avoid management tools dependency
Function Invoke-SQLQuery {
    [Cmdletbinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$ServerName,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Database,

        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Query
    )

    # Get our return table initialised
    $Datatable = New-Object System.Data.DataTable;
    
    # Get our connection sorted out
    $Connection = New-Object System.Data.SQLClient.SQLConnection;
    $Connection.ConnectionString = "server='$ServerName';database='$Database';trusted_connection=true;";
    $Connection.Open();

    # Get the SQL command ready to execute
    $Command = New-Object System.Data.SQLClient.SQLCommand;
    $Command.Connection = $Connection;
    $Command.CommandText = $Query;

    # Execute the reader command and load the datatable we created earlier
    $Reader = $Command.ExecuteReader();
    $Datatable.Load($Reader);

    # Close off the connection
    $Connection.Close();
    
    # And return
    return $Datatable;
}


#---------[ OS ]---------
try {
    Write-ShellMessage -Message "Gathering OS information" -Type INFO;
    Add-HostInformation -Name OS -Value $(Get-WMIObject -Class "Win32_OperatingSystem" | Select -Property *);
}
catch {
    Write-ShellMessage -Message "Error gathering OS information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ BIOS ]---------
try {
    Write-ShellMessage -Message "Gathering BIOS information" -Type INFO;
    Add-HostInformation -Name BIOS -Value $(Get-WMIObject -Class "Win32_BIOS" | Select -Property *);
}
catch {
    Write-ShellMessage -Message "Error gathering BIOS information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Chassis/Hardware ]---------
try {
    Write-ShellMessage -Message "Gathering hardware information" -Type INFO;
    Add-HostInformation -Name Hardware -Value $(Get-WMIObject -Class "Cim_Chassis" | Select -Property *);
}
catch {
    Write-ShellMessage -Message "Error gathering hardware information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ System ]---------
try {
    Write-ShellMessage -Message "Gathering system information" -Type INFO;

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

    # Get the CPU usage, trapped in case of negative value exception
    try {
        $CounterPath = "\\$env:COMPUTERNAME\processor(_total)\% processor time";
        $CounterValue = ((Get-Counter $CounterPath | Select CounterSamples).CounterSamples | Select CookedValue).CookedValue;
        $CPUPercentage = $([Math]::Round($CounterValue,2).ToString() + "%");
    }
    catch {
        $CPUPercentage = "0%";
    }

    # And add to the collection
    Add-HostInformation -Name SystemInfo -Value $(New-Object PSCustomObject -Property @{
        Hostname         = $env:COMPUTERNAME;
        IsVirtualMachine = $IsVirtualMachine;
        MachineType      = $MachineType;
        SystemInfo       = $SystemInfo;
        Location         = $(Locate-WindowsMachine);
        CPUPercentInUse  = $CPUPercentage;
    });
}
catch {
    Write-ShellMessage -Message "Error gathering system information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Compute ]---------
try {
    Write-ShellMessage -Message "Gathering compute information" -Type INFO;
    Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor" | Select -Property *);
}
catch {
    Write-ShellMessage -Message "Error gathering compute information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Memory ]---------
try {
    Write-ShellMessage -Message "Gathering memory information" -Type INFO;
    
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
    Write-ShellMessage -Message "Error gathering memory information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Storage ]---------
try {
    Write-ShellMessage -Message "Gathering storage information" -Type INFO;

    # Get the original Win32_Share collection and create an output object to hold our version
    $WMIShares = $(Get-WMIObject -Class "Win32_Share" | Select -Property *);
    $CustomShares = @();

    # Enumerate the shares from WMI
    $WMIShares | Select Name | %{
        
        # Get the sharename
        $ShareName = $_.Name;
        
        # Get some share permission information
        $Expr = "net share '" + $ShareName + "'";
        $ShareInfo = Invoke-Expression $Expr;

        # Clean it up
        $Permissions = (($ShareInfo | ?{$_ -like "Permission*" -or $_ -like " *"}) -join "");
        $Permissions = $Permissions.Replace("Permission","").Trim().Replace("   "," ");
        
        # Create a new object
        $Share = $WMIShares | ?{$_.Name -eq $ShareName};
        
        # Add the permission property 
        $Share | Add-Member -MemberType NoteProperty -Name SharePermissions -Value $Permissions;
        
        # And add to our collection
        $CustomShares += $Share;
    }

    Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
        PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive" | Select -Property *);
        LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk" | Select -Property *);
        Volumes       = $(Get-WMIObject -Class "Win32_Volume" | Select -Property *);
        SharedFolders = $CustomShares;
        MountedDrives = $(Get-WMIObject -Class "Win32_MappedLogicalDisk" | Select -Property *);
    });
}
catch {
    Write-ShellMessage -Message "Error gathering storage information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Networking ]---------
try {
    Write-ShellMessage -Message "Gathering networking information" -Type INFO;

    # Do an OS check here to see if we're running 2003
    if ($HostInformation.OS.Caption.Contains("2003")) {
        # Use netsh to work it out
        $FirewallRules = Get-NetshFireWallRule;
        $FirewallZone = Get-NetshFireWallProfile;
    }
    else {
        # Let's get the Com object established for the firewall rules, outvar to null to avoid ps misinterpretation
        $Firewall = New-Object -Com "HNetCfg.FwPolicy2" -OutVariable null;
        $FirewallRules = $Firewall.Rules;
        $FirewallZone = $(switch ($Firewall.CurrentProfileTypes) {1 {"Domain"};2 {"Private"};3 {"Public"};4 {"Domain,Profile,Public"}});
    }

    # And add to the HostInformation collection
    Add-HostInformation -Name Networking -Value $(New-Object PSCustomObject -Property @{
        AdapterInformation = $(Get-WMIObject -Class "Win32_NetworkAdapterConfiguration" | Select -Property *);
        Hostname           = $env:COMPUTERNAME;
        NTPConfiguration   = $(Invoke-Expression "w32tm /query /configuration");
        FirewallZone       = $FirewallZone;
        FirewallRules      = $FirewallRules;
    });
}
catch {
    Write-ShellMessage -Message "Error gathering networking information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Peripherals ]---------
try {
    Write-ShellMessage -Message "Gathering peripherals information" -Type INFO;
    Add-HostInformation -Name Peripherals -Value $(New-Object PSCustomObject -Property @{
        USBDevices    = $(Get-WMIObject -Class "Win32_USBControllerDevice" | %{[Wmi]$_.Dependent} | Select -Property *);
        SerialDevices = $(Get-WMIObject -Class "Win32_SerialPort" | Select -Property *);
        Printers      = $(Get-WMIObject -Class "Win32_Printer" | Select -Property *);
    });
}
catch {
    Write-ShellMessage -Message "Error gathering peripherals information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Applications ]---------
try {
    Write-ShellMessage -Message "Gathering application information" -Type INFO;

    # Var up our regkeys and select criteria for legibility
    $x32Reg = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*";
    $x64Reg = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*";
    $SelectCriteria = @("DisplayName","DisplayVersion","Publisher","InstallDate");

    # We might not be x64, so let's test before attempting the result
    if (Test-Path $x32Reg) {  
        # Add to the collection normally
        Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
            x32 = $(Get-ItemProperty $x32Reg | ?{![String]::IsNullOrEmpty($_.DisplayName)} | Select $SelectCriteria);
            x64 = $(Get-ItemProperty $x64Reg | ?{![String]::IsNullOrEmpty($_.DisplayName)} | Select $SelectCriteria);
        });
    }
    else {
        # Swap, as we're x32 only
        Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
            x32 = $(Get-ItemProperty $x64Reg | ?{![String]::IsNullOrEmpty($_.DisplayName)} | Select $SelectCriteria);
            x64 = $Null;
        });
    }
}
catch {
    Write-ShellMessage -Message "Error gathering applications information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Roles & Features ]---------
try {
    # Check if Server or Workstation here as ServerManager isn't available on workstations
    if ($HostInformation.OS.Caption.ToLower().Contains("server")) {       
        Write-ShellMessage -Message "Gathering roles and features information" -Type INFO;

        # Now, we need to do a check here to see if we're on 2003
        if ($HostInformation.OS.Caption.Contains("2003")) {
            # 2003 requires a different capture method; Get the components from the registry
            $Components = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents";
            
            # Let's check and see if we're x64 and add to the internal collection
            if (Test-Path "C:\Program Files (x86)") {
                $Components += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Setup\Oc Manager\Subcomponents";
            }

            # Get the roles and features data
            $RolesAndFeatures = @(
                $Components | Get-Member -MemberType NoteProperty | %{ 
                    if ($_.Name -notlike "PS*") {
                        [PSCustomObject]@{
                            "DisplayName" = "Server 2003 feature: $($_.Name)";
                            "Name"         = $_.Name;
                            "FeatureType" = "2003 Feature";
                            "Path"         = $Components.PSPath;
                            "Subfeatures"  = "N/A"
                            "Installed"    = [Bool]($Components.$($_.Name));
                        };
                    };
                };
            );
        }
        elseif ($HostInformation.OS.Caption.Contains("2008") -and $HostInformation.OS.Caption -notlike "*R2*") {
            # 2008 R1 only has Servermanagercmd
            $SMCMD = Invoke-Expression "servermanagercmd -q";
            
            # Get the roles and features data
            $RolesAndFeatures = @(  
                $SMCMD | %{
                    # Get the line containing what we want
                    $Line = $_;
                    
                    # Work out whether it's the right type of line
                    if ($Line.Contains("[X]") -or $Line.Contains("[ ]")) {
                    
                        # Find out if it's installed or not
                        if ($Line.Contains("[X] ")) {
                            # Yes it is installed, remove the tickbox
                            $Line = $Line.Replace("[X] ","").Trim();
                            $Installed = $True;      
                        }
                        else {
                            # No it is not installed, remove the tickbox
                            $Line = $Line.Replace("[ ] ","").Trim();
                            $Installed = $False;
                        }
                                
                        # Set the prop values
                        $DisplayName = $Line.Split("[")[0].Trim();
                        $Name = $Line.Split("[")[1].Trim().TrimEnd("]");
                        
                        
                        # Throw the object out
                        [PSCustomObject]@{
                            "DisplayName" = $DisplayName;
                            "Name"        = $Name
                            "FeatureType" = "2008 R1 Feature/Role";
                            "Path"        = "N/A"
                            "Subfeatures" = "N/A"
                            "Installed"   = $Installed;
                        };
                    }
                }
            );

        }
        else {
            # Import the servermanager module for the Get-WindowsFeature cmdlet
            Import-Module ServerManager;
            $RolesAndFeatures = $(Get-WindowsFeature | Select -Property *);
        }

        # Add to our HostInfo collection
        Add-HostInformation -Name RolesAndFeatures -Value $RolesAndFeatures;
    };
}
catch {
    Write-ShellMessage -Message "Error gathering roles and features information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ IIS v7+ ]---------
try {
    if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "Web-Server"}).Installed) {
        Write-ShellMessage -Message "Gathering IIS information" -Type INFO;

        # This is wrapped in a powershell job; sometimes due to bad server configuration
        # powershell modules just hang when trying to load. Processing this way allows 
        # the use of a timeout to prevent the whole process getting hung up.

        # Get the job defined in a scriptblock
        $GetIISConfigurationJobScriptBlock = {

            # Set the Execution policy
            Set-ExecutionPolicy Unrestricted -Force;

            # Get the WebAdministration module imported
            Import-Module WebAdministration -Force;

            # Slight wait to fix any import latency issues
            Try{
                [Void](Get-WebSite);
            } Catch [System.IO.FileNotFoundException]{}

            # Now, we need to explicitly cast the outputs of the following
            # to PSCustomObjects as the IISConfigurationElement and other
            # types don't serialise properly.

            # Get the WebSites
            $WebSites = $(Get-WebSite | %{
                $(New-Object PSCustomObject -Property @{
                    Name         = $_.Name;
                    ID           = $_.ID;
                    State        = $_.State;
                    PhysicalPath = $_.PhysicalPath;
                    Bindings     = @(,$(($_.Bindings | %{$_.Collection}) -join " "));
                });
            });

            # Get the Application Pools
            $ApplicationPools = $(gci "IIS:\AppPools" | Select -Property * | %{
                $Name = $_.Name;
                $(New-Object PSCustomObject -Property @{
                    Name                  = $Name;
                    State                 = $_.State;
                    ManagedPipelineMode   = $_.ManagedPipelineMode;
                    ManagedRuntimeVersion = $_.ManagedRuntimeVersion;
                    StartMode             = $_.StartMode;
                    AutoStart             = $_.AutoStart;
                    Applications          = @(,$((Get-WebSite | ?{$_.applicationPool -eq $Name} | Select Name).Name));
                });
            });

            # Get the Bindings
            $WebBindings = $(Get-WebBinding | %{
                $(New-Object PSCustomObject -Property @{
                    Protocol           = $_.protocol;
                    BindingInformation = $_.bindingInformation;
                });
            });

            # Get the Virtual Directories
            $VirtualDirectories = $(Get-WebVirtualDirectory | %{
                $(New-Object PSObject -Property @{
                    Name         = $_.Path.Split("/")[($_.Path.Split("/").Length)-1];
                    Path         = $_.Path;
                    PhysicalPath = $_.PhysicalPath;
                });
            });

            # Get a list .config files for each application so we can work out dependency chains
            $ConfigFileContent = @();
            $WebSites | %{
                
                # Get the site name and physical path
                $WebsiteName = $_.Name;
                $PhysicalPath = $_.PhysicalPath.Replace("%SystemDrive%",$Env:SystemDrive).Replace("%SystemRoot%",$env:SystemRoot);
                
                # Enumerate the config files and add to the configfilecontent array
                Get-ChildItem -Path $PhysicalPath -Recurse | ?{$_.Name -like "*.config"} | %{
                    $ConfigFileContent += $(New-Object PSCustomObject -Property @{
                        Site    = $WebsiteName;
                        Path    = $_.FullName;
                        Content = $(Get-Content $_.FullName | Out-String);
                    }); 
                };
            };

            # Return the data we want
            return $(New-Object PSCustomObject -Property @{
                WebSites            = $WebSites;
                ApplicationPools    = $ApplicationPools;
                WebBindings         = $WebBindings;
                VirtualDirectories  = $VirtualDirectories;
                ConfigurationFiles  = $ConfigFileContent;
            });
        }

        # Ok get our desired timeout
        $Timeout = (Get-Date).AddMinutes(2);

        # Start the job
        $GetIISConfigurationJob = Start-Job -ScriptBlock $GetIISConfigurationJobScriptBlock;

        # Now we need to wait for the job to finish
        While ("NotStarted","Starting","Running" -contains $GetIISConfigurationJob.State) {

            # Ok first we need to check the timeout
            if ($(Get-Date) -ge $Timeout) {
                
                # Ok kill the job
                Remove-Job -Job $GetIISConfigurationJob -Force;

                # And throw
                throw [System.TimeoutException] "the IIS WebAdministration module import timed out";
            }
            else {
                # Wait a bit longer instead
                Start-Sleep -Seconds 5;
            }
        }

        # Ok get the data
        $IISConfiguration = Receive-Job -Job $GetIISConfigurationJob;

        # And add the IIS data to our HostInformation collection
        Add-HostInformation -Name IISConfiguration -Value $IISConfiguration;
    };
}
catch {
    Write-ShellMessage -Message "Error gathering IIS information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ IIS v5/6 ]---------
try {
    if ($(try{[Void](Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServer);$True}catch{$False})) {
        Write-ShellMessage -Message "Gathering IIS v5/6 information" -Type INFO;
        
        # Get the WebSites
        $WebSites = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServerSetting | %{
            $ID = $_.Name;
            New-Object PSCustomObject -Property @{
                Name         = $_.ServerComment;
                ID           = $ID;
                State        = "Enabled";
                PhysicalPath = $((Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebVirtualDirSetting | ?{$_.Name -like "$ID/*"} | select -expandproperty path).Path);
                Bindings     = $($_.SecureBindings | Select IP,Port)
            }
        }

        # Get the Application Pools
        $ApplicationPools = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsApplicationPool | %{
            $Name = $_.Name.Replace("W3SVC/AppPools/","");
            New-Object PSCustomObject -Property @{
                Name                  = $Name;
                State                 = $(switch($_.AppPoolState){1 {"Starting"};2 {"Started"};3 {"Stopping"};4 {"Stopped"}});
                ManagedPipelineMode   = $Null;
                ManagedRuntimeVersion = $Null;
                StartMode             = $Null;
                AutoStart             = $Null;
                Applications          = $((Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebServerSetting | ?{$_.AppPoolId -eq $Name} | Select -ExpandProperty ServerComment).ServerComment);
                
            }
        }

        # Get the Virtual Directories
        $VirtualDirectories = Get-WmiObject -Namespace "root/MicrosoftIISv2" -Class IIsWebVirtualDirSetting | %{
            if ($_.Caption) {
                New-Object PSObject -Property @{
                    Name         = $_.Caption;
                    Path         = $_.Name;
                    PhysicalPath = $_.Path;
                }
            }
        }

        # Add a collection containing our IIS trees to the hostinfo object
        Add-HostInformation -Name IISConfigurationv5and6 -Value $(New-Object PSCustomObject -Property @{
            WebSites            = $WebSites;
            ApplicationPools    = $ApplicationPools;
            VirtualDirectories  = $VirtualDirectories;
        });
    };
}
catch {
    Write-ShellMessage -Message "Error gathering IIS v5/6 information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ TLS Certificates ]---------
try {
    Write-ShellMessage -Message "Gathering TLS certificate information" -Type INFO;
        
    # Add a collection containing our certificate tree
    $TLSCertificates = $(Get-ChildItem "Cert:\LocalMachine" -Recurse | ?{!$_.PSIsContainer} | Select -Property *);
    Add-HostInformation -Name TLSCertificates -Value $TLSCertificates;
}
catch {
    Write-ShellMessage -Message "Error gathering TLS certificate information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Windows Updates ]---------
try {
    Write-ShellMessage -Message "Gathering Windows Update information" -Type INFO;
        
    # Ok again another OS check to see if we're running 2003
    if ($HostInformation.OS.Caption.Contains("2003")) {
        $UpdateHistory = $(wmic qfe list /format:csv | ConvertFrom-CSV | %{
            [PSCustomObject]@{
                Title       = $($_.HotfixID + " " + $_.Description);
                Description = $_.Caption;
                Date        = $_.InstalledOn;
                Operation   = "Install";
            };
        });
    }
    else {
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
            # RTM; Set to null
            $UpdateHistory = $Null;
        }
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
    Write-ShellMessage -Message "Error gathering Windows Update information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ PowerShell, WinRM & .NET ]---------
try {
    Write-ShellMessage -Message "Gathering management information" -Type INFO;
        
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
    Write-ShellMessage -Message "Error gathering management information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Scheduled Tasks ]---------
try {
    Write-ShellMessage -Message "Gathering scheduled tasks information" -Type INFO;
    
    # Now we need to check what OS we're on here, 2003 doesn't support our custom method
    if ($HostInformation.OS.Caption.Contains("2003")) {
        # Ok we have to parse schtasks.exe
        $ScheduledTasks = $(schtasks /query /v /fo csv | ConvertFrom-Csv | %{
            [PSCustomObject]@{
                Name        = $_.TaskName;
                Enabled     = $(if ($_."Scheduled Task State" -eq "Enabled"){$True}else{$False});
                Actions     = $_."Task To Run";
                LastRunTime = $_."Last Run Time";
                LastResult  = $_."Last Result";
            }
        });
    }
    else {
        # 2008 and above; let's use the custom method
        $ScheduledTasks = $(Get-ScheduledTasksList);
    }
    
    # And add to our HostInformation collection
    Add-HostInformation -Name ScheduledTasks -Value $ScheduledTasks;
}
catch {
    Write-ShellMessage -Message "Error gathering scheduled tasks information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Domain Controller ]---------
try {
    if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "AD-Domain-Services"}).Installed) {      
        Write-ShellMessage -Message "Gathering Active Directory Domain Controller information" -Type INFO;

        # Get the ActiveDirectory module imported
        Import-Module ActiveDirectory;

        # Add a collection containing our domain info to the hostinfo object
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
    Write-ShellMessage -Message "Error gathering Active Directory Domain Controller information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Database ]---------
try {
    if (Test-Path "HKLM:\Software\Microsoft\Microsoft SQL Server\Instance Names\SQL") {
        Write-ShellMessage -Message "Gathering SQL Server information" -Type INFO;

        # Ok let's declare an object to hold our data
        $SQLServerInformation = @();
        
        # Find all the SQL instances by (running) service, this seems to be the most reliable method cross version
        Get-Service | ?{$_.Name -like "MSSQL*" -and $_.DisplayName -like "SQL Server*" -and $_.Status -eq "Running"} | %{
            
            # Get the instance name
            $InstanceName = [Regex]::Match($_.DisplayName,"(?<=\()[^}]*(?=\))").Value;
            
            # If the instance is the default we need to connect differently
            if ($InstanceName -eq "MSSQLSERVER") {
                $InstanceConnectionIdentifier = $env:computername;
            }
            else {
                $InstanceConnectionIdentifier = $env:computername + "\" + $InstanceName;
            }
            
            # Get the list of databases for this instance
            $Databases = Invoke-SQLQuery -Server $InstanceConnectionIdentifier -Database Master -Query "select name from sys.databases";
        
            # Enumerate the database list and get the sp_helpdb info
            $DBInfoCollection = @();
            $Databases | %{
            
                # Get the SP_HELPDB object
                $DatabaseName = $_.Name;
                $DB = Invoke-SQLQuery -ServerName $InstanceConnectionIdentifier -Database Master -query "EXEC SP_HELPDB '$DatabaseName'";
        
                # Parse and add to the DBInfoCollection
                $DBInfoCollection += $(New-Object PSCustomObject -Property @{
                    Name               = $DB.name.ToString().Trim();
                    Size               = $DB.db_size.ToString().Trim();
                    Owner              = $DB.owner.ToString().Trim();
                    DBID               = $DB.dbid;
                    CreatedDate        = [Datetime]$DB.created;
                    Status             = $DB.status.ToString().Trim();
                    CompatibilityLevel = $DB.compatibility_level;
                });
            
            }
            
            # Add to the SQLServerInformation object
            $SQLServerInformation += $(New-Object PSCustomObject -Property @{
                ServerName           = $env:computername;
                InstanceName         = $InstanceName;
                ConnectionIdentifier = $InstanceConnectionIdentifier;
                Databases            = $DBInfoCollection;    
            });
        
        }

        # Add a collection containing our SQL server information to the hostinfo object
        Add-HostInformation -Name SQLServer -Value $SQLServerInformation;
    };
}
catch {
    Write-ShellMessage -Message "Error gathering SQL Server information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Apache Virtual Hosts ]---------
try {
    if ($(try{[Void](Get-Process "httpd");$True;}catch{$false})) {
        Write-ShellMessage -Message "Gathering Apache Virtual Host information" -Type INFO;

        # Get the Apache httpd.exe path
        $Httpd = (Get-Process "httpd").Path;

        # Add a collection containing our Apache tree to the hostinfo object
        Add-HostInformation -Name ApacheVirtualHosts -Value $((Invoke-Expression "$httpd -S").Split("`r`n"));
    }
}
catch {
    Write-ShellMessage -Message "Error gathering Apache Virtual Host information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Tomcat Web Applications ]---------
try {
    if (Get-Service | ?{$_.DisplayName -like "Apache Tomcat*"}) {
        Write-ShellMessage -Message "Gathering Apache Tomcat application information" -Type INFO;

        # Add a collection containing our Tomcat tree to the hostinfo object
        $TomcatApplications = $((New-Object System.Net.WebClient).DownloadString("http://localhost:8080/manager/list").Split("`r`n"));
        Add-HostInformation -Name TomcatApplications -Value $TomcatApplications;
    }
}
catch {
    Write-ShellMessage -Message "Error gathering Apache Tomcat application information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Windows Services ]---------
try {
    Write-ShellMessage -Message "Gathering Windows service information" -Type INFO;
    Add-HostInformation -Name WindowsServices -Value $(Get-WMIObject -Class "Win32_Service" | Select -Property *);
}
catch {
    Write-ShellMessage -Message "Error gathering Windows service information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Base networking topology ]---------
try {
    Write-ShellMessage -Message "Gathering established session and connection information" -Type INFO;
    
    # Ok get a full netstat and declare an output object
    $Netstat = Invoke-Expression "netstat -ano"
    $ConnectionInformation = @();
    
    # Enumerate the output from netstat
    $Netstat | ?{$_.Contains("ESTABLISHED") -or $_.Contains("CLOSE_WAIT")} | %{
    
        # Ok get the netstat row into an object to process
        $Connection = $_;
    
        # Split up on and dedupe spaces
        $Properties = $Connection.Split(" ") | ?{$_};
    
        # Get the process object from the PID
        $ProcessObject = Get-Process -ID $Properties[4];
    
        # Create a new PSCustomObject using the properties we just split out, add to the collection
        $ConnectionInformation += $(New-Object PSCustomObject -Property @{
            Protocol           = $Properties[0];
            LocalAddress       = $Properties[1].Split(":")[0];
            LocalPort          = $Properties[1].Split(":")[1];
            RemoteAddress      = $Properties[2].Split(":")[0];
            RemotePort         = $Properties[2].Split(":")[1];
            State              = $Properties[3];
            ProcessID          = $Properties[4];
            ProcessName        = $ProcessObject.Name;
            ProcessDescription = $ProcessObject.Description;
            ProcessProduct     = $ProcessObject.Product;
            ProcessFileVersion = $ProcessObject.FileVersion;
            ProcessExePath     = $ProcessObject.Path;
            ProcessCompany     = $ProcessObject.Company;
        });
    }

    # And add to our HostInformation collection
    Add-HostInformation -Name ConnectionInformation -Value $ConnectionInformation;
}
catch {
    Write-ShellMessage -Message "Error gathering established session and connection information" -Type ERROR -ErrorRecord $Error[0];
}

#---------[ Fix ExecutionPolicy ]---------
Set-ExecutionPolicy $ExecutionPolicy -Force;

#---------[ Return ]---------
Write-ShellMessage -Message "Gathering completed" -Type SUCCESS;
if ($X.IsPresent) {
    return [System.Management.Automation.PSSerializer]::Serialize($HostInformation,5);
}
else {
    return $HostInformation;
}