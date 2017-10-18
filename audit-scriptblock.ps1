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

#---------[ Main() ]---------

# OS Information
Write-Host "Gathering OS information";
Add-HostInformation -Name OS -Value $(Get-WMIObject -Class "Win32_OperatingSystem" | Select -Property *);

# System Information
Write-Host "Gathering system information";
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
    Hostname         = $env:COMPUTERNAME
    IsVirtualMachine = $IsVirtualMachine
    MachineType      = $MachineType
    SystemInfo       = $SystemInfo
});

# Compute
Write-Host "Gathering compute information";
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor" | Select -Property *);

# Memory: Get a PSCustomObject to hold our goodies
Write-Host "Gathering memory information";
$WindowsMemory = New-Object PSCustomObject;

# Enumerate the output of systeminfo and get what we want
Invoke-Expression "systeminfo" | ?{$_ -like "*memory*"} | %{
    # Let's split out the spaces
    $String = $_.Replace(" ","");

    # And the first : if there are more than one
    if (($String.ToCharArray() | ?{$_ -eq ":"}).Count -gt 1) {
        $String = ([Regex]":").Replace($String,"",1);
    };

    # Add the k:v to the object we created earlier
    $WindowsMemory | Add-Member -MemberType NoteProperty -Name $String.Split(":")[0] -Value $String.Split(":")[1];   
};

# We need to do a check here as Win32_PhysicalMemory is $Null on virtual machines
if ($IsVirtualMachine) {
    Add-HostInformation -Name Memory -Value $(New-Object PSCustomObject -Property @{
        PhysicalMemory = $Null
        WindowsMemory  = $WindowsMemory
    });
}
else {
    Add-HostInformation -Name Memory -Value $(New-Object PSCustomObject -Property @{
        PhysicalMemory = $(Get-WMIObject -Class "Win32_PhysicalMemory" | Select -Property *)
        WindowsMemory  = $WindowsMemory
    });
}

# Storage
Write-Host "Gathering storage information";
Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
    PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive" | Select -Property *)
    LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk" | Select -Property *)
    Volumes       = $(Get-WMIObject -Class "Win32_Volume" | Select -Property *)
    SharedFolders = $(Get-WMIObject -Class "Win32_Share" | Select -Property *)
    MountedDrives = $(Get-WMIObject -Class "Win32_MountPoint" | Select -Property *)
});


# Networking
Write-Host "Gathering networking information";

# Let's get the Com object established for the firewall rules, outvar to null to avoid ps misinterpretation
$Firewall = New-Object -Com "HNetCfg.FwPolicy2" -OutVariable null;

# And add to the hostinformation collection
Add-HostInformation -Name Networking -Value $(New-Object PSCustomObject -Property @{
    AdapterInformation = $(Get-WMIObject -Class "Win32_NetworkAdapterConfiguration" | Select -Property *)
    Hostname           = $env:COMPUTERNAME
    NTPConfiguration   = $(Invoke-Expression "w32tm /query /configuration")
    FirewallZone       = $(switch ($Firewall.CurrentProfileTypes) {1 {"Domain"};2 {"Private"};4 {"Public"}})
    FirewallRules      = $Firewall.Rules
});

# Peripherals
Write-Host "Gathering peripherals information";
Add-HostInformation -Name Peripherals -Value $(New-Object PSCustomObject -Property @{
    USBDevices    = $(Get-WMIObject -Class "Win32_USBControllerDevice" | Select -Property *)
    SerialDevices = $(Get-WMIObject -Class "Win32_SerialPort" | Select -Property *)
    Printers      = $(Get-WMIObject -Class "Win32_Printer" | Select -Property *)
});

# Applications
Write-Host "Gathering application information";
Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
    x32 = $(Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
    x64 = $(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
});

# Check if Server or Workstation here as ServerManager isn't available on workstations
if ($HostInformation.OS.Caption.ToLower().Contains("server")) {
    
    Write-Host "Gathering roles and features information";

    # Import the servermanager module for the Get-WindowsFeature cmdlet
    Import-Module ServerManager;
    Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature | Select -Property *);

};

# IIS Applications
if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "Web-Server"}).Installed) {
    
    Write-Host "Gathering IIS information";

    # Get the WebAdministration module imported
    Import-Module WebAdministration;

    # Get a list .config files for each application so we can work out dependency chains
    $ConfigFiles = Get-ChildItem "IIS:\" -Recurse | ?{$_.Name -like "*.config"} | Select FullName;
    $ConfigFileContent = @();
    
    # If any are found, enumerate the collection and get the content
    $ConfigFiles | %{
        
        # Get the pipeline object
        $ConfigFile = $_;

        # Add to the collection
        $ConfigFileContent += $(New-Object PSCustomObject -Property @{
            Path    = $ConfigFile.FullName
            Content = $(Get-Content $ConfigFile.FullName | Out-String)
        });
    }

    # Because the calling machine may not have the WebAdministration module, we need to use appcmd for the next section
    $Appcmd = "C:\windows\system32\inetsrv\appcmd.exe";

    # Sites
    $Sites = New-Object PSCustomObject;
    & $Appcmd "list" "site" | %{
        # Get the pipe object and trim the SITE prefix
        $Line = $_.Replace("SITE ","");

        # Split up and clean
        $SiteName = $Line.Split("(")[0].Trim("""");
        $SiteName = $SiteName.Substring(0,$SiteName.Length-2); # Remove extra "
        $SiteInfo = $Line.Split("(")[1].TrimEnd(")");

        # Add the results to our collection
        $Sites | Add-Member -MemberType NoteProperty -Name $SiteName -Value $SiteInfo;
    }

    # Applciation pools
    $AppPools = New-Object PSCustomObject;
    & $Appcmd "list" "apppool" | %{
        # Get the pipe object and trim the APPPOOL prefix
        $Line = $_.Replace("APPPOOL ","");

        # Split up and clean
        $AppPoolName = $Line.Split("(")[0].Trim("""");
        $AppPoolName = $AppPoolName.Substring(0,$AppPoolName.Length-2); # Remove extra "
        $AppPoolInfo = $Line.Split("(")[1].TrimEnd(")");

        # Add the results to our collection
        $AppPools | Add-Member -MemberType NoteProperty -Name $AppPoolName -Value $AppPoolInfo;
    }

    # Virtual directories
    $VirtualDirectories = New-Object PSCustomObject;
    & $Appcmd "list" "vdir" | %{
        # Get the pipe object and trim the VDIR prefix
        $Line = $_.Replace("VDIR ","");

        # Split up and clean
        $VirtualDirectoryName = $Line.Split("(")[0].Trim("""");
        $VirtualDirectoryName = $VirtualDirectoryName.Substring(0,$VirtualDirectoryName.Length-2); # Remove extra "
        $VirtualDirectoryInfo = $Line.Split("(")[1].TrimEnd(")");

        # Add the results to our collection
        $VirtualDirectories | Add-Member -MemberType NoteProperty -Name $VirtualDirectoryName -Value $VirtualDirectoryInfo;
    }

    # Add a collection containing our IIS trees to the hostinfo object
    Add-HostInformation -Name IISConfiguration -Value $(New-Object PSCustomObject -Property @{
        Sites               = $Sites
        ApplicationPools    = $AppPools
        VirtualDirectories  = $VirtualDirectories
        ConfigurationFiles  = $ConfigFileContent
    });
    
};

# Check if Apache is installed and get applications
if (Get-Service | ?{$_.Name -like "*Apache*" -and $_.Name -notlike "*Tomcat*"}) {
    
    Write-Host "Gathering Apache Virtual Host information";

    # Get the Apache install and httpd.exe paths
    $ApachePath = $((Get-ChildItem "C:\Program Files (x86)\*Apache*").FullName);
    $Httpd      = $((Get-ChildItem $ApachePath "httpd.exe" | Select -First 1).FullName);

    # Add a collection containing our Apache tree to the hostinfo object
    Add-HostInformation -Name ApacheApplications -Value $(New-Object PSCustomObject -Property @{
        Applications = $((Invoke-Expression "$httpd -S").Split("`r`n"))
    });

};

# Check if Tomcat is installed and get applications
if (Get-Service | ?{$_.Name -like "*Tomcat*"}) {
    
    Write-Host "Gathering Tomcat applications information";

    # Add a collection containing our Tomcat tree to the hostinfo object
    Add-HostInformation -Name TomcatApplications -Value $(New-Object PSCustomObject -Property @{
        Applications = $((New-Object System.Net.WebClient).DownloadString("http://localhost:8080/manager/text/list").Split("`r`n"))
    });

};

#---------[ Return ]---------
Write-Host "Gathering completed";
return $HostInformation;