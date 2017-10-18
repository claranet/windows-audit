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
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_OperatingSystem" | Select -Property *);

# System Information
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
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor" | Select -Property *);

# Memory: Get a PSCustomObject to hold our goodies
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
}

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
Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
    PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive" | Select -Property *)
    LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk" | Select -Property *)
    Volumes       = $(Get-WMIObject -Class "Win32_Volume" | Select -Property *)
    SharedFolders = $(Get-WMIObject -Class "Win32_Share" | Select -Property *)
    MountedDrives = $(Get-WMIObject -Class "Win32_MountPoint" | Select -Property *)
});

# Networking
Add-HostInformation -Name Networking -Value $(New-Object PSCustomObject -Property @{
    AdapterInformation = $(Get-WMIObject -Class "Win32_NetworkAdapterConfiguration" | Select -Property *)
    Hostname           = $env:COMPUTERNAME
    NTPConfiguration   = $(Invoke-Expression "w32tm /query /configuration")
    Firewall           = (New-Object –ComObject HNetCfg.FwPolicy2).Rules
});

# Peripherals
Add-HostInformation -Name Peripherals -Value $(New-Object PSCustomObject -Property @{
    USBDevices    = $(Get-WMIObject -Class "Win32_USBControllerDevice" | Select -Property *)
    SerialDevices = $(Get-WMIObject -Class "Win32_SerialPort" | Select -Property *)
    Printers      = $(Get-WMIObject -Class "Win32_Printer" | Select -Property *)
});

# Applications and features
Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
    x32 = $(Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
    x64 = $(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
});

# Import the servermanager module for the Get-WindowsFeature cmdlet
Import-Module ServerManager;
Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature | Select -Property *);

# IIS Applications
if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "Web-Server"}).Installed) {
    # Get the WebAdministration module in
    Import-Module WebAdministration;

    # Get a list .config files for each application so we can work out dependency chains
    $ConfigFiles = Get-ChildItem "IIS:\" -Recurse | ?{$_.Name -like "*.config"} | Select FullName;
    $ConfigFileContent = @()
    
    # If any are found, enumerate the collection and get the content
    if ($ConfigFiles) {
        $ConfigFiles | %{
            
            # Get the pipeline object
            $ConfigFile = $_;

            # Add to the collection
            $ConfigFileContent += $(New-Object PSCustomObject -Property @{
                Path    = $ConfigFile.FullName
                Content = (Get-Content $ConfigFile.FullName | Out-String)
            });
        }
    }

    # Add a collection containing our IIS tree to the hostinfo object
    Add-HostInformation -Name IISConfiguration -Value $(New-Object PSCustomObject -Property @{
        IIS                = $(Get-ChildItem "IIS:\" -Force | Select -Property *;)
        ApplicationPools   = $(Get-ChildItem "IIS:\AppPools" -Recurse -Force | Select -Property *)
        Sites              = $(Get-ChildItem "IIS:\Sites" -Recurse -Force | Select -Property *)
        SslBindings        = $(Get-ChildItem "IIS:\SslBindings" -Recurse -Force | Select -Property *)
        ConfigurationFiles = $ConfigFileContent
    });
}

# Check if Apache is installed and get applications
if (Get-Service | ?{$_.Name -like "*Apache*" -and $_.Name -notlike "*Tomcat*"}) {
    
    # Get the httpd.exe path
    $Httpd = (Get-ChildItem "C:\Program Files (x86)\*Apache*" "httpd.exe" | Select -First 1).FullName;

    # Add a collection containing our Apache tree to the hostinfo object
    Add-HostInformation -Name ApacheApplications -Value $(New-Object PSCustomObject -Property @{
        Applications = $((Invoke-Expression "$httpd -S").Split("`r`n"))
    });

}

# Check if Tomcat is installed and get applications
if (Get-Service "*Tomcat*") {
    
    # Add a collection containing our Tomcat tree to the hostinfo object
    Add-HostInformation -Name TomcatApplications -Value $(New-Object PSCustomObject -Property @{
        Applications = $((Invoke-WebRequest -URI "http://localhost:8080/manager/text/list").Content.Split("`r`n"))
    });

}

#---------[ Return ]---------
return $HostInformation;