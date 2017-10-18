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

}

#---------[ Main() ]---------

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
}

# And add to the collection
Add-HostInformation -Name SystemInfo -Value $(New-Object PSCustomObject -Property @{
    Hostname         = $env:COMPUTERNAME
    IsVirtualMachine = $IsVirtualMachine
    MachineType      = $MachineType
    SystemInfo       = $SystemInfo
})

# Compute
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor" | Select -Property *);

# Memory, we need to do a check here as Win32_PhysicalMemory is $Null on virtual machines
if ($IsVirtualMachine) {
    Add-HostInformation -Name Memory -Value "TODO!";
}
else {
    Add-HostInformation -Name Memory -Value $(Get-WMIObject -Class "Win32_PhysicalMemory" | Select -Property *);
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
})

# Applications and features
Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
    x32 = $(Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
    x64 = $(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select -Property *)
})

# Import the servermanager module for the Get-WindowsFeature cmdlet
Import-Module ServerManager;
Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature | Select -Property *);

# IIS Applications
if (($HostInformation.RolesAndFeatures | ?{$_.Name -eq "Web-Server"}).Installed) {
    # Get the WebAdministration module in
    Import-Module WebAdministration;

    # Add a collection containing our IIS tree to the hostinfo object
    Add-HostInformation -Name IIS -Value $(New-Object PSCustomObject -Property @{
        ApplicationPools = $(Get-ChildItem "IIS:\AppPools" -Recurse -Force | Select -Property *;)
        Sites            = $(Get-ChildItem "IIS:\Sites" -Recurse -Force | Select -Property *;)
        SslBindings      = $(Get-ChildItem "IIS:\SslBindings" -Recurse -Force | Select -Property *;)
    })

    # Get .config files for each application so we can work out dependency chains
    #TODO

}

# Check if Apache is installed and get applications
#TODO

# Check if Tomcat is installed and get applications
#TODO

#---------[ Return ]---------
return $HostInformation;