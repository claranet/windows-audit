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
$SystemInfo = Get-WMIObject -Class "Win32_ComputerSystem";

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
Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor");

# Memory, we need to do a check here as Win32_PhysicalMemory is $Null on virtual machines
if ($IsVirtualMachine) {
    Add-HostInformation -Name Memory -Value "TODO!";
}
else {
    Add-HostInformation -Name Memory -Value $(Get-WMIObject -Class "Win32_PhysicalMemory");
}

# Storage
Add-HostInformation -Name Storage -Value $(New-Object PSCustomObject -Property @{
    PhysicalDisks = $(Get-WMIObject -Class "Win32_DiskDrive")
    LogicalDisks  = $(Get-WMIObject -Class "Win32_LogicalDisk")
    Volumes       = $(Get-WMIObject -Class "Win32_Volume")
    SharedFolders = "TODO"
    MountedDrives = $(Get-WMIObject -Class "Win32_MountPoint")
});

# Networking
Add-HostInformation -Name Networking -Value $(New-Object PSCustomObject -Property @{
    AdapterInformation = $(Get-WMIObject -Class "Win32_NetworkAdapterConfiguration")
    Hostname           = $env:COMPUTERNAME
    NTPConfiguration   =  $(Invoke-Expression "w32tm /query /configuration")
    Firewall           = "TODO, as get-netfirewallrule is fairly new"
});

# Peripherals
Add-HostInformation -Name Peripherals -Value $(New-Object PSCustomObject -Property @{
    USBDevices    = $(Get-WMIObject -Class "Win32_USBControllerDevice")
    SerialDevices = $(Get-WMIObject -Class "Win32_SerialPort")
    Printers      = $(Get-WMIObject -Class "Win32_Printer")
})

# Applications and features
Add-HostInformation -Name Applications -Value $(New-Object PSCustomObject -Property @{
    x32 = $(Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*")
    x64 = $(Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
})

# Import the servermanager module for the Get-WindowsFeature cmdlet
Import-Module ServerManager;
Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature);

#---------[ Return ]---------
return $HostInformation;