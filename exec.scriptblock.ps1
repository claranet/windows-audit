{
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

    # Compute
    Add-HostInformation -Name Compute -Value $(Get-WMIObject -Class "Win32_Processor");

    # Memory
    Add-HostInformation -Name Memory -Value $(Get-WMIObject -Class "Win32_PhysicalMemory");

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

    Add-HostInformation -Name RolesAndFeatures -Value $(Get-WindowsFeature);

    # System information
    Add-HostInformation -Name SystemInformation -Value $(Invoke-Expression "systeminfo");

    #---------[ Return ]---------
    return $HostInformation;
}